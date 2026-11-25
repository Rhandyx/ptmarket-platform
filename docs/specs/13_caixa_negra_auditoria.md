# 13. Caixa negra: auditoria de tudo o que acontece na plataforma

> Pedido do owner (25/11/2026). Prevalece sobre a spec 07 §3.4 e a 12 §3, que só cobriam ações de admin: `admin_audit_logs` passa a ser a categoria `admin` desta tabela única.

## 0. Princípio (owner): "mega auditoria", logs de tudo na base de dados
- **Todas as tabelas da BD**, sem exceção, registam cada INSERT, UPDATE e DELETE em `audit_events`: quem, quando, de onde, o quê e os valores antes/depois. Isto inclui produtos, variantes, lojas, utilizadores, clientes, papéis, encomendas, pagamentos e definições.
- As únicas exceções são técnicas e estão numa allowlist fixa no teste: o próprio `audit_events` e `outbox_events`, cujo conteúdo já está no evento de negócio auditado. Não há opt-in: uma tabela nova sem trigger chumba os testes.
- Há 4 camadas, para nada escapar:
  - **L1, trigger de linha genérico em todas as tabelas:** captura tudo o que muda dados, venha da app, do Data Studio, de SQL manual ou de um worker.
  - **L2, event trigger de DDL:** `CREATE`/`ALTER`/`DROP` de tabelas, funções, policies, papéis e grants vão para `audit_events` (`action = 'ddl.*'`). Uma tabela criada por migration recebe logo o trigger da L1 automaticamente.
  - **L3, `pgaudit`** (logs do Postgres, ficam no servidor com rotação; NÃO vão para o WORM, para não explodir o volume (decisão do owner, 26/11/2026)): sessões de superuser e manutenção, que podem passar ao lado dos triggers.
  - **L4, eventos semânticos da app:** login/logout, 2FA, recusas, exportações e leituras de dados pessoais. São coisas que a BD não vê como mudança de dados.

## 1. Âmbito: tudo o que altera estado ou é recusado
- **Atores:**
  - cliente, lojista, staff da Câmara e admin (incluindo quem está em impersonation);
  - sistema: worker Go, webhook Eupago/Stripe, job agendado, IA;
  - API key.
- **Ações:**
  - criar, alterar e apagar entidades de negócio;
  - preços e stock;
  - encomendas e estados;
  - pagamentos, reembolsos e payouts;
  - definições de loja e tenant;
  - permissões e papéis;
  - login, logout, 2FA, recuperação de conta e passkeys;
  - exportações de dados e pedidos RGPD;
  - Data Studio (o SQL executado e o resultado do dry-run);
  - início e fim de impersonation.
- **Recusas:** também se regista o que foi negado (`outcome = 'denied'`): 401/403, tentativas IDOR, login falhado, rate-limit, CSRF e webhook com assinatura inválida. **Recusas por limite de pedidos (429):** o 1.º 429 por ator ou IP e por classe de rota, em cada janela de 60 s, é gravado de forma síncrona; os seguintes vão para um contador, com um evento-resumo no fim da janela; se o Redis falhar, a resposta é 503 (decisão do owner, 25/11/2026).
- **Todas as ações de qualquer utilizador autenticado são auditáveis (owner, 25/11), seja qual for o papel.**
  - **Cliente:** registo, login, ver encomendas, adicionar e remover do carrinho (mesmo estando no Redis), favoritos, checkout passo a passo, pagamento, devolução, avaliação, alterar dados, consentimentos, pedidos RGPD.
  - **Lojista e a sua equipa:** criar, editar e apagar produtos e variantes, preços, stock, imagens, importações e migração (com o resumo do lote e o detalhe por linha), encomendas, envios, reembolsos, definições da loja, IBAN, faturação, equipa e convites, e consultas de relatórios.
  - **Membro da Câmara:** aprovar e suspender lojas, definições do tenant e do template, conteúdos, relatórios e exportações, gestão de utilizadores do tenant.
  - **Admin e superadmin:** tudo o que fazem, incluindo **leituras** (cada ecrã ou registo consultado e cada pesquisa), Data Studio, impersonation (com as duas identidades), alterações de RBAC, tenants, comissões e feature flags.
- **Regra técnica:** cada pedido HTTP de um utilizador autenticado gera um `audit_event`. Mudanças e recusas são síncronas e gravadas na mesma transação. Leituras e ações sem BD (carrinho em Redis, pesquisas) são assíncronas, com entrega garantida: o evento vai para um Redis Stream, o worker grava-o em lote em `audit_events` dentro da cadeia de hash e só depois faz ACK.
  - **Exceção:** leituras de admin/superadmin e de dados pessoais são **síncronas**. Se a gravação falhar, a resposta é 503.
  - O que não tem utilizador autenticado (navegação anónima no catálogo) fica nos logs e métricas. Passa à caixa negra quando é uma mudança ou uma recusa (ex.: tentativa de login, checkout de convidado).
- **Ninguém está acima da auditoria (superadmin incluído):**
  - não existe papel, flag ou endpoint para desligar, filtrar ou editar a auditoria;
  - as ações de superadmin e os eventos críticos são exportados para o WORM quase em tempo real (minutos, não só a raiz diária);
  - **alertas imediatos no Telegram e no Discord** só para eventos críticos: mudança de IBAN, falhas de pagamento e de faturação, login de superadmin e falha do `verify-audit`. A lista vive numa função da caixa negra; o sinal vem da tabela `audit.audit_alerts` e não do outbox (decisão do owner, 26/11/2026);
  - **timeline no Super-Admin:** vista filtrável por tenant, loja, utilizador e encomenda, com antes/depois e o estado da cadeia; a própria consulta é auditada (leitura de admin, síncrona) (decisão do owner, 26/11/2026);
  - mexer na retenção ou nos papéis de auditoria exige duas pessoas (2 superadmins com 2FA), e esse próprio ato é auditado.

## 2. Modelo (PG 18, particionado por mês desde o início, `created_at`)
`audit_events`:
- `id` (uuidv7), `tenant_id` (NULL = plataforma), `store_id`;
- `actor_type` (`customer|merchant|municipal|admin|system|api_key`), `actor_id`, `impersonator_id`;
- `action` (ex.: `product.price_changed`), `target_type`, `target_id`;
- `outcome` (`success|denied|error`), `reason`;
- `changes` JSONB: diff antes/depois, só dos campos alterados e já mascarado;
- `request_id`, `ip` (INET), `user_agent_hash`, `created_at`;
- `prev_hash`, `hash` (BYTEA).

## 3. Garantias
1. **Na mesma transação** que a alteração de negócio, como o outbox. Em Rust as mutações recebem um `AuditCtx` obrigatório (ator, ip, request_id) vindo do extractor; sem `AuditCtx` não compila. Os workers Go usam `actor_type = 'system'`.
2. **Quem fez (contexto de ator na BD):**
   - Na mesma transação, a app faz `set_config('app.actor_type' | 'app.actor_id' | 'app.impersonator_id' | 'app.request_id' | 'app.ip', …, true)`, tal como o tenant (`TenantTx` passa a exigir o `AuditCtx`).
   - O trigger da L1 lê esse contexto.
   - **Falha fechado:** uma mutação de `ptmarket_app`/`ptmarket_worker` sem `app.actor_type` → `RAISE` e a transação aborta. Uma alteração sem autor não entra.
   - Fora da app (SQL manual, Data Studio), o trigger regista `actor_type = 'db'` com o `session_user`, e o `pgaudit` (L3) guarda o SQL completo.
3. **Só de acréscimo:**
   - a escrita é feita só por uma função `SECURITY DEFINER` cujo dono é o papel `ptmarket_audit_writer`;
   - nenhum papel tem UPDATE ou DELETE;
   - a retenção é feita apagando partições inteiras (`DROP` de partição), por um papel próprio e só fora da app.
   - **Selagem** (decisão do owner, 25/11/2026): a caixa negra vive no schema `audit`, cujo dono é um papel NOLOGIN. O migrator não é membro nem tem privilégios nele, depois de `audit_admin.audit_seal()`. Nenhuma função DEFINER de `audit.*` toca em objetos de papéis com LOGIN. Mudar o schema `audit` exige o superuser.
4. **À prova de adulteração:**
   - uma cadeia de hash por tenant: `hash = sha256(prev_hash ‖ linha canónica)`;
   - um job diário publica a raiz do dia e os eventos críticos num único bucket WORM gerido pela plataforma, com prefixo por `tenant_id`: Backblaze B2 com Object Lock em modo **GOVERNANCE** (nunca COMPLIANCE). A credencial da app/worker só tem PutObject/GetObject, sem Delete nem bypass de governance (decisão do owner, 26/11/2026);
   - **Sem contas de armazenamento para as Câmaras:** todos os tenants usam o bucket da plataforma. Fica previsto, para o futuro, um override opcional de bucket externo na tabela `tenants`, desligado por defeito e alterável só pelo superuser (decisão do owner, 26/11/2026).
   - um comando `verify-audit` recalcula a cadeia e assinala qualquer quebra.
5. **RGPD:**
   - nunca se gravam segredos, passwords, PAN ou IBAN completo (aplica-se a redação de `telemetry`);
   - dados pessoais vão só como referência ao id;
   - quando uma conta é apagada, o `actor_id` é pseudonimizado sem partir a cadeia (o hash usa o id original, e a correspondência é destruída).
6. **Escala:** a gravação custa um INSERT na mesma transação. Particionamento mensal, com índices `(tenant_id, created_at)` e `(target_type, target_id, created_at)`. Exportação para armazenamento frio por partição.

## 4. Quem vê o quê (RLS + RBAC)
- O lojista vê a sua loja e a Câmara o seu tenant; o admin vê tudo, e cada consulta do admin à caixa negra também é auditada.
- A exportação é assinada (CSV/JSON + hash da cadeia) para a ASAE, tribunal ou titular dos dados (RGPD art. 15).

## 5. Retenção (decisão do owner; default até lá)
- O default é 10 anos para eventos financeiros e fiscais, 2 anos para os restantes e 1 ano para as recusas de segurança (na BD). No WORM: eventos 2 anos; raízes diárias 10 anos (KB por dia; o limite superior do intervalo 5–10 anos indicado pelo owner, para cobrir a retenção fiscal da BD) (decisão do owner, 26/11/2026).
