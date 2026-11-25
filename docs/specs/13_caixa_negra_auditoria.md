# 13. Caixa negra: auditoria de tudo o que acontece na plataforma

> Pedido do owner (25/11/2026). Prevalece sobre a spec 07 §3.4 e a 12 §3, que só cobriam ações de admin: `admin_audit_logs` passa a ser a categoria `admin` desta tabela única.

## 0. Princípio (owner): "mega auditoria", logs de tudo na base de dados
- **Todas as tabelas da BD**, sem exceção, registam cada INSERT, UPDATE e DELETE em `audit_events`: quem, quando, de onde, o quê e os valores antes/depois. Isto inclui produtos, variantes, lojas, utilizadores, clientes, papéis, encomendas, pagamentos e definições.
- As únicas exceções são técnicas e estão numa allowlist fixa no teste: o próprio `audit_events` e `outbox_events`, cujo conteúdo já está no evento de negócio auditado. Não há opt-in: uma tabela nova sem trigger chumba os testes.
- Há 4 camadas, para nada escapar:
  - **L1, trigger de linha genérico em todas as tabelas:** captura tudo o que muda dados, venha da app, do Data Studio, de SQL manual ou de um worker.
  - **L2, event trigger de DDL:** `CREATE`/`ALTER`/`DROP` de tabelas, funções, policies, papéis e grants vão para `audit_events` (`action = 'ddl.*'`). Uma tabela criada por migration recebe logo o trigger da L1 automaticamente.
  - **L3, `pgaudit`** (logs do Postgres, enviados para WORM): sessões de superuser e manutenção, que podem passar ao lado dos triggers.
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
- **Recusas:** também se regista o que foi negado (`outcome = 'denied'`): 401/403, tentativas IDOR, login falhado, rate-limit, CSRF e webhook com assinatura inválida.
- **Fora de âmbito:** leituras normais de catálogo, que ficam nos logs/métricas e não na caixa negra. Exceção: são registadas as leituras de dados pessoais por staff ou admin (ver ficha de cliente, exportar).

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
4. **À prova de adulteração:**
   - uma cadeia de hash por tenant: `hash = sha256(prev_hash ‖ linha canónica)`;
   - um job diário publica a raiz do dia num armazenamento WORM externo (R2/S3 Object Lock);
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
- O default é 10 anos para eventos financeiros e fiscais, 2 anos para os restantes e 1 ano para as recusas de segurança.
