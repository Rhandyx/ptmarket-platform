# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Épico 03 EM CURSO (`docs/plans/03-patrocinio-comissoes/`, ordem no `00-INDICE.md`)
- **Feito e commitado:** 01, 02, 12, 03, 04, 13, 05, 06, 07, par A (08 + 16), 0034 (tiered), par B (08b + 14), 09 (0036), 10 (0037) e 11 (0038, selada `0038_critical_kinds_commission`). **A camada de BD do épico está fechada**: a BD de dev está na **0038** e tem o DICOFRE carregado (CAOP 2025, 3596 linhas).
- **Próximo:** 15 → 17 → 18 → 19 → 20 (adenda: entidade desativada → 404) + 26 (frontend, depois do 18).
- **Nota de plano (owner, 27/11):** fechados esses, **pausar 21–25** (storage privado, verificações e jobs Go 24/25; as adendas do 23 e do 25 ficam à espera) e priorizar: (a) **Montra Pública**: migration **0039** (views de portal para `products`/`categories`) + rotas HTTP read-only sobre `tenancy::portal` no OpenAPI + frontend; (b) **ecrã de aprovação do `sponsor_admin`** em `admin.ptmarket.pt` (sobre a API do 20). Ambos precisam de cartões novos do architect-master.
- **Como correu:** db-architect/rust-core em série no checkout principal, sem commits dos agentes; o supervisor revê, corre as suites, aplica em dev e commita. A auditoria pode correr em paralelo com o executor seguinte (só lê). Quando um executor pára no limite de turnos, retomá-lo com SendMessage. Corrigir uma migration aplicada em dev mas ainda não commitada: CREATE OR REPLACE em dev + `UPDATE _sqlx_migrations SET checksum = decode(sha384 do ficheiro,'hex')`.
- **CAOP:** `infra/data/geo/dicofre_caop2025.csv` + `infra/scripts/caop-to-dicofre-csv.py` (README "Seed DICOFRE"). Os códigos DTMNFR de 2025 têm 18 freguesias com letras (ex.: `0302FA`): validar sempre com `length()` + FK, nunca com regex só de algarismos.
- **Testes (sem `.env` no repo):** `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api --no-fail-fast`; a mesma URL para `sqlx migrate run --source migrations`. O `build.rs` recompila quando `migrations/` muda (antes dava verde falso). O owner autorizou correr os testes (26/11).
- **Regras novas:**
  - `stores` tem grants por coluna (0029): uma coluna nova precisa de `GRANT INSERT/UPDATE (col)` à app.
  - Tabelas de referência levam a policy `migrator_all`.
  - Rotas de dinheiro/IBAN usam `RequireStoreOwner` (2FA), nunca `RequireStoreRole`.
  - Âmbito por loja (0035 + 14): escrita/leitura de backoffice em tabelas de loja só com `begin_store_tx(StoreScope)` (do `RequireStoreRole`/`RequireStoreOwner`) ou `begin_sponsor_tx(SponsorScope)` (do `RequireSponsorAdmin`); exceção: ator admin sem impersonação. Leitura pública só pelo portal. Uma tabela nova com `store_id` ou FK (em cadeia) para lojas precisa das 4 policies `store_scope_*` (o teste chumba). Um `national_portal` por país.
  - Arredondamento: Decimal → cêntimos só via `money::half_up` (half-up); `money/no_loose_round.rs` chumba `round_dp`/`round`/`round_sf` soltos em todo o `src/` (27/11).
  - Auditoria por loja (0038): `audit.audit_events` tem `store_scope_read` RESTRICTIVE para a app, **fail-closed** (só a loja de `app.store_id`, ou admin sem impersonação). As expressões estão inline (a `audit_seal` não deixa `audit` depender de `public`): mudar `app_store_id`/`app_is_platform_admin` obriga a uma alteração selada nova. Bootstrap: o `ptmarket_identity` tem EXECUTE em `audit_append_db` (0037); num cluster existente, reaplicar o bootstrap antes da 0037/0038.
  - Verificações (0036/0037): o ficheiro E o código cifrado da Certidão (`v1:<kid8hex>:<base64>`, CHECK) apagam-se até 30 dias depois da decisão; o worker apaga ambos num só UPDATE com `file_deleted_at`.
  - 0034 (27/11, aplicada em dev): `tiered_subscription` = só mensalidade, 0 bps. Com patrocínio `active` o plano não entra: desconto contra a âncora (800 ou exceção) e mensalidade 0 (`money::monthly_fee_due`; a cobrança usa esta, nunca `monthly_fee_for`).
- **Dívida do 08b (auditoria, 27/11), fechar antes de produção:** (1) `app_is_platform_admin()` confia só no GUC `app.actor_type='admin'`: passar a DEFINER (dona `ptmarket_identity`) com as verificações da porta da 0026 (super_admin ativo com TOTP + sessão de plataforma com MFA, não revogada), refazendo os seeds de admin nos testes SQL/Rust. (2) `store_sponsorships.decided_by` não é verificado na BD (a entidade pode gravar outro user): `WITH CHECK decided_by = app.actor_id`. (3) Convites da entidade (`initiated_by='sponsor'`) e criação de patrocínios pelo admin: épico futuro (a 0035 só deixa a loja pedir). O Alto (auditoria legível entre lojas) ficou fechado na 0038. (1) inclui atualizar a policy selada `store_scope_read` da 0038.
- **Dívida do 09–11 (auditorias, 27/11):** (a) `audit.audit_append` aceita `p_store_id` ≠ `app.store_id` (um handler com bug põe eventos na timeline de outra loja): recusar numa alteração selada futura, salvo ator admin/system. (b) Os eventos L1 de `product_variants`/`product_price_history` ficam sem `store_id` (o lojista não os vê): pôr a coluna ou preencher `v_store` na L1 (alteração selada). (c) `storage_key` não está na máscara da L1 (o super_admin vê-o na timeline; sem acesso ao ficheiro). Eventos nomeados de `secret`/`decide`: adenda do cartão 23.
- **Dívida:** a sessão absoluta de staff/sponsor_admin fica em 8 h, e não nas 12 h, por causa do CHECK `sessions_max_lifetime` da 0019 (precisa de uma migration nova). O `RequireTenantAdmin` dá 403 a quem não tem o papel e 404 a quem o tem noutro tenant (aceite). Mudar o `tenant_type` de um tenant que já tem lojas ou é canal não é revalidado (trigger em `tenants` futuro). `portal::with_badges` faz O(n·m) (≤100): trocar por HashMap.

## 26/11/2026 — Fase 2 CONCLUÍDA (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feito:** todos os cartões (01–24b, 20b/20c, 23a). Cada um passou pela auditoria ASVS (L3 em admin/identity) e os achados foram corrigidos na mesma ronda. No fim: Rust (suite completa), `run.sh` (com L2) e `npm run verify` verdes; o Go não muda desde o 24a.
- **Próximo:** épico 03 (spec 14). Os cartões estão em `docs/plans/03-patrocinio-comissoes/`; a ordem, os pares atómicos ([08 → 16], [08b → 14]) e o paralelismo estão em `00-INDICE.md`. **Antes do cartão 02, o supervisor obtém a CAOP da DGT** (dados abertos, versão mais recente) e converte-a para o CSV intermédio. Perguntas do owner no índice: nenhuma bloqueia o arranque. Depois deste épico: frontend de autenticação e backoffice (o 1.º cartão é a UI da timeline).
- **Dev:** BD na 0026 com L2; a cadeia selada termina em `0026_admin_read_events_v2`. Os `.env` locais (Rust e Go) precisam de `APP_ENV=development` (o owner acrescenta). Depois de mudar o `openapi.json`: `npm run gen:api`. Depois de mexer no bootstrap: 1) reaplicá-lo como superuser, 2) `sqlx migrate run`, 3) `event-triggers.sql` (se faltarem). Os executores Rust correm um de cada vez (o mesmo `target/`; o hook faz `cargo fmt`); Go e BD podem ir em paralelo com o Rust só se as migrations não estiverem a mudar.
- **Identidade (como está):**
  - **Emails:** hash sempre com `throttle::account_hash` (HMAC, `ACCOUNT_HASH_KEY`).
  - **Origin:** exigida no register e no login (clientes e staff) e no passkey anónimo.
  - **2FA:** obrigatório no servidor (`totp_enabled` ou papel admin; `RequireStoreOwner` exige-o sempre). `RequireStaffPreMfa` só no `/staff/me` e nas rotas de 2FA.
  - **TOTP:** AES-GCM `v1:<kid>` (`TOTP_ENC_KEY`, `TOTP_ENC_KEYS_OLD`).
  - **Recuperação:** códigos em HMAC por utilizador.
  - **`/api/v1/superadmin/*`:** 404 uniforme.
  - **1.º super_admin:** pelo CLI `ptmarket-admin` (função 0024; `infra/README.md`).
  - **Passkeys:** reautenticação de 10 min (`REAUTH_WINDOW`).
  - **Código partilhado:** elevação e rotação em `identity/elevate.rs`.
  - **Timeline:** lida só por `identity_admin_read_events`, que grava a própria leitura na cadeia; o GUC `app.session_id` só serve portas de BD.
  - **Produção:** `APP_ENV` obrigatório; em staging/production a API exige `TRUSTED_PROXY_CIDRS`, `INTERNAL_PROXY_TOKEN`, `CSRF_KEY`, `PLATFORM_ADMIN_HOST`, `TURNSTILE_SECRET` (sem chaves de teste), `ACCOUNT_HASH_KEY` e `TOTP_ENC_KEY`. O worker recusa `ALERT_DEV_LOG_ONLY`, WORM sem https e retenção abaixo de 730/3650.
- **Regras e lições (ler antes de mexer em `audit.*`):**
  - **Processo:** o topo da 0008 e a secção "Caixa negra" do `infra/README.md` (alteração selada → `audit_upgrade` → `audit_seal()`).
  - **DEFINER:** nenhuma DEFINER de `audit.*` lê `public`; a porta fica numa `identity_*` (padrão da 0025/0026).
  - **Migrations:** nunca `SET ROLE` para um papel sem acesso a `audit`.
  - **Tabelas novas:** levam o bloco L1 (topo da 0018).
  - **Rust:** `audit.*`, `portal_stores` e `identity_*` com `query_as` estático + casts.
  - **Executores:** muitas vezes chegam ao limite de turnos; retomá-los com SendMessage ("continua sem reler").

## Para o owner / produção (sem pressa)
- A view do portal mostra `legal_name`, NIF e contactos da loja (DSA art. 30.º, DL 7/2004 art. 10.º). Antes de aplicar a 0020 e a 0023 em produção, esvaziar o stream de auditoria. Confirmar que a chave B2 só tem Put/Get; testar o Telegram e o Discord reais.
- Redis de produção: `appendonly yes` + `maxmemory-policy noeviction` (o agrupamento de alertas vive lá). IP do servidor Next em `TRUSTED_PROXY_CIDRS` e o Next a reenviar o IP real; sem isso o SSR conta como um só IP no travão de Hosts (30/min).

## Decisões do owner (25–26/11; a fonte é a spec 13 + `docs/CUSTOS.md`)
1. WORM: um só bucket da plataforma, Backblaze B2, Object Lock GOVERNANCE, prefixo por tenant. Eventos 2 anos, raízes 10 anos. O pgaudit não vai para o WORM. Sem buckets das Câmaras (override futuro desligado).
2. Alertas imediatos Telegram + Discord, só para eventos críticos (IBAN, falhas de pagamento/faturação, login de superadmin, falha do verify-audit). Mais de 5 do mesmo kind/tenant em 5 min → resumo; `audit.*`, `verify_failure`, `superadmin_login` e sem tenant nunca se agrupam.
3. Timeline no Super-Admin, filtrável por tenant/loja/utilizador/encomenda: a API é o cartão 23; a UI é o 1.º cartão do épico de backoffice.
4. 429: o 1.º por chave/minuto é gravado de forma síncrona; os restantes contam-se e saem num resumo; Redis em baixo → 503 (vale também para o travão de Hosts fora da cache; a cache, mesmo expirada, continua a ser servida). Sessões: cliente 7 dias no máximo; staff 12 h/30 min; plataforma 8 h/15 min.
6. **Modelo comercial (26/11, spec 14 canónica):**
   - **Canais e catálogo:** `tenants` = canais com domínio (`custom_domain` continua NOT NULL) e `sponsor_entities` = Câmara, Junta ou Associação (N:N com as lojas por `store_sponsorships`: pending/active/rejected/expired/revoked). Catálogo universal em `lojaportugal.pt`, sem opt-out (`shipping_scope` controla a entrega); `stores.tenant_id` = canal nacional do país.
   - **Comissão:** patrocínio ativo → `MIN(commission_override_bps)` (0); senão `custom_commission_bps` (só super_admin); senão o plano (`commission_payg` 8%/6% marginal por defeito, ou `tiered_subscription` = só mensalidade de 5 € a 500 €/mês, 0% de comissão: 0034, 27/11), com escalões em `billing_plan_tiers` (nunca hardcoded). `sponsored_discount_cents` = (referência 8% ou exceção) − fee, sobre o subtotal sem portes, half-up. A cobrança das mensalidades fica para o épico de pagamentos.
   - **Painel e preços:** painel único `admin.ptmarket.pt` (âmbito pelo papel; `sponsor_admin`). Preço único por tipo de entidade, com ou sem domínio próprio. O domínio white-label (3 templates + PWA) é uma opção incluída a 0 €, que se ativa no arranque ou mais tarde (correção do owner, 26/11). Os valores:
     - Câmara: 12.500–14.500 € no Ano 1 + 2.700–3.600 €/ano (o triénio CCP do doc 01 §3.2 mantém-se).
     - Junta/Associação: 750–1.500 € + 1.200–1.800 €/ano. Pode operar só com selos e página dedicada ou ativar o domínio.
5. Pendentes: textos dos Termos/Privacidade (o owner traz um documento antigo; agente jurídico, só local; bloqueia a produção). IVA ES / NIF ES no futuro. Marca (fontes/paleta). Retenção da BD: default 10/2/1 anos.

## Dívida técnica conhecida
- Guarda de memberships de `ptmarket_identity`/`ptmarket_portal` só corre na 0022: repetir num job periódico do worker (alerta `audit.*`) e verificar também CREATEROLE/CREATEDB/REPLICATION.
- Go: tipos com nome sobre `[]byte` saem em base64 no log. Resumo de alertas sem dedupe por canal (falha parcial repete).
- `cargo deny` não instalado e sem `deny.toml`. API sem graceful shutdown no SIGTERM. `golangci-lint` não instalado.
- 0001/0007 criam papéis (corrida resolvida pelo bootstrap). Em produção, a BD deve ter dono `postgres` e o migrator não deve ter CREATEDB.
- Filtro por `store_id` na leitura da auditoria pelo lojista (anti-IDOR entre lojas): pô-lo no cartão desse endpoint.
- `infra/scripts/dev-check.sh` não corrido depois do 04. `run.sh` no modo `MIGRATIONS_TEST_URL` não verificado (o host não tem psql; agora exige também `MIGRATIONS_TEST_L2_URL`/`_L2_SUPER_URL`). HSTS preload só nos nossos domínios. `split_vat` PROVISÓRIO até haver paridade com o Moloni.
- **Identidade (da Fase 2):**
  - `form_started_at` vem do cliente: passar a carimbo HMAC.
  - Limite de 1 email "já tem conta" por cliente a cada 24 h.
  - Falta `nif_country`.
  - Alertas críticos às ~50 falhas de login por conta e às 10 de MFA (precisam de um kind crítico novo).
  - O logout anónimo não verifica a Origin.
  - Os testes de integração estão perto do limite da pool do Postgres.
  - O `RequireStoreRole` lê `stores` a partir de `identity` (trocar pela API de lojas).
  - Falta o enroll por token para os `tenant_admin` novos (convites no backoffice).
  - Comentário desatualizado na 0024:167 (checksum: não mexer).
  - O `dev-check` deve verificar `proacl`/`prosecdef` das DEFINER novas.
  - O CLI não foi testado num terminal real.
  - Passkeys sem prova em browser real (conditional UI).
  - `chain_ok` não deteta o corte do prefixo (a retenção deve gravar o piso).
  - Os helpers de teste estão copiados entre `tests/totp.rs` e `admin_timeline.rs`.
- WebKit: aviso intermitente de CSP em `<link nonce>`. `--toast-reserve` alto em mobile.

## Fase 1 (25/11/2026, concluída)
Fundação: PG 18.1 + Redis 8, papéis sem superuser, RLS FORCE, Omnibus por triggers, Rust (TenantTx, money, logs mascarados), Go (outbox → Asynq), Next 16 (CSP com nonce, componentes acessíveis). Provas e comandos: `infra/README.md`, `migrations/tests/run.sh`, `cargo test`, `go test ./...`, `npm run verify`.

## Pendentes operacionais
- **Push:** quando o owner o pede, faço eu `git push origin main`, depois de `git remote -v` (remote pessoal `Rhandyx`). Se o classificador bloquear, o owner corre `! git push origin main`.
- **Backup:** o owner faz duplo clique em `infra/scripts/backup-nvme.command` no fim de cada ronda: bundle git + memórias + `.env` numa única imagem encriptada AES-256 (password pedida no Terminal), copiada para o NVMe e para `Backups_PTMarket` no Google Drive pessoal (basta um dos dois; o Drive guarda os 10 mais recentes). O macOS bloqueia o acesso ao disco a partir do Claude Code.
- Worktrees partem do último commit enviado: depois de um push, os executores podem usar `isolation: worktree`. Nesta ronda os executores correram no checkout principal (pastas disjuntas, sem commits) e correu bem.
