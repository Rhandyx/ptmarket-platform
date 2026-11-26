# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Fase 2 CONCLUÍDA (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feito:** todos os cartões (01–24b, 20b/20c, 23a). Cada um passou pela auditoria ASVS (L3 em admin/identity) e os achados foram corrigidos na mesma ronda. No fim: Rust (suite completa), `run.sh` (com L2) e `npm run verify` verdes; o Go não muda desde o 24a.
- **Próximo:** épico 03. O `architect-master` escreve os cartões. Candidatos: frontend de autenticação (registo, login, 2FA, passkeys com prova em browser real) + backoffice (o 1.º cartão é a UI da timeline); depois o catálogo. O supervisor decide a ordem.
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
