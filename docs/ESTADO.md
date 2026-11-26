# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 (2.ª ronda) — Fase 2 em curso (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feitos:** 01–16, 22, 03e (rondas anteriores); nesta ronda: 10b (0021), 09b (Go), 10c (0022 + run.sh com 2.ª passagem L2), 09c (Go: agrupamento de alertas no Redis), 11b (Rust: portal pela view, travão a Hosts), 03f (0023: a máscara da BD corrompia UUIDs). Cada um passou pela auditoria ASVS e os achados foram corrigidos na mesma ronda.
- **Próximo:** 17 → 18 → 19 → 20 → 21 → 23 → **24 (por escrever)**: `APP_ENV` obrigatório no Rust e no Go; em produção recusa `TRUSTED_PROXY_CIDRS` vazio (Rust) e `ALERT_DEV_LOG_ONLY=1` (Go). A BD é sempre em série.
- **Estado de dev:** BD na 0023 com L2; run.sh, Rust (todos), Go `-race`, `npm run verify` verdes. Depois de mudar o `openapi.json`: `npm run gen:api`. URLs em `infra/README.md`. Depois de mexer no bootstrap: 1) reaplicá-lo como superuser, 2) `sqlx migrate run`, 3) `event-triggers.sql` (se faltarem; o bootstrap mantém-nos).
- **Regras (ler antes de mexer em `audit.*`):** o topo da 0008 e a secção "Caixa negra" de `infra/README.md` (alteração selada no bootstrap → `audit_admin.audit_upgrade(nome, sha256)` → `audit_seal()`; cadeia linear, a última é `0023_mask_uuid`). Em Rust, `audit.*` e `portal_stores` com `query_as` estático + casts (`.claude/rules/rust.md`).
- **Lição (L2):** numa migration, nunca `SET ROLE` para um papel sem acesso a `audit` (`ptmarket_identity`, `ptmarket_portal`): a L2 recusa o DDL (42501). Para agir como dono: INHERIT temporário no migrator e repor `INHERIT FALSE, SET TRUE` (padrão do ponto D da 0021). O run.sh agora apanha isto (2.ª passagem: última migration com a L2 já ligada).
- **Padrões:** tabelas novas levam o bloco L1 condicional (topo da 0018); funções `identity_*` com dono `ptmarket_identity` e `search_path = pg_catalog, pg_temp`; o portal lê lojas só por `portal_stores` (dona `ptmarket_portal`); a 0022 recusa memberships estranhas nesses dois papéis.

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
- Códigos de recuperação: com a app comprometida, DELETE + INSERT do mesmo `code_hash` reativa um código (cartão 20: gerar sempre códigos novos). Go: tipos com nome sobre `[]byte` saem em base64 no log. Resumo de alertas sem dedupe por canal (falha parcial repete).
- `cargo deny` não instalado e sem `deny.toml`. API sem graceful shutdown no SIGTERM. `golangci-lint` não instalado.
- 0001/0007 criam papéis (corrida resolvida pelo bootstrap). Em produção, a BD deve ter dono `postgres` e o migrator não deve ter CREATEDB.
- Filtro por `store_id` na leitura da auditoria pelo lojista (anti-IDOR entre lojas): pô-lo no cartão desse endpoint.
- `infra/scripts/dev-check.sh` não corrido depois do 04. `run.sh` no modo `MIGRATIONS_TEST_URL` não verificado (o host não tem psql; agora exige também `MIGRATIONS_TEST_L2_URL`/`_L2_SUPER_URL`). HSTS preload só nos nossos domínios. `split_vat` PROVISÓRIO até haver paridade com o Moloni.
- WebKit: aviso intermitente de CSP em `<link nonce>`. `--toast-reserve` alto em mobile.

## Fase 1 (25/11/2026, concluída)
Fundação: PG 18.1 + Redis 8, papéis sem superuser, RLS FORCE, Omnibus por triggers, Rust (TenantTx, money, logs mascarados), Go (outbox → Asynq), Next 16 (CSP com nonce, componentes acessíveis). Provas e comandos: `infra/README.md`, `migrations/tests/run.sh`, `cargo test`, `go test ./...`, `npm run verify`.

## Pendentes operacionais
- **Push:** quando o owner o pede, faço eu `git push origin main`, depois de `git remote -v` (remote pessoal `Rhandyx`). Se o classificador bloquear, o owner corre `! git push origin main`.
- **Backup:** o owner faz duplo clique em `infra/scripts/backup-nvme.command` no fim de cada ronda: bundle git + memórias + `.env` numa única imagem encriptada AES-256 (password pedida no Terminal), copiada para o NVMe e para `Backups_PTMarket` no Google Drive pessoal (basta um dos dois; o Drive guarda os 10 mais recentes). O macOS bloqueia o acesso ao disco a partir do Claude Code.
- Worktrees partem do último commit enviado: depois de um push, os executores podem usar `isolation: worktree`. Nesta ronda os executores correram no checkout principal (pastas disjuntas, sem commits) e correu bem.
