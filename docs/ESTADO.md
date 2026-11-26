# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Fase 2 em curso (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feitos:** 01 `audit_events` + cadeia de hash · 01b caixa negra SELADA (schema `audit`, dono NOLOGIN, `audit_admin.audit_seal()` com allowlist de DEFINER e de grants, `audit.audit_alerts`) · 02 funções do worker · 03 trigger L1 em todas as tabelas · 05 pgaudit + WORM local (Versity) · 08 escritor do Redis Stream · 15 Argon2id + HIBP (+ correções da auditoria ASVS da onda 1) · 03b `db_user` + `audit_upgrade` (0011) · 03c máscara/dedupe/verify (0012) · 06 AuditCtx · 07 middleware por pedido · 08b stream endurecido.
- **Auditoria ASVS ondas 2+ (26/11):** feita. Altos → cartão 03b (selagem sem `pg_temp`, `audit_append` aceita 'db') e 04 (o migrator, dono das tabelas, faz DISABLE/DROP dos `zz_audit_*`); médios/baixos → 03c (BD) e 08b (Go). Redis ACL/TLS/HMAC: dívida do épico de produção.
- **Mecanismo novo (03b):** o migrator não altera objetos selados. Isso faz-se com uma alteração aprovada no bootstrap (`audit_admin.sealed_changes`, superuser = duas pessoas), disparada na migration por `audit_admin.audit_upgrade(nome, sha256)`. Numeração: 03b=0011, 03c=0012, 04=0013, 03d=0014, 09a=0015, 10/12/13/14=0016–0019.
- **Auditoria ASVS onda 3 (26/11):** feita. 2 altos (NUL em path params, flood de 401/anónimos) + médios → cartões 07b (Rust) e 03d (BD, 0014); o achado do worker (paragem > 7 dias) foi para o cartão 09.
- **Em curso:** 04 (0013). Próximos: 07b ∥ 03d (0014) → 09a (0015) → 09 (Go) ∥ 10 (0016) → 11 → 12–14 (0017–0019), 16–21, 22, 23. Cada cartão tem "Depende de".
- **Regras (ler antes de mexer em `audit.*`):** o topo da 0008 e `infra/README.md`. Cada migration que toca em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma DEFINER nova entra pela allowlist no bootstrap. Chamar `audit.*` sempre com o schema e com tipos exatos.
- **Re-provar:** o 5.º critério do cartão 08 contra uma tabela real com `zz_audit_row`.
- **BD de dev:** na 0012 (bootstrap reaplicado a 26/11); Rust, Go e run.sh verdes contra ela. URLs de dev em `infra/README.md` (não é preciso ler o `.env`). Depois de cada alteração ao bootstrap: reaplicá-lo como superuser ANTES do `sqlx migrate run`.

## Decisões do owner (25–26/11; a fonte é a spec 13 + `docs/CUSTOS.md`)
1. WORM: um só bucket da plataforma, Backblaze B2, Object Lock GOVERNANCE, prefixo por tenant. Eventos 2 anos, raízes 10 anos. O pgaudit não vai para o WORM. Sem buckets das Câmaras (override futuro desligado).
2. Alertas imediatos Telegram + Discord, só para eventos críticos (IBAN, falhas de pagamento/faturação, login de superadmin, falha do verify-audit).
3. Timeline no Super-Admin, filtrável por tenant/loja/utilizador/encomenda: a API é o cartão 23; a UI é o 1.º cartão do épico de backoffice.
4. 429: o 1.º por chave/minuto é gravado de forma síncrona; os restantes contam-se e saem num resumo; Redis em baixo → 503. Sessões: cliente 7 dias no máximo; staff 12 h/30 min; plataforma 8 h/15 min.
5. Pendentes: textos dos Termos/Privacidade (o owner traz um documento antigo; agente jurídico, só local; bloqueia a produção). IVA ES / NIF ES no futuro. Marca (fontes/paleta). Retenção da BD: default 10/2/1 anos.

## Dívida técnica conhecida
- `cargo deny` não instalado e sem `deny.toml`. API sem graceful shutdown no SIGTERM.
- 0001/0007 criam papéis (a corrida está resolvida pelo bootstrap, que cria todos os papéis antes). Em produção, a BD deve ter dono `postgres` e o migrator não deve ter CREATEDB.
- Filtro por `store_id` na leitura da auditoria pelo lojista (anti-IDOR entre lojas): pô-lo no cartão desse endpoint.
- `run.sh` no modo `MIGRATIONS_TEST_URL` não verificado (o host não tem psql). HSTS preload só nos nossos domínios. `split_vat` PROVISÓRIO até haver paridade com o Moloni.
- WebKit: aviso intermitente de CSP em `<link nonce>`. `--toast-reserve` alto em mobile.

## Fase 1 (25/11/2026, concluída)
Fundação: PG 18.1 + Redis 8, papéis sem superuser, RLS FORCE, Omnibus por triggers, Rust (TenantTx, money, logs mascarados), Go (outbox → Asynq), Next 16 (CSP com nonce, componentes acessíveis). Provas e comandos: `infra/README.md`, `migrations/tests/run.sh`, `cargo test`, `go test ./...`, `npm run verify`.

## Pendentes operacionais
- **Push:** o classificador bloqueia o meu `git push`. O owner corre `! git push origin main` (remote pessoal `Rhandyx`; antes, `git remote -v`).
- **Backup:** o owner faz duplo clique em `infra/scripts/backup-nvme.command` no fim de cada ronda (git bundle verificado para o NVMe; o macOS bloqueia o acesso ao disco a partir do Claude Code).
- Worktrees partem do último commit enviado: depois de um push, os executores podem usar `isolation: worktree`.
