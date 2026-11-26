# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Fase 2 em curso (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feitos:** 01–08b, 15 (rondas anteriores); nesta ronda: 03d (0014), 09a (0015), 09 (Go), 10 (0016), 11 (Rust), 12 (0017), 13 (0018), 14 (0019), 22 (frontend), 16 (Rust, sessões/CSRF), 03e (0020). Auditoria ASVS da onda 4 feita → cartões 03e, 10b, 09b, 11b (commit d2848d0); 17, 18 e 20 atualizados.
- **Próximo:** 10b (0021) ∥ 09b (Go) → 11b (Rust) → 17 → 18 → 19 → 20 → 21 → 23. A BD é sempre em série. Entre o 10b e o 11b, os testes Rust do portal ficam vermelhos (a policy `portal_read` de stores passa para a view `portal_stores`).
- **Para o owner (sem pressa):** a view do portal mostra `legal_name`, NIF e contactos da loja (obrigação legal: DSA art. 30.º, DL 7/2004 art. 10.º). Antes de aplicar a 0020 em produção, esvaziar o stream de auditoria. Em produção, confirmar que a chave B2 só tem Put/Get e testar o Telegram e o Discord reais.
- **Regras (ler antes de mexer em `audit.*`):** o topo da 0008 e a secção "Caixa negra" de `infra/README.md`. O migrator não altera objetos selados: faz-se com uma alteração aprovada no bootstrap (`audit_admin.sealed_changes`), disparada na migration por `audit_admin.audit_upgrade(nome, sha256)`. Cada migration que toca em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma DEFINER nova entra pela allowlist. Chamar `audit.*` sempre com o schema e com tipos exatos; em Rust, com `query_scalar` + casts (regra em `.claude/rules/rust.md`).
- **L2 (event triggers):** exigem superuser. `infra/postgres/bootstrap/event-triggers.sql` corre DEPOIS das migrations (run.sh e dev-check.sh já o fazem). As BDs do `sqlx::test` não têm L2 (a prova é o run.sh).
- **Padrões novos:** as tabelas novas levam o bloco L1 condicional (ver o topo da 0018); as alterações seladas são uma cadeia linear (`sealed_changes.requires`); as funções `identity_*` têm dono `ptmarket_identity`, e as asserções dos testes listam-nas todas (atualizar a allowlist em customers.sql e users_rbac.sql).
- **BD de dev:** na 0020 com event triggers; run.sh, Rust (131 testes), Go e `npm run verify` verdes. Depois de mudar o `openapi.json`: `npm run gen:api` no frontend (o `check:api` chumba se não o fizeres). URLs de dev em `infra/README.md` (não é preciso ler o `.env`). Ordem depois de mexer no bootstrap: 1) reaplicá-lo como superuser, 2) `sqlx migrate run`, 3) `event-triggers.sql` como superuser (comandos no README).

## Decisões do owner (25–26/11; a fonte é a spec 13 + `docs/CUSTOS.md`)
1. WORM: um só bucket da plataforma, Backblaze B2, Object Lock GOVERNANCE, prefixo por tenant. Eventos 2 anos, raízes 10 anos. O pgaudit não vai para o WORM. Sem buckets das Câmaras (override futuro desligado).
2. Alertas imediatos Telegram + Discord, só para eventos críticos (IBAN, falhas de pagamento/faturação, login de superadmin, falha do verify-audit).
3. Timeline no Super-Admin, filtrável por tenant/loja/utilizador/encomenda: a API é o cartão 23; a UI é o 1.º cartão do épico de backoffice.
4. 429: o 1.º por chave/minuto é gravado de forma síncrona; os restantes contam-se e saem num resumo; Redis em baixo → 503. Sessões: cliente 7 dias no máximo; staff 12 h/30 min; plataforma 8 h/15 min.
5. Pendentes: textos dos Termos/Privacidade (o owner traz um documento antigo; agente jurídico, só local; bloqueia a produção). IVA ES / NIF ES no futuro. Marca (fontes/paleta). Retenção da BD: default 10/2/1 anos.

## Dívida técnica conhecida
- O run.sh liga a L2 DEPOIS das migrations, por isso não apanha uma migration que falhe com os event triggers ativos (aconteceu no 03e). Acrescentar uma 2.ª passagem: BD até N-1 + L2 → migration N.
- `cargo deny` não instalado e sem `deny.toml`. API sem graceful shutdown no SIGTERM.
- 0001/0007 criam papéis (a corrida está resolvida pelo bootstrap, que cria todos os papéis antes). Em produção, a BD deve ter dono `postgres` e o migrator não deve ter CREATEDB.
- Filtro por `store_id` na leitura da auditoria pelo lojista (anti-IDOR entre lojas): pô-lo no cartão desse endpoint.
- `infra/scripts/dev-check.sh` não corrido depois do 04. `run.sh` no modo `MIGRATIONS_TEST_URL` não verificado (o host não tem psql). HSTS preload só nos nossos domínios. `split_vat` PROVISÓRIO até haver paridade com o Moloni.
- WebKit: aviso intermitente de CSP em `<link nonce>`. `--toast-reserve` alto em mobile.

## Fase 1 (25/11/2026, concluída)
Fundação: PG 18.1 + Redis 8, papéis sem superuser, RLS FORCE, Omnibus por triggers, Rust (TenantTx, money, logs mascarados), Go (outbox → Asynq), Next 16 (CSP com nonce, componentes acessíveis). Provas e comandos: `infra/README.md`, `migrations/tests/run.sh`, `cargo test`, `go test ./...`, `npm run verify`.

## Pendentes operacionais
- **Push:** quando o owner o pede, faço eu `git push origin main`, depois de `git remote -v` (remote pessoal `Rhandyx`). Se o classificador bloquear, o owner corre `! git push origin main`.
- **Backup:** o owner faz duplo clique em `infra/scripts/backup-nvme.command` no fim de cada ronda: bundle git verificado + memórias + `.env` numa imagem encriptada AES-256 (password pedida no Terminal). O macOS bloqueia o acesso ao disco a partir do Claude Code.
- Worktrees partem do último commit enviado: depois de um push, os executores podem usar `isolation: worktree`.
