# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Fase 2 em curso (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feitos:** 01, 01b (caixa negra SELADA), 02, 03 (L1, trigger em todas as tabelas), 03b (`db_user` no hash + `audit_upgrade`, 0011), 03c (máscara/dedupe/verify, 0012), 04 (L2, event triggers de DDL, 0013), 05 (pgaudit + WORM local), 06 (AuditCtx), 07 + 07b (middleware por pedido, endurecido), 08 + 08b (escritor do stream), 15 (Argon2id + HIBP). Auditorias ASVS: ondas 1, 2+ e 3 feitas e com achados encaminhados.
- **Próximo:** 03d (0014; máscara PT/EN e por valor, limites, alterações encadeadas) → 09a (0015) → 09 (Go: raiz WORM, verify, alertas, varredura dos 429, stream parado) ∥ 10 (0016) → 11 → 12–14 (0017–0019), 16–21, 22, 23. A BD é sempre em série (numeração); o Rust e o Go correm em paralelo. Cada cartão tem "Depende de". Depois do 03d e do 09: auditoria ASVS da onda 4.
- **Regras (ler antes de mexer em `audit.*`):** o topo da 0008 e a secção "Caixa negra" de `infra/README.md`. O migrator não altera objetos selados: faz-se com uma alteração aprovada no bootstrap (`audit_admin.sealed_changes`), disparada na migration por `audit_admin.audit_upgrade(nome, sha256)`. Cada migration que toca em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma DEFINER nova entra pela allowlist. Chamar `audit.*` sempre com o schema e com tipos exatos; em Rust, com `query_scalar` + casts (regra em `.claude/rules/rust.md`).
- **L2 (event triggers):** exigem superuser. `infra/postgres/bootstrap/event-triggers.sql` corre DEPOIS das migrations (run.sh e dev-check.sh já o fazem). As BDs do `sqlx::test` não têm L2 (a prova é o run.sh).
- **Re-provar:** o 5.º critério do cartão 08 contra uma tabela real com `zz_audit_row`.
- **BD de dev:** na 0013 com event triggers (26/11); run.sh, Rust (87 testes) e Go verdes. URLs de dev em `infra/README.md` (não é preciso ler o `.env`). Ordem depois de mexer no bootstrap: 1) reaplicá-lo como superuser, 2) `sqlx migrate run`, 3) `event-triggers.sql` como superuser (comandos no README).

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
- `infra/scripts/dev-check.sh` não corrido depois do 04. `run.sh` no modo `MIGRATIONS_TEST_URL` não verificado (o host não tem psql). HSTS preload só nos nossos domínios. `split_vat` PROVISÓRIO até haver paridade com o Moloni.
- WebKit: aviso intermitente de CSP em `<link nonce>`. `--toast-reserve` alto em mobile.

## Fase 1 (25/11/2026, concluída)
Fundação: PG 18.1 + Redis 8, papéis sem superuser, RLS FORCE, Omnibus por triggers, Rust (TenantTx, money, logs mascarados), Go (outbox → Asynq), Next 16 (CSP com nonce, componentes acessíveis). Provas e comandos: `infra/README.md`, `migrations/tests/run.sh`, `cargo test`, `go test ./...`, `npm run verify`.

## Pendentes operacionais
- **Push:** quando o owner o pede, faço eu `git push origin main`, depois de `git remote -v` (remote pessoal `Rhandyx`). Se o classificador bloquear, o owner corre `! git push origin main`.
- **Backup:** o owner faz duplo clique em `infra/scripts/backup-nvme.command` no fim de cada ronda (git bundle verificado para o NVMe; o macOS bloqueia o acesso ao disco a partir do Claude Code).
- Worktrees partem do último commit enviado: depois de um push, os executores podem usar `isolation: worktree`.
