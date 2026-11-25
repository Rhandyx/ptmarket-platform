# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 26/11/2026 — Fase 2 em curso (épico `02-identidade-tenancy`, cartões em `docs/plans/02-identidade-tenancy/`)
- **Feitos:** 01 `audit_events` + cadeia de hash · 01b caixa negra SELADA (schema `audit`, dono NOLOGIN, `audit_admin.audit_seal()` com allowlist de DEFINER e de grants, `audit.audit_alerts`) · 02 funções do worker · 03 trigger L1 em todas as tabelas · 05 pgaudit + WORM local (Versity) · 08 escritor do Redis Stream · 15 Argon2id + HIBP (+ correções da auditoria ASVS da onda 1).
- **Próxima onda:** 04 (DDL L2) ∥ 06 (AuditCtx Rust) ∥ 09a (eventos críticos + índices da timeline, migration 0012). Depois 07 → 09 → 10 → 11 → 12–14, 16–21, 22, 23 (API da timeline). Grafo de ondas no relatório do architect: cada cartão tem "Depende de".
- **Regras novas (ler antes de mexer em `audit.*`):** o topo da 0008 e `infra/README.md`. O migrator tem USAGE+CREATE em `audit`, mas não manda em nada selado. Cada migration que toca em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma DEFINER nova só entra pela allowlist em `infra/postgres/init/03-audit-bootstrap.sh` (aplicada pelo superuser = duas pessoas). Chamar `audit.*` sempre com o schema e com tipos exatos.
- **1.º cartão da próxima sessão (03b, a escrever pelo supervisor):** o migrator tem SET em `ptmarket_app` (precisa dele para os GRANT da 0001/0007) e por isso consegue forjar eventos com ator da app. Correção: cada evento grava `db_user = session_user` (dentro do hash), e o verify assinala eventos com ator de app/worker cujo `db_user` não seja o papel LOGIN esperado. O pgaudit 'misc' já regista o SET ROLE. Avaliar também retirar o SET depois do bootstrap.
- **Re-provar:** o 5.º critério do cartão 08 contra uma tabela real com `zz_audit_row`. A auditoria ASVS das ondas 2+ (01b, 02, 03, 08) ainda não correu: fazer antes do 06.
- **BD de dev** recriada a 26/11 com o bootstrap novo (0001–0009). Depois de cada migration nova: `sqlx migrate run`.

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
