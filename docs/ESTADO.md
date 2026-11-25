# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal, Opus). Secções recentes no topo. Máx. ~40 linhas: o histórico está no git.

## 25/11/2026 — Fase 1 concluída (épico `01-fundacao`, 9 cartões + auditorias)
- **Dev:** `infra/scripts/dev-check.sh` sobe PG 18.1 + Redis 8 (127.0.0.1). Papéis: `ptmarket_migrator` (dono), `ptmarket_app` (API), `ptmarket_worker` (outbox), `ptmarket_price_writer` (só trigger Omnibus). Nenhum é superuser.
- **BD** `migrations/0001–0007`: RLS FORCE com contexto `app.current_tenant_id`. Omnibus calculado por triggers (a app só lê). Outbox global só sem contexto de tenant. Prova: `migrations/tests/run.sh` (corre sem superuser).
- **Rust** `backend-rust/`: `AppError`, `money` (Decimal, half-up por linha), dual pool, `/healthz` + `/readyz`. A única entrada para a BD de um tenant é `tenancy::begin_tenant_tx` → `TenantTx`; o outbox usa `append` / `append_global`. Logs mascaram valores sensíveis e falham fechado. Prova: `DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api`.
- **Go** `workers-go/`: publicador outbox → Asynq (TaskID = id do evento), provado de ponta a ponta. Toolchain fixado em 1.27.4. Prova: `go test ./...`.
- **Web** `frontend-web/`: Next 16 + React 19, CSP com nonce, tokens, Modal / Confirm / Drawer / Popover / Toast. Prova: `npm run verify && npm run test:e2e` (axe a 375/1440 px, claro e escuro). Screenshots em `proofs/` (fora do git).
- **Auditorias:** ASVS sem nenhum achado crítico ou alto; os médios estão corrigidos. `cargo audit`, `govulncheck` e `npm audit` dão 0 vulnerabilidades.
- **UX:** aprovado depois das correções. Nu validator 0 erros. Orçamento de JS redefinido como "runtime + 30 KB" (o runtime mede ~135 KB).

## Próximo passo — Fase 2 (épico `02-identidade-tenancy`, a confirmar pelo `architect-master`)
- Extractor de tenant pelo `Host`: o `TenantId::new` é `pub(crate)` e está à espera dele. Inclui a policy do portal nacional (`publish_to_national_portal`).
- Épico identity: abrir `customers` (hoje sem policies nem grants), Argon2id/passkeys, RBAC, `super_admin` + 2FA.
- Cliente TS gerado a partir do `openapi.json`.

## Decisões do owner (pendentes; até lá vale o default)
1. Histórico de preços: `ON DELETE RESTRICT`, por isso variante/loja/tenant com histórico não se apaga, só se desativa. Prazo de retenção por definir.
2. IVA ES/Açores/Madeira e equivalentes legais ES (hoje só PT continente 23%). Decidir antes do 1.º tenant espanhol.
3. Marca: ≤ 2 fontes + paleta final (hoje `#0F4C81`/`#111827`, fontes do sistema; muda-se só nos tokens).

## Dívida técnica conhecida
- API sem graceful shutdown no SIGTERM; o worker Go já o tem.
- `dev-check.sh`: falta testar o caso de erro.
- HSTS com `includeSubDomains`/`preload` só nos nossos domínios (épico domínios). `eupago_split_key` em claro até confirmar se é segredo.
- WebKit: aviso intermitente de CSP em `<link nonce>` (bfcache?). `--toast-reserve: 20rem` é alto em mobile; ponderar 1 toast visível a 375 px.
- `split_vat` PROVISÓRIO até ao teste de paridade com o Moloni (1.º cartão de payments).

## Pendentes
- **Push:** o classificador do auto mode bloqueia o meu `git push`. O owner corre `! git push origin main` (remote pessoal `Rhandyx`; antes, `git remote -v`).
- Worktrees partem do último commit enviado: sem push, os executores correm no checkout principal, um por pasta e sem commits.
- `seed-and-verify.md` (workflow AGY) por definir. Cloudflare Tunnel como origem dos domínios SaaS (por confirmar).
