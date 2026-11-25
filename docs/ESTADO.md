# COMEÇA AQUI — estado do projeto

> Nova conversa: o owner escreve **"começa aqui"**. Lê este ficheiro primeiro, depois só o que a próxima tarefa pede.
> Mantido pelo supervisor (sessão principal). As secções mais recentes ficam no topo. Máx. ~40 linhas: o histórico está no git.

## 25/11/2026 — Fase 0 concluída (estrutura, sem código da aplicação)
- Specs em `docs/specs/` (02–12). **11 (escala e qualidade) e 12 (segurança e domínios) prevalecem sobre a 02.**
- 9 agentes em `.claude/agents/` (Sonnet por defeito; Opus nos cartões críticos; Fable só arquitetura; Haiku pesquisa e tarefas triviais).
- Regras por área em `.claude/rules/` (rust, go, sql, frontend), que carregam só ao tocar na pasta.
- Hooks: Rust fmt+check · Go fmt+vet · frontend typecheck+lint. A leitura de `docs/business/` e das pastas geradas está bloqueada.
- Método: épico → `architect-master` escreve cartões (`docs/plans/<épico>/`, modelo `_CARTAO.md`) → executores fazem um cartão cada → `security-auditor` + `ux-reviewer` → o supervisor revê o diff e integra.

## Próximo passo — Fase 1: fundação (épico `01-fundacao`)
1. `architect-master` cria os cartões do épico a partir de 02 §4 + 11 §1–2 + 12 §3:
   - esqueleto do workspace Rust (módulos de domínio, `AppError`, `money`, config, dual pool);
   - migrations base (tenants, stores, categories, products + `product_variants`, `customers`, `outbox_events`) com RLS;
   - esqueleto Go (publicador do outbox + Asynq);
   - esqueleto Next.js (design system com tokens, Modal/Toast/Popover/Drawer, ESLint `no-alert`);
   - `infra/` docker-compose de desenvolvimento.
2. Execução em paralelo por pasta, com worktrees.

## Pendentes
- **Push:** o GitHub está em dia até `b0b0abb`; este último ajuste ao ESTADO ficou só em local. No próximo push, testar se `git push origin main` passa com a regra de `settings.local.json`; se o classificador bloquear, o owner corre `! git push origin main`.
- `seed-and-verify.md` (workflow AGY) por definir.
- Fase 2: Cloudflare Tunnel como origem dos domínios SaaS (por confirmar).
