# 06. Estrutura do Monorepo e Orquestração Multi-Modelo no Claude Code

**Objetivo:** Estruturar o repositório e o sistema de subagentes para trabalhar com velocidade máxima e custo controlado no **Claude Code**, usando uma hierarquia rigorosa de modelos:
- **Cérebro Mestre (Arquitetura, Planeamento e Decisões Críticas):** Fable 5.2 (`claude-fable-5-2`)
- **Programação Pesada & Core Engineering:** `opus` (Claude Opus)
- **Leitura, Revisão, Auditoria e Documentação:** `sonnet` (Claude Sonnet)
- **Tarefas Triviais, Boilerplate e Scripts Simples:** `haiku` (Claude Haiku)

> As regras mestras estão em `CLAUDE.md` (raiz) e as definições dos 8 subagentes em `.claude/agents/*.md`. Este documento guarda o resto do plano original: estrutura do monorepo, matriz de roteamento e fluxo diário.

---

## 1. Estrutura Completa do Monorepo (`ptmarket-platform`)

```text
ptmarket-platform/
├── CLAUDE.md                             # Regras absolutas lidas em todas as sessões
├── .claudeignore                         # Ignora .agent/ e docs/business/
├── .claude/
│   ├── settings.json                     # Permissões, hooks automáticos (cargo check/fmt) — por criar
│   └── agents/
│       ├── architect-master.md           # [fable]    Cérebro Mestre, especificações e decisões
│       ├── db-architect.md               # [opus]     PostgreSQL 17, RLS e migrations SQL
│       ├── rust-core.md                  # [opus]     Backend Rust (Axum, SQLx, Ledger, Admin)
│       ├── go-integrations.md            # [opus]     Workers Go (Eupago, Moloni, CTT, IA, Sync)
│       ├── frontend-ui.md                # [opus]     Next.js White-Label, WCAG 2.1 AA, Data Studio
│       ├── codebase-reader.md            # [sonnet]   Leitura profunda, investigação e docs
│       ├── security-auditor.md           # [sonnet]   Auditoria Read-Only (RLS, Auth, Webhooks)
│       └── quick-helper.md               # [haiku]    Boilerplate, renomeações, traduções, CSS simples
├── .agent/                               # Configuração AGY (Antigravity) — ver 09
├── docs/
│   ├── business/                         # 01 — estratégia de negócio (ignorado pelo Claude Code)
│   └── specs/                            # 02 a 10 — especificações técnicas
├── migrations/                           # Migrações SQL sequenciais (sqlx migrate)
├── backend-rust/                         # Core API, Ledger Financeiro, Storage, Data Studio
├── workers-go/                           # Workers Redis/Asynq, Conectores externos e Migração
├── frontend-web/                         # Next.js (Lojas Municipais, lojaportugal.pt, Admin)
├── landing-pages/                        # HTML/Tailwind estático (segjarsolucoes, ptsolucoes, ptmarket)
├── seeds/                                # Taxonomia PT/ES e assets/script da Demo Municipal
└── infra/                                # Caddyfile, docker-compose (1 VPS & 2 VPS), scripts backup
```

---

## 2. Matriz de Roteamento de Modelos (Como Poupar Tokens sem Perder Qualidade)

| Papel / Tipo de Tarefa | Modelo Atribuído | Exemplos Concretos de Utilização |
| :--- | :--- | :--- |
| **Cérebro Mestre / Orquestrador** | **Fable 5.2** | Desenhar novas funcionalidades, quebrar épicos em tarefas atómicas, resolver conflitos arquiteturais entre Rust/Go/DB, rever contratos de API e aprovar planos antes de escrever código. |
| **Programação Core & Complexa** | **`opus`** | Escrever código Rust (`Axum`, `SQLx`, *split* financeiro, concorrência de stock, RLS), workers idempotentes em Go, Data Studio com transações *dry-run*, arquitetura Next.js SSR. |
| **Leitura, Pesquisa & Auditoria** | **`sonnet`** | Ler ficheiros extensos da codebase para explicar fluxos, procurar bugs sem alterar ficheiros, fazer auditorias de segurança RLS/Webhooks/WCAG, atualizar documentação `.md`. |
| **Tarefas Triviais & Rotineiras** | **`haiku`** | Gerar ficheiros `.env.example`, criar tipos simples, ajustar margens/cores Tailwind, renomear variáveis, formatar JSON/SQL, escrever textos *placeholder* e mensagens de erro PT/ES. |

---

## 3. Como Trabalhar no Dia a Dia (Fluxo Prático em 4 Passos)

1. **Planeamento (Fable 5.2):** Pedes ao `architect-master`: *"Lê `docs/specs/02_arquitetura_tecnica_rust_go_postgresql_e_tls.md` e `docs/specs/03_pagamentos_split_faturacao_at_e_logistica.md` e cria o plano de implementação do endpoint de Checkout Multi-Loja com Split."*
2. **Investigação (`sonnet`):** Se o projeto já cresceu, o `codebase-reader` recolhe os ficheiros relevantes e entrega um resumo limpo.
3. **Execução (`opus` + `haiku`):** Ativas `db-architect` -> `rust-core` -> `go-integrations` -> `frontend-ui` em sequência (ou paralelo em pastas separadas). Usas `quick-helper` (`haiku`) para textos, traduções e ajustes rápidos de UI.
4. **Revisão Final (`sonnet`):** Antes de fazer `git commit`, corres o `security-auditor` sobre o diff.
