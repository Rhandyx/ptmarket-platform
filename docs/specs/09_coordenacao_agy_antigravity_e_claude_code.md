# 09. Guia de Orquestração e Configuração para AGY (Antigravity)

**Objetivo:** Adaptar integralmente a arquitetura, regras e fluxo de trabalho do projeto **PT Market / Loja Portugal** para o ambiente **AGY (Antigravity)** — aproveitando os seus pontos fortes únicos (Artifacts estruturados, Rules persistentes, Workflows automatizados e **Browser Subagent** para testes visuais reais do Next.js, templates White-Label, WCAG e Data Studio), podendo operar de forma autónoma ou em paralelo com o Claude Code.

> As regras e workflows do AGY estão em `.agent/rules/` e `.agent/workflows/`. Este documento guarda a estratégia de coordenação entre as duas ferramentas.

---

## 1. Estrutura de Configuração do Workspace para AGY

Além da pasta `.claude/` (usada pelo Claude Code), o repositório mantém a estrutura nativa do AGY em `.agent/`, partilhando a mesma documentação em `docs/specs/`:

```text
ptmarket-platform/
├── docs/specs/                           # Fonte única de verdade partilhada
├── .agent/
│   ├── rules/
│   │   ├── 00-architecture-core.md       # [Always On] Regras Rust/Go/SQL/Multi-Tenant
│   │   ├── 01-financial-legal-pt-es.md   # [Always On] Dinheiro, IVA, Art. 53, Omnibus, WCAG
│   │   └── 02-frontend-whitelabel.md     # [Glob: frontend-web/**] Regras Next.js/Tailwind/UI
│   └── workflows/
│       ├── new-feature.md                # /new-feature — Planeamento -> DB -> Rust -> Go -> UI -> QA
│       ├── qa-visual-demo.md             # /qa-visual-demo — Teste automático no Browser Subagent
│       ├── security-audit.md             # /security-audit — Verificação RLS, 2FA, Webhooks, Dinheiro
│       └── seed-and-verify.md            # /seed-and-verify — Reset BD, Migrations, Seed Demo (por definir)
└── ...
```

---

## 2. Como Coordenar AGY + Claude Code (Estratégia Híbrida sem Conflitos)

Podes usar apenas o **AGY**, apenas o **Claude Code**, ou tirar o melhor dos dois mundos no mesmo repositório Git:

| Fase / Tipo de Trabalho | Ferramenta Recomendada | Porquê? |
| :--- | :--- | :--- |
| **Arquitetura e Planeamento Mestre** | **Cérebro Mestre (Fable 5.2 no Claude Code ou Planning Mode no AGY)** | Garante visão global e Artifacts de especificação aprovados antes de codificar. |
| **Backend Core Pesado (Rust, SQLx, RLS, Go Workers)** | **Claude Code (`opus` nos subagentes `rust-core` e `go-integrations`)** | Execução rápida em terminal com loop contínuo de `cargo check` / `cargo test`. |
| **Frontend Visual, 3 Templates, PWA, WCAG & Testes Browser** | **AGY (Antigravity + Browser Subagent)** | O AGY consegue abrir o site real no browser, clicar nos botões, testar responsividade mobile, inspecionar erros visuais CSS/WCAG e gravar provas em *Walkthrough*. |
| **Tarefas Rápidas / Boilerplate / Landing Pages** | **Claude Code (`haiku`) ou modelo rápido no AGY** | Custo mínimo e resposta instantânea. |

### Regra de Ouro para Evitar Conflitos no Git
- Nunca edites o mesmo ficheiro simultaneamente no Claude Code e no AGY.
- Trabalha por **branches/commits pequenos e limpos** (ex: branch `feat/rust-checkout` no Claude Code -> `git commit` -> branch `feat/ui-checkout` no AGY).
- Mantém os ficheiros `docs/specs/*.md` sempre atualizados quando tomares uma decisão nova, pois tanto o Claude Code como o AGY os leem como fonte única de verdade.
