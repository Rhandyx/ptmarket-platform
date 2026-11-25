# 06. Estrutura do Monorepo e Orquestração Multi-Modelo no Claude Code

**Revisto em 25/11/2026 (Fase 0, aprovado pelo owner):** economia máxima de tokens. Os agentes leem só o cartão da sua tarefa, Sonnet é o modelo por defeito e o supervisor revê cada diff.

---

## 1. Estrutura do monorepo

```text
ptmarket-platform/
├── CLAUDE.md                 # Regras universais (≤ 500 tokens) + método + índice das specs
├── .claude/
│   ├── settings.json         # Hooks (fmt/check/vet/typecheck/lint) + leituras bloqueadas
│   ├── settings.local.json   # Pessoal (fora do git): permissão de push
│   ├── rules/                # Regras por pasta, carregam só ao tocar nela: rust, go, sql, frontend
│   └── agents/               # 9 agentes (ver §2)
├── .agent/                   # Configuração AGY (Antigravity) — ver 09
├── docs/
│   ├── ESTADO.md             # "COMEÇA AQUI" — passagem de estado entre conversas
│   ├── plans/                # Cartões de tarefa por épico (modelo: _CARTAO.md)
│   ├── business/             # 01 — estratégia (leitura bloqueada ao Claude)
│   └── specs/                # 02–12 — especificações técnicas
├── migrations/ · backend-rust/ · workers-go/ · frontend-web/ · landing-pages/ · seeds/ · infra/
└── proofs/                   # Screenshots de prova de UX (fora do git)
```

## 2. Equipa e modelos

| Agente | Modelo base | Limite de passos | Papel |
|---|---|---|---|
| Sessão principal (supervisor) | Opus | — | Plano, divisão em cartões, revisão de cada diff, integração, memória, `ESTADO.md` |
| `architect-master` | Fable | 30 | Só épicos e decisões de arquitetura; escreve cartões, nunca código |
| `db-architect` · `rust-core` · `go-integrations` · `frontend-ui` | Sonnet (Opus nos cartões críticos) | 60 | Um cartão cada, num branch/worktree próprio |
| `security-auditor` | Sonnet | 30 | Revê o diff contra a checklist ASVS da spec 12 (só leitura) |
| `ux-reviewer` | Sonnet | 30 | Prova em browser real: W3C, axe, WCAG 2.2, 375/1440 px |
| `codebase-reader` | Haiku | 15 | Pesquisas que devolvem `ficheiro:linha` |
| `quick-helper` | Haiku | 15 | Tarefas mecânicas com instruções exatas |

**Cartões críticos = Opus:** dinheiro/ledger/split, RLS, stock, autenticação e sessões, webhooks de pagamento. O supervisor escolhe o modelo em cada chamada; não há agentes duplicados.

## 3. Regras de economia de tokens

1. **O custo vem das instruções, não dos agentes.** Cada tarefa é um cartão de ≤ 40 linhas com o excerto exato da spec já colado. O executor nunca lê specs inteiras.
2. **Agentes curtos.** O custo cresce com o quadrado do número de passos, por isso o `maxTurns` está definido em todos. Um cartão grande divide-se por camada.
3. **Relatórios curtos** (≤ 10–15 linhas): tudo o que um agente devolve entra no contexto do supervisor.
4. **Verificação automática:** os hooks fazem fmt/check/lint a cada edição. Os agentes correm só os testes do módulo; o conjunto completo corre uma vez, na integração.
5. **Paralelo por pasta**, com worktrees; nunca dois agentes no mesmo ficheiro.
6. **Uma conversa por tema.** No fim de cada fase o supervisor atualiza o `docs/ESTADO.md`, as memórias e faz commit; a conversa seguinte começa com "começa aqui".
7. **Não delegar o que são 2–3 chamadas de ferramenta:** o supervisor faz isso diretamente.
8. **Leituras bloqueadas** (`permissions.deny`): `docs/business/`, `node_modules/`, `target/`, `.next/`.

## 4. Fluxo de um épico

1. **Plano:** o `architect-master` lê as secções das specs e escreve os cartões em `docs/plans/<épico>/`. O supervisor revê-os.
2. **Execução:** um agente por cartão, por ordem de dependência; os independentes correm em paralelo, em worktrees.
3. **Revisão:** o `security-auditor` revê o diff do backend e o `ux-reviewer` prova a UI.
4. **Integração:** o supervisor revê cada diff, junta os branches, corre o conjunto completo de testes uma vez e faz commit.
5. **Fecho:** atualizar o `ESTADO.md` e as memórias.

## 5. Lições incorporadas (de projetos anteriores do owner)

- O plano é aprovado em `.md` antes de haver código.
- Cada cartão diz o que **não** se pode tocar e que funcionalidades aprovadas têm de voltar a ser provadas.
- Nenhuma UI entra sem prova em browser real.
- Provar antes de afirmar; suspeitar primeiro das próprias mudanças.
- Os agentes fazem commit do trabalho em curso; nada fica só no scratchpad.
- Staging antes de produção, com backup e rollback; nunca editar no servidor.
