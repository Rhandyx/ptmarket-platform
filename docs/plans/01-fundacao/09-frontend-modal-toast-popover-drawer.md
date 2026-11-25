# 09 — Modal, Toast, Popover e Drawer acessíveis (épico: 01-fundacao)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 08 · **Paralelo com:** 03, 05

## Objetivo
O design system tem os quatro componentes que substituem para sempre `alert`/`confirm`/`prompt`, provados em browser real com axe a zero.

## Pode alterar
- `frontend-web/src/components/ui/**`, `frontend-web/src/app/design-system/page.tsx`, `frontend-web/e2e/**`, `playwright.config.ts` (criar); `package.json` (só Playwright, `@axe-core/playwright` e script `test:e2e`); `tokens.css` (só acrescentar tokens)

## Não tocar
- Config ESLint/Stylelint, middleware/proxy de cabeçalhos, nomes de tokens existentes — aprovados no cartão 08
- `backend-rust/`, `migrations/`, `workers-go/`, `infra/` — outros cartões

## Contexto exato (colado da spec; não ler a spec)
```
"Pop-ups bonitos, nunca nativos": Modal (<dialog> estilizado), Toast, Popover (Popover API), Drawer — animados, acessíveis (Esc, foco preso, anunciados). Nada abre sozinho ao carregar a página. Aviso de cookies não bloqueia.
Todos: folhas "use client", só tokens, rem/clamp, sem dependência nova de UI, CSP com nonce continua a passar (sem estilos/scripts inline).
Modal: <dialog> + showModal(); aria-labelledby no título; fecha com Esc e botão "Fechar" (form method="dialog"); foco preso (nativo) e devolvido ao disparador; ::backdrop por token; clique no backdrop só fecha se `dismissible`.
ConfirmDialog (substitui confirm()): Modal com "Cancelar" + ação; em ação destrutiva o foco inicial fica em "Cancelar".
Drawer: o mesmo <dialog> modal, ancorado a inline-end (em ecrã estreito, ao fundo); largura min(100%, 28rem).
Popover: atributo `popover` + `popovertarget` → Esc e light-dismiss nativos; abre e fecha SEM JavaScript; posição por CSS com fallback.
Toast: <ToastProvider> + useToast(); região viva sempre montada, role="status" aria-live="polite" (erros: role="alert"); nunca rouba o foco; ≥ 5 s, pausa em hover/foco, botão fechar; erros ficam até serem fechados; máx. 3 visíveis.
Movimento: 150–250 ms por tokens; prefers-reduced-motion: reduce → sem transição.
WCAG 2.2 AA a cumprir: 1.4.3 contraste · 2.1.2 sem armadilha de teclado · 2.2.1 tempo ajustável · 2.4.3 ordem de foco · 2.4.7 foco visível · 2.4.11 foco não tapado · 2.5.8 alvo ≥ 24×24 CSS px · 4.1.2 nome/função/valor · 4.1.3 mensagens de estado.
Página de prova `/design-system` (noindex): um disparador por componente; textos em pt-PT.
Prova de UI (spec 11 §6): browser real, 375 px e 1440 px, tema claro e escuro, interação real; axe 0 violações.
```

## Feito quando
- [ ] Playwright (Chromium real) × {375, 1440} × {claro, escuro}: abrir/fechar cada componente por teclado e por ponteiro; foco volta ao disparador; axe 0 violações com cada overlay aberto
- [ ] Casos de erro: Tab não sai do Modal/Drawer; Toast de erro não desaparece sozinho; com `reducedMotion: 'reduce'` não há transição; Popover abre com JavaScript desativado
- [ ] Nenhum diálogo nativo: o teste falha se o browser emitir o evento `dialog`; `/design-system` não abre nada ao carregar
- [ ] Um screenshot por componente e tema em `e2e/__screenshots__/` para o `ux-reviewer`

## Prova (um comando)
`cd frontend-web && npm run test:e2e` → esperado: todos os testes passam, axe 0 violações, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Lint, cabeçalhos e contraste do cartão 08 — `cd frontend-web && npm run verify`
