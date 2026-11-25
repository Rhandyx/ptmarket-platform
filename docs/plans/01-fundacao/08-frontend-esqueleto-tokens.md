# 08 — Esqueleto Next.js: tokens, lint `no-alert`, cabeçalhos de segurança (épico: 01-fundacao)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** — · **Paralelo com:** 01, 02, 04, 07

## Objetivo
`frontend-web/` constrói, tem o design system por tokens (claro/escuro, 3 templates) e recusa em lint qualquer pop-up nativo, px de layout ou cor fora dos tokens.

## Pode alterar
- `frontend-web/**` (criar): `package.json`, lockfile, `tsconfig.json`, config ESLint e Stylelint, middleware/proxy, `src/app/{layout,page}.tsx`, `src/styles/tokens.css`, testes

## Não tocar
- `frontend-web/src/components/ui/` — cartão 09; `backend-rust/`, `migrations/`, `workers-go/`, `infra/` — outros cartões
- Tipos de resposta da API escritos à mão — proibido (virão do `openapi.json`); qualquer `.env` real

## Contexto exato (colado da spec; não ler a spec)
```
Stack: Next.js App Router (versão estável atual, fixada; lockfile no git; API do Next: consultar Context7) + TypeScript strict. CSS Modules + custom properties; sem biblioteca de componentes, sem CSS-in-JS, sem Tailwind. npm.
Tokens (src/styles/tokens.css): cor, espaço, raio, sombra, movimento, tipografia — --color-*, --space-*, --radius-*, --shadow-*, --motion-* (150–250 ms), --font-*; tamanhos em rem/clamp(). Escuro: [data-theme="dark"] + prefers-color-scheme. Templates [data-template="bairro|editorial|catalogo"] e cores da Câmara = só tokens diferentes, mesmos componentes.
Semente: primária #0F4C81, secundária #111827; fonte = pilha do sistema (famílias de marca por decidir; quando houver: self-hosted, ≤ 2, subset, font-display: swap).
Estilo: limpo, editorial, hierarquia clara, muito espaço, tipografia forte. Anti-referência: Amazon/AliExpress.
Proibido: alert()/confirm()/prompt() — ESLint "no-alert": "error" + no-restricted-properties para window.alert|confirm|prompt; react/no-danger = error; jsx-a11y recomendado. Stylelint: px só em border/outline e media queries; cores literais só em tokens.css.
WCAG 2.2 AA: <html lang="pt-PT">; landmarks header/nav/main/footer; skip link; :focus-visible visível (≥ 3:1) e nunca tapado; contraste de texto ≥ 4,5:1 nos dois temas; alvos ≥ 24×24 CSS px (ideal ~44); prefers-reduced-motion: reduce → sem animação. HTML semântico: button a sério, nunca div clicável.
Cabeçalhos (spec 12 §3): CSP com nonce por pedido (default-src 'self'; script-src 'self' 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'self'; frame-ancestors 'none') · Strict-Transport-Security: max-age=31536000 (SEM includeSubDomains/preload: nos subdomínios das Câmaras o preload abrangeria o domínio delas) · X-Content-Type-Options: nosniff · Referrer-Policy: strict-origin-when-cross-origin · Permissions-Policy mínima · Cross-Origin-Opener-Policy: same-origin
Server Components por defeito; página inicial sem JS de cliente próprio; nenhum pop-up nem banner a tapar conteúdo ao entrar.
Scripts npm obrigatórios (os hooks chamam-nos): typecheck, lint (ESLint + Stylelint), test (Vitest), build, verify = typecheck && lint && test && build.
```

## Feito quando
- [ ] `npm run verify` verde; `npm audit --omit=dev` sem vulnerabilidades altas/críticas
- [ ] Teste novo `lint-guards`: ESLint dá erro em `alert('x')`, `window.confirm('x')`, `prompt()` e `dangerouslySetInnerHTML`; Stylelint dá erro em `margin: 12px` e em `color: #fff` fora de `tokens.css` (casos de erro)
- [ ] Teste novo `security-headers`: a resposta de `/` tem todos os cabeçalhos acima, nonce diferente em cada pedido, e HSTS sem `preload`
- [ ] Teste novo `tokens-contrast`: pares texto/fundo dos dois temas e dos 3 templates ≥ 4,5:1

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: typecheck, lint, testes e build sem erros, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- —
