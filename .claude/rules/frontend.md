---
paths:
  - "frontend-web/**"
  - "landing-pages/**"
---
# Frontend — specs: 04, 07, 11 §3–§6, 12 §3 (Browser)

- **Proibido** `alert()`, `confirm()`, `prompt()` (ESLint `no-alert` = erro). Usar os componentes do design system: Modal (`<dialog>`), Toast, Popover (Popover API), Drawer — animados e acessíveis.
- Nada de pop-ups a tapar o conteúdo ao entrar; aviso de cookies não bloqueia.
- Anti-referência de layout: Amazon/AliExpress. Limpo, editorial, hierarquia clara, espaço, tipografia forte.
- Só **tokens** (CSS custom properties) para cor/espaço/raio/sombra/movimento/tipografia; tamanhos em `rem`/`clamp()`; nunca px fixos de layout.
- WCAG 2.2 AA; HTML semântico e válido (Nu validator 0 erros); axe 0 violações; `prefers-reduced-motion`.
- Server Components por defeito; `"use client"` só em folhas interativas; ≤ ~100 KB JS gzip por rota.
- Catálogo, carrinho e checkout funcionam sem JS (forms + Server Actions).
- Tenant pelo header `Host`; templates `bairro`/`editorial`/`catalogo` = tokens diferentes, mesmos componentes e hooks.
- API Rust só via cliente gerado do `openapi.json`; nunca tipos escritos à mão para respostas da API.
- Imagens AVIF/WebP com `srcset` e dimensões; fontes self-hosted (≤ 2 famílias).
- CSP com nonces; nunca `dangerouslySetInnerHTML` com conteúdo de utilizador.
- Turnstile só nos formulários listados na spec 12 §2.
- Antes de terminar: o hook já corre `typecheck` + `lint`. UI só entra com prova do `ux-reviewer` em browser real (375 px e 1440 px).
