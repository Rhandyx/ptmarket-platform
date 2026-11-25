---
trigger: glob
globs: frontend-web/**
---
# Regras Frontend Next.js White-Label & Acessibilidade

1. Resolve o tenant dinamicamente pelo header `Host` e aplica as variáveis CSS (`--color-primary`, etc.) sem recriar componentes por cliente.
2. Mantém os 3 layouts selecionáveis (`bairro`, `editorial`, `catalogo`) partilhando exatamente os mesmos hooks de carrinho, checkout e autenticação.
3. Consome exclusivamente tipos gerados do `openapi.json` do backend Rust.
4. Cumpre rigorosamente **WCAG 2.2 AA** (inclui a 2.1) (contraste >= 4.5:1, navegação por teclado, `aria-labels`, tags semânticas) obrigatório por lei para Câmaras Municipais (DL 83/2018).
5. Inclui `<link rel="canonical">` e dados estruturados JSON-LD (`Schema.org Product`) nas páginas de produto.
6. **Nunca** `alert()`, `confirm()` ou `prompt()`: usar os componentes do design system (Modal `<dialog>`, Toast, Popover, Drawer), bonitos e acessíveis. Nada de pop-ups a tapar o conteúdo ao entrar.
7. Só tokens de design e tamanhos adaptativos (`rem`/`clamp()`), nunca px fixos. Orçamentos de desempenho e prova em browser real: spec 11 §3–§6.
