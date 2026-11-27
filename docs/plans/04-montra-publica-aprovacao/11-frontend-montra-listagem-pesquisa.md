# 11 — Frontend: montra, página inicial, categorias, listagem e pesquisa (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 10 (e 13 para a prova em browser) · **Paralelo com:** 12, 09 (pastas diferentes) · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
Quem chega a `lojaportugal.pt` ou ao domínio de uma entidade vê a página inicial do canal, navega por categorias, percorre a lista de produtos e pesquisa. Tudo funciona sem JavaScript.

## Pode alterar
- `frontend-web/src/app/(montra)/page.tsx` (criar; substitui `src/app/page.tsx`, que se apaga, com o seu `page.module.css`); `src/app/(montra)/{categoria/[slug],pesquisa,lojas}/**` (criar); testes vitest; `e2e/montra-listagem.spec.ts` (criar)

## Não tocar
- `backend-rust/`, `openapi.json`, `src/lib/api/**` (se faltar um campo, PARAR e reportar); `src/app/(montra)/layout.tsx`, `src/components/storefront/**`, `src/lib/{storefront,format}/**` e `src/styles/**` (do cartão 10: usar; se faltar um componente, PARAR e reportar em vez de duplicar); `src/app/painel/`; `src/proxy.ts`. Nunca ler `.env`.

## Contexto exato (cartão 05; spec 11 §3–§5; spec 14 §1.1)
```
API (cliente gerado; Server Components com createServerApi(headers())): GET /api/v1/catalog/categories → [{"id","parent_id","slug","name","has_products"}] · GET /api/v1/catalog/products?category=<slug>&q=&cursor=&limit= → {"items":[ProductCard],"next_cursor"} (limit por defeito 24; com q não se combinam outros filtros) · GET /api/v1/catalog/stores?cursor=&limit= → {"items":[{"slug","name","shipping_scope","is_vacation_mode","badges":[…]}],"next_cursor"}
ProductCard: {"id","title","image":{"thumb","card"}|null,"store":{"slug","name","badges"},"price_from_cents","variants_count","in_stock","previous_lowest_cents","vat_rate_bps","vat_exempt_art53"}
O canal decide o conteúdo (nacional = catálogo inteiro; domínio de entidade = só lojas patrocinadas): o frontend não filtra nada por canal, só mostra o que a API devolve.
Páginas:
  /  — abertura editorial com o nome do canal (um <h1>), categorias com produtos (has_products), "Novidades" (primeira página de produtos) e uma faixa de lojas com selos. Sem carrossel automático, sem pop-up.
  /categoria/[slug] — <h1> com o nome; migalhas (nav aria-label="Migalhas"); subcategorias com produtos como ligações; grelha de <ProductCard>. Slug desconhecido (404 da API) → notFound().
  /pesquisa?q= — formulário GET (o do cabeçalho leva aqui); <h1> "Resultados para «q»" (q vai como texto, nunca como HTML); q vazio → só o formulário; 0 resultados → <EmptyState> com sugestões de categorias. robots noindex.
  /lojas — lista paginada de lojas com <StoreChip> e selos.
Paginação por cursor: <LoadMore> é uma ligação para a mesma página com ?cursor=<next_cursor> (funciona sem JS); com JS pode acrescentar à lista sem recarregar, anunciando "Mais N produtos carregados" em role="status" e mantendo o foco no primeiro item novo. Cursor inválido (422) → voltar à primeira página.
Ordenação v1: "mais recentes primeiro", dita em texto junto à lista (transparência dos critérios: DSA art. 27.º; Reg. (UE) 2019/1150 art. 5.º); sem ordenação por preço nem destaques pagos. Preços e promoções só pelo <Price> do cartão 10 (Omnibus): nenhum preço riscado, etiqueta de desconto ou percentagem feitos aqui.
SEO e desempenho: <title>, descrição e <link rel="canonical"> (sem ?cursor) por página; sem JSON-LD aqui (cartão 12). Server Components; imagens com dimensões (CLS ≤ 0,05), só a primeira fila com loading="eager"; esqueleto com Suspense do tamanho final; JS próprio ≤ 30 KB gzip por rota.
UI: nunca alert()/confirm()/prompt(); HTML semântico (listas em <ul>, um <h1> por página); alvos ≥ 24×24 px; foco visível; reflow a 320 px; claro e escuro; layout editorial (Amazon/AliExpress são anti-referência): no máximo 4 colunas a 1440 px.
```

## Feito quando
- [ ] Vitest (respostas simuladas): categorias sem produtos não aparecem; "Carregar mais" só existe com `next_cursor`; `q` com `<script>` aparece como texto; 404 e 422 da API tratados; lista vazia mostra `<EmptyState>`
- [ ] Com JavaScript desligado: navegar da página inicial a uma categoria, paginar e pesquisar; `e2e/montra-listagem.spec.ts` com axe sem violações AA
- [ ] No Host do painel estas rotas dão 404; num canal white-label de dev só aparecem as lojas patrocinadas (dados do cartão 13)
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, Nu validator sem erros, Lighthouse como indicador (LCP, CLS), uma captura por página

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde (inclui o limite de JS por rota em `check-api.mjs --chunks`)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `/design-system`, `/design-system/montra`, `/registar-loja` e `/painel/entrar` continuam a abrir (a home mudou de pasta); `npm run test:e2e` completo
