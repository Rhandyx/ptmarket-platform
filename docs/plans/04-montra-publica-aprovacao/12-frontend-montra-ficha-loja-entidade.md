# 12 — Frontend: montra, ficha de produto, página da loja e página da entidade (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 10 · **Paralelo com:** 11, 09 (pastas diferentes) · **Auditoria:** security-auditor (helper JSON-LD e conteúdo de lojistas) · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
Cada produto, cada loja e cada entidade patrocinadora têm a sua página pública, com selos, preço correto (Omnibus, IVA) e a identificação legal do vendedor.

## Pode alterar
- `frontend-web/src/app/(montra)/{produto/[id],loja/[slug],entidade/[slug]}/**` (criar); `src/components/storefront/JsonLd.tsx` (criar, só este ficheiro nessa pasta); testes vitest; `e2e/montra-ficha.spec.ts` (criar)

## Não tocar
- `backend-rust/`, `openapi.json`, `src/lib/api/**` (se faltar um campo, PARAR e reportar); o resto de `src/components/storefront/**`, `src/app/(montra)/layout.tsx`, `src/lib/**`, `src/styles/**` (do cartão 10: usar); as pastas do cartão 11; `src/app/painel/`; `src/proxy.ts`. Sem dependências novas (sem biblioteca de Markdown). Nunca ler `.env`.

## Contexto exato (cartão 05; spec 11 §5; spec 12 §3; spec 14 §1.1)
```
API: GET /api/v1/catalog/products/{id} → Product = ProductCard + {"description","attributes","is_perishable","images":[{"thumb","card","full"}],"category","breadcrumb":[{"slug","name"}],"variants":[{"id","ean","attributes","price_cents","in_stock","previous_lowest_cents"}],"store": StoreCard} · 404
  GET /api/v1/catalog/stores/{slug} → {"slug","name","shipping_scope","is_vacation_mode","vacation_message","badges","legal_name","nif","email","phone","address","business_hours","supports_click_collect","supports_local_courier","supports_national_shipping","vat_exempt_art53"} · 404
  GET /api/v1/catalog/products?store=<slug>|entity=<slug>&cursor= · GET /api/v1/catalog/stores?entity=<slug>&cursor=
404 da API → notFound() (a API não distingue "não existe" de "não é deste canal": o frontend também não).
/produto/[id]: galeria (primeira imagem eager, com dimensões; sem imagens → marcador do cartão 10); <h1> título; <Price> da variante escolhida; variantes como grupo de rádio (fieldset + legend) num formulário GET (?v=<id>): sem JS a página recarrega com a variante; ?v inválido → primeira variante. Disponibilidade "Disponível"/"Esgotado" em texto. Nota de IVA do <Price>. Descrição como TEXTO simples em parágrafos (quebras de linha → <p>): nunca HTML do lojista. Atributos em <dl>. Bloco "Vendido por" com <StoreChip>, selos e ligação à loja.
  Compra: o carrinho ainda não existe. NÃO pôr botão de compra desligado: mostrar "Compra online disponível em breve" e a ligação "Contactar a loja" (página da loja). Texto num só ficheiro de strings.
/loja/[slug]: <h1> nome; selos; aviso de férias (vacation_message como texto) se is_vacation_mode; modos de entrega (shipping_scope + supports_*) em texto; horário; produtos da loja paginados (<LoadMore>).
  Identificação do vendedor, sempre visível (DSA art. 30.º; DL 7/2004 art. 10.º; DL 24/2014 art. 4.º): designação legal, NIF, morada, email e telefone (mailto:/tel:). Se vat_exempt_art53: "Vendedor em regime de isenção de IVA (art. 53.º do CIVA)".
/entidade/[slug]: <h1> nome e tipo da entidade (tirados do selo com esse slug na primeira loja devolvida), lojas com esse selo e os seus produtos. 0 lojas → notFound().
JSON-LD (spec 11 §5): Product + Offer (price a partir de cêntimos inteiros, formatado "12.90" por divisão inteira e resto; priceCurrency do canal; availability InStock/OutOfStock; gtin se houver ean) e BreadcrumbList. Só pelo helper JsonLd: <script type="application/ld+json" nonce> com JSON.stringify e substituição de "<" por "<". É a ÚNICA exceção a dangerouslySetInnerHTML, só neste ficheiro (se o lint a bloquear, desativar a regra numa linha deste ficheiro e reportar).
SEO: <title>/descrição por página; canonical sem ?v nem ?cursor; hreflang fica para quando houver canal ES.
UI: nunca alert()/confirm()/prompt(); um <h1>; alvos ≥ 24×24 px; foco visível; reflow a 320 px; claro e escuro; fotografia grande e muito espaço (anti-referência: Amazon/AliExpress); JS próprio ≤ 30 KB gzip por rota.
```

## Feito quando
- [ ] Vitest: `JsonLd` com título `</script><script>alert(1)</script>` não fecha o script; preço JSON-LD de 1290 → "12.90" e de 5 → "0.05" sem floats; descrição com `<img onerror>` sai como texto; `?v` inválido cai na primeira variante; Omnibus e Art. 53.º visíveis
- [ ] Página da loja mostra os 5 dados legais; loja em férias mostra o aviso; `/entidade/x` sem lojas → 404; trocar de variante sem JavaScript funciona
- [ ] `e2e/montra-ficha.spec.ts`: axe sem violações AA; CSP sem erros na consola (o JSON-LD usa o nonce); teste de dados estruturados válido (JSON parseável com `@type` Product)
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, Nu validator sem erros, uma captura por página (produto com promoção, loja co-patrocinada com 2 selos)

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `tests/lint-guards.test.ts` e `tests/security-headers.test.ts` verdes (a exceção do JSON-LD não abre mais nada); `/design-system/montra` sem alterações
