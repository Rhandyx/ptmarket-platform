# 10 — Frontend: montra, fundações (canal, tema, cabeçalho, rodapé legal e componentes) (épico: 04-montra-publica-aprovacao)

**Agente:** frontend-ui · **Modelo:** sonnet · **Depende de:** 05 (`openapi.json`), 07 (`platform-host.ts`) · **Paralelo com:** 06, 08, 09, 13 · **Prova:** ux-reviewer em browser real, obrigatória

## Objetivo
Fica pronto o que todas as páginas da montra partilham: o canal pelo `Host`, os tokens dos 3 templates, cabeçalho com pesquisa, rodapé legal e os componentes de produto, preço (Omnibus), selos e loja. Sem páginas de catálogo (cartões 11 e 12).

## Pode alterar
- `frontend-web/src/app/(montra)/layout.tsx` (criar); `src/components/storefront/**` (criar); `src/lib/storefront/**` e `src/lib/format/**` (criar); `src/styles/{tokens.css,templates.css}` (tokens novos; `templates.css` criar); `src/app/design-system/montra/page.tsx` (criar: mostruário com dados fixos); `src/lib/api/schema.d.ts` (só por `npm run gen:api`); testes vitest; `e2e/montra-componentes.spec.ts`

## Não tocar
- `backend-rust/`, `openapi.json`; `src/proxy.ts`; `src/app/{layout.tsx,page.tsx,painel/,registar-loja/}` (se `registar-loja` já tiver formatadores ou `SponsorBadges`, importar sem alterar; se não servirem, criar aqui e reportar a duplicação); `src/components/ui/`. Sem dependências novas. Nunca ler `.env`.

## Contexto exato (spec 11 §3–§5; spec 14 §1; `.claude/rules/frontend.md`)
```
Canal: GET /api/v1/tenant → {"slug","name","tenant_type","country_code","currency","template_layout": bairro|editorial|catalogo,"theme_config":{"primary_color","logo_url",…},"legal_config":{"entity_name","nif","ral_entity","livro_reclamacoes_url"}}. Helper getChannel() (React cache, uma chamada por pedido, via createServerApi(headers())); 404 → notFound(). Se isPlatformAdminHost → o layout da montra faz notFound() (o painel vive em /painel).
Tema: data-template no contentor; os 3 templates são só tokens diferentes em templates.css (mesmos componentes). primary_color só é aceite se casar com ^#[0-9a-fA-F]{6}$ e entra por <style nonce> como --brand-accent, usado SÓ em elementos decorativos (filetes, formas): texto e botões usam os tokens do sistema, para o contraste AA não depender da cor da entidade. logo_url só se começar por "/media/".
Cabeçalho: ligação "Saltar para o conteúdo"; nome/logótipo do canal; <form role="search" method="get" action="/pesquisa"> com label; navegação de categorias (Drawer do design system em 375 px). Sem banners nem pop-ups à entrada.
Rodapé legal (PT): entity_name e NIF do canal; "Livro de Reclamações" (livro_reclamacoes_url; DL 74/2017); entidade RAL (Lei 144/2015); "Preços com IVA incluído"; ligação da declaração de acessibilidade, se existir; Termos e Privacidade como ligações inativas até haver textos (pendente do owner). Sem cookies além dos estritamente necessários → sem aviso de cookies.
Dinheiro: só formatar inteiros. formatCents(cents) com Intl.NumberFormat('pt-PT', EUR) a partir de inteiros (dividir com resto, nunca float em contas); formatBps(2300) → "23%". Nenhum cálculo de desconto nem percentagem no frontend.
<Price>: preço atual; com variants_count > 1 → "desde 12,90 €". OMNIBUS (DL 70/2007 art. 5.º; ES art. 20 Ley 7/1996): só quando previous_lowest_cents ≠ null mostra <del> com esse valor e o texto VISÍVEL "Preço mais baixo dos últimos 30 dias: X €". Sem esse campo, nenhum preço riscado, nenhuma etiqueta "promoção". Texto para leitor de ecrã completo ("Preço atual … Preço mais baixo dos últimos 30 dias …"). Nota de IVA: "IVA incluído" ou, se vat_exempt_art53, "IVA: regime de isenção (art. 53.º do CIVA)".
<SponsorBadges>: logótipo + nome + tipo (Câmara Municipal / Junta de Freguesia / Associação), pela ordem da API; alt = nome; sem logo_key → só texto. <ProductCard> (um <article>, uma só ligação principal), <StoreChip>, <ProductImage> (width/height explícitos, loading lazy abaixo da dobra; sem imagem → marcador tipográfico com o nome, nunca imagem partida), <LoadMore> (ligação ?cursor=), <EmptyState>, disponibilidade só "Disponível" / "Esgotado" (sem contagens nem urgência: padrões enganosos são proibidos pelo DSA art. 25.º).
Layout "transcendente": Amazon/AliExpress são anti-referência. Editorial: fotografia grande, muito espaço, hierarquia tipográfica forte (≤ 2 famílias), grelha de 2 colunas a 375 px e no máximo 4 a 1440 px, sem carrosséis automáticos, sem contadores, sem etiquetas a gritar.
UI: só tokens; rem/clamp/unidades de container; alvos ≥ 24×24 px; foco visível; claro e escuro; prefers-reduced-motion; Server Components por defeito; JS próprio ≤ 30 KB gzip por rota.
```

## Feito quando
- [ ] Vitest: `formatCents`/`formatBps` sem floats (1, 99, 100, 123456789); `<Price>` nos 4 casos (simples, "desde", Omnibus, Art. 53.º); cor inválida ou `logo_url` externo são ignorados; selos pela ordem recebida
- [ ] `/design-system/montra` mostra todos os componentes nos 3 templates; contraste AA em todos (teste `tokens-contrast` alargado aos tokens novos)
- [ ] `e2e/montra-componentes.spec.ts`: axe sem violações AA em claro e escuro; reflow a 320 px sem scroll horizontal
- [ ] Prova `ux-reviewer`: Chromium + WebKit, 375 e 1440 px, claro e escuro, 3 templates, Nu validator sem erros, uma captura por template

## Prova (um comando)
`cd frontend-web && npm run verify` → esperado: tudo verde

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `/design-system`, `/registar-loja` e `/painel/**` sem alterações visuais (o `ux-reviewer` confirma); `tests/tokens-contrast.test.ts` e `tests/security-headers.test.ts`
