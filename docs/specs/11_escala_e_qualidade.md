# 11. Escala ("pronto para ser um Amazon") e Padrões de Qualidade

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

**Estado:** aprovado pelo owner em 25/11/2026. **Prevalece sobre a spec 02** nos pontos marcados abaixo.
**Princípio:** decidir já o que é barato agora e caro depois de haver dados; adiar o que só custa quando se escala.

---

## 1. Arquitetura

- **Monólito modular em Rust** (`backend-rust/`), um módulo por domínio, com fronteiras explícitas:
  `identity` (contas, sessões, RBAC) · `catalog` (produtos, variantes, categorias, pesquisa) · `orders` (carrinho, encomendas, sub-encomendas, devoluções) · `payments` (gateways, split, ledger) · `fulfillment` (envios, levantamentos) · `tenancy` (Câmaras, lojas, domínios) · `admin` (Data Studio, auditoria).
- Um módulo **nunca** lê as tabelas de outro diretamente: chama a sua API interna (funções públicas do módulo). É isto que permite extrair um módulo para serviço próprio mais tarde sem reescrever.
- **Workers Go** (`workers-go/`) continuam para integrações externas (faturação AT, envios, IA, migração).
- **Microserviços só quando um domínio precisar de escalar sozinho** (medido, não suposto).

## 2. Modelo de dados — alterações à spec 02 (obrigatórias desde a 1.ª migration)

| # | Alteração | Porquê |
|---|---|---|
| D1 | **`product_variants`** (id, product_id, sku, ean, attributes JSONB, price_cents, compare_at_price_cents, lowest_price_30d_cents, stock_qty, is_active). `products` deixa de ter preço/stock/`variants` JSONB; um produto simples tem 1 variante. `sub_order_items` e `product_price_history` referenciam `variant_id`. | Stock e preço por variante, bloqueáveis atomicamente. |
| D2 | **Stock atómico com reserva:** ao iniciar o pagamento, `UPDATE product_variants SET stock_qty = stock_qty - $n WHERE id = $id AND stock_qty >= $n` (0 linhas = sem stock) **e**, na mesma transação, uma linha em **`stock_reservations`** (variant_id, order_id, qty, expires_at). Pagamento confirmado → a reserva é apagada. Reserva expirada ou pagamento falhado → um worker devolve a `qty` ao stock e apaga a reserva (idempotente). O stock nunca é descontado duas vezes. | Nunca vender o que não existe, mesmo com 1000 checkouts em simultâneo. |
| D3 | **`outbox_events`** (id, aggregate, aggregate_id, event_type, payload JSONB, created_at, published_at NULL). Escrito **na mesma transação** que a alteração de negócio; um publicador lê-o e envia para Redis/Asynq; consumidores idempotentes por `id`. Nada é publicado no Redis diretamente a partir de um handler. | Zero eventos perdidos entre o commit na BD e a fila. |
| D4 | **`customers`** (id, email único, nome, telefone, nif, password_hash Argon2id, passkeys, consentimentos, anonymized_at). `orders.customer_id` (NULL = convidado, com snapshot de nome/email/morada). `loyalty_ledger` usa `customer_id`. | Uma conta para todas as lojas e Câmaras; RGPD (esquecimento) num só sítio. |
| D5 | **`catalog_item_id` UUID NULL** em `products` (+ tabela `catalog_items` por GTIN/EAN, criada mais tarde). | "O mesmo produto em várias lojas" e comparação de preços sem migrar dados. |
| D6 | **PostgreSQL 18** (em vez do 17 da spec 02) e **UUIDv7** em todas as PK: gerados em Rust (`Uuid::now_v7()`), com `DEFAULT uuidv7()` nativo do PG18 como rede de segurança. | Índices ordenados no tempo → muito mais eficientes com milhões de linhas. Começando do zero, não há razão para arrancar numa versão sem `uuidv7()` nativo. |
| D7 | **Preços com IVA incluído** (`price_cents` = PVP, obrigatório B2C em PT). **IVA em bps** (`vat_rate_bps INT`: 2300 = 23%), coerente com as comissões. Arredondamento **aritmético (half-up) por linha**, num único módulo `money`; tem de dar exatamente os mesmos cêntimos que o software de faturação certificado (Moloni) — o primeiro cartão de `payments` inclui um teste de paridade com faturas reais. | Uma só convenção; zero diferenças de cêntimos entre fatura, ledger e montra. |
| D8 | `currency CHAR(3) NOT NULL DEFAULT 'EUR'` em `orders`, `sub_orders`, `refunds`. | Custo zero agora; evita migração se houver outra moeda. |
| D9 | **Pesquisa atrás de `SearchBackend`** (trait, como `StorageBackend`): `PostgresSearch` (FTS + trigram) agora; `Meilisearch`/`OpenSearch` mais tarde, alimentado pelo outbox. | Trocar o motor de pesquisa sem tocar no resto. |
| D10 | Tabelas que crescem sem parar (`orders`, `outbox_events`, `product_price_history`, `admin_audit_logs`) com índice por `created_at`; **particionamento por mês só quando medido** (> ~50 M linhas). | Preparado, não pago antes do tempo. |
| D11 | **Snapshot de comissão/patrocínio em `sub_orders`** (`base_commission_bps`, `applied_commission_bps`, `sponsored_discount_cents`, `billing_plan_code`, `store_monthly_gmv_before_cents`, `store_dicofre`, `origin_channel_id`) + **`active_sponsor_ids UUID[]` com índice GIN**; relatórios sobre `sub_orders` únicas (spec 14 §7). Escalões em `billing_plan_tiers`, nunca hardcoded. | Relatórios sem dupla contagem com co-patrocínio; histórico imutável; escalões editáveis sem deploy. |

Índices compostos começam sempre por `tenant_id` (exceto tabelas globais: `customers`, `catalog_items`).

### Nota para a Fase 1 (verificação em compilação)
`sqlx::query!` precisa da BD ou de metadados offline: fazer commit da pasta `backend-rust/.sqlx/` (`cargo sqlx prepare`) — o hook de Rust ativa `SQLX_OFFLINE=true` quando ela existe, para o `cargo check` funcionar em qualquer worktree sem BD.

## 3. Desempenho (orçamentos — falhar = não entra)

- **API Rust:** p95 < 50 ms em leituras de catálogo; p95 < 150 ms no checkout (sem contar o gateway). Sem N+1: cada endpoint com nº de queries conhecido.
- **Web:** PageSpeed **oficial** (pagespeed.web.dev, mediana de 3) **≥ 99 desktop e ≥ 90 mobile**; LCP ≤ 2,0 s · INP ≤ 200 ms · CLS ≤ 0,05. Lighthouse local headless **não** conta como número final.
- **JS:** ≤ ~100 KB gzip por rota; Server Components por defeito; `"use client"` só em componentes interativos e o mais folha possível.
- **Imagens:** AVIF/WebP, `srcset` responsivo, dimensões explícitas (CLS 0), lazy abaixo da dobra, CDN da Cloudflare.
- **Fontes:** self-hosted, subset, `font-display: swap`, máximo 2 famílias.

## 4. Design e UX ("transcendente", não Amazon/AliExpress)

- **Anti-referências:** Amazon e AliExpress (densidade caótica, banners a gritar). Referências de qualidade: lojas de design editorial, limpas, com hierarquia clara, muito espaço, tipografia forte, fotografia grande.
- **Design system** em `frontend-web` com **tokens** (CSS custom properties: cor, espaço, raio, sombra, movimento, tipografia) — os 3 templates White-Label (`bairro`, `editorial`, `catalogo`) e as cores de cada Câmara são só tokens diferentes.
- **Tamanhos adaptativos:** `rem`, `clamp()`, unidades de container — **nunca px fixos** de layout. Alvos de toque ≥ 24×24 CSS px (WCAG 2.5.8), idealmente ~44.
- **Movimento:** transições curtas (150–250 ms), `prefers-reduced-motion` respeitado.
- **Tema claro/escuro** por tokens.
- **Pop-ups bonitos, nunca nativos.** Proibido `alert()`, `confirm()`, `prompt()` (ESLint `no-alert` = erro). Componentes do design system: **Modal** (`<dialog>` estilizado), **Toast**, **Popover** (Popover API), **Drawer** — animados, acessíveis (Esc, foco preso, anunciados). Nada de pop-ups promocionais a tapar o conteúdo ao entrar (penalização Google mobile); se houver promoção, aparece após ação do utilizador ou como barra discreta. Aviso de cookies não bloqueia a página.

## 5. Normas W3C e acessibilidade

- **WCAG 2.2 AA** (inclui a 2.1 exigida pelo DL 83/2018 / EN 301 549).
- **HTML válido** no validador W3C (Nu) com zero erros; HTML semântico (`header`, `nav`, `main`, `article`, `button` a sério, nunca `div` clicável).
- **axe-core** com zero violações.
- **Progressive enhancement:** catálogo, carrinho e checkout funcionam com formulários e Server Actions mesmo sem JS.
- **SEO:** `<link rel="canonical">`, JSON-LD `Product`/`Offer`/`BreadcrumbList`, sitemap por domínio, `hreflang` PT/ES.

## 6. Prova obrigatória antes de qualquer UI entrar

Feita pelo agente `ux-reviewer` num **browser real**: viewports 375 px e 1440 px, tema claro e escuro, interação real do fluxo alterado (não só renderização), Nu validator, axe, Lighthouse como indicador (PSI oficial em staging). Um screenshot por estado alterado — não dezenas.
