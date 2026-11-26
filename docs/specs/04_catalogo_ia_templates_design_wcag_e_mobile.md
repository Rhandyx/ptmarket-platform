# 04. Catalogação por IA, Templates White-Label, Acessibilidade WCAG e Mobile

> Atualizada a 26/11/2026: canais, patrocínio, comissões e planos seguem a spec 14 (prevalece).

**Objetivo:** Eliminar o cadastro manual de milhares de categorias/atributos, oferecer uma montra personalizada a cada município sobre uma única base de código, cumprir as exigências legais de acessibilidade do setor público e cobrir Web, PWA, Android e iPhone.

---

## 1. O Fim das 1.000 Categorias Manuais (Taxonomia + IA)

### 1.1 Seed Global de Taxonomia (PT e ES)
Na primeira *migration* / *seed* do sistema, importa-se automaticamente a **Shopify Standard Product Taxonomy** ou a **Google Product Taxonomy** oficial (já traduzida em Português e Espanhol, com mais de 5.000 categorias hierarquizadas).
- Para evitar menus sobrecarregados nas Câmaras Municipais, o painel permite marcar como `is_featured = true` as 12 a 15 categorias típicas do comércio tradicional local (Padaria, Talho, Mercearia & Produtos Regionais, Vestuário, Calçado, Livraria, Florista, Ferragens, Artesanato, Ótica).

### 1.2 Pipeline de Enriquecimento Automático no Upload do Produto
O comerciante só precisa de carregar uma foto e escrever o nome básico e preço (ex: *"Sapatilhas corrida azul marinho"*):
1. O backend coloca a tarefa na fila `ai_catalog_enrichment` do Redis.
2. O worker Go chama um modelo LLM ultrarrápido e económico (`gemini-2.5-flash` ou `haiku` — custo inferior a **0,0005€ por produto**, cerca de 1€ por cada 2.000 produtos).
3. A IA devolve JSON estrito que preenche automaticamente:
   - `category_id` exato na árvore de taxonomia.
   - `attributes (JSONB)` normalizados (`{"cor": "Azul Marinho", "tipo": "Running"}`) com autocomplete para evitar 50 variações da mesma cor nos filtros.
   - Tradução imediata para **Espanhol (`es`)** pronta para exportação ibérica.
   - Descrição comercial limpa e meta-tags SEO.

---

## 2. Design Multi-Template White-Label (1 Código, Múltiplas Peles)

### 2.1 Tematização Dinâmica por Domínio (`Host`)
O middleware do Next.js lê o cabeçalho `Host` (ex: `compreemgaia.pt` vs. `lojaportugal.pt`), consulta o `theme_config` do *tenant* (em cache Redis de 5 min) e injeta variáveis CSS nativas na raiz da página (`--color-primary`, `--color-secondary`, `--radius-ui`, `--font-heading`), logótipo, brasão e rodapé institucional.

### 2.2 Os 3 Layouts Estruturais Selecionáveis no Backoffice

| Template | Conceito Visual e UX | Indicado Para |
| :--- | :--- | :--- |
| **1. `bairro` ("Bairro & Proximidade")** | Mapa interativo das lojas aderentes do concelho, atalho *"Levantar em Loja Hoje"*, destaque para comércio diário e banner do Cartão da Cidade. | Câmaras Municipais de pequena/média dimensão e Bairros Comerciais Digitais. |
| **2. `editorial` ("Montra Moderna")** | Hero visual de ecrã largo, coleções temáticas sazonais (*Natal Local*, *Vinhos & Azeites*), fotografia limpa estilo Shopify. | Associações Comerciais urbanas, moda, artesanato, produtos *gourmet*. |
| **3. `catalogo` ("Catálogo Denso / B2B")** | Barra de pesquisa central proeminente, filtros laterais rápidos por atributo/preço/concelho e grelha compacta orientada a conversão. | Portal Nacional **`lojaportugal.pt`**, mercados transfronteiriços PT/ES e nichos B2B. |

### 2.3 Canais, patrocinadores e selos (ver spec 14 §1–§2)
Os templates, o `theme_config` e a PWA mantêm-se integralmente. Acrescenta-se:
- **Domínio próprio = vista filtrada do catálogo universal:** só mostra as lojas com patrocínio ativo de uma entidade cujo `channel_tenant_id` é esse canal. Não há cópia de produtos nem de stock.
- **Novas chaves de `theme_config`:** brasão, banners, rodapé institucional/PRR e PWA própria (nome, ícone, cores).
- **Selos dos patrocinadores** nas fichas de produto e nas páginas de loja, na ordem `municipality` → `parish` → `association` (dentro do mesmo tipo, por nome); também no `lojaportugal.pt`.
- **Entidades sem domínio:** página/filtro `/entidade/<slug>` no portal nacional.
- **Âncora `~~8%~~ 0%` acessível (WCAG 2.2 AA):** o texto riscado tem de ser lido corretamente pelos leitores de ecrã. Usar `<del>8%</del> <ins>0%</ins>` (ou texto alternativo visualmente oculto, por exemplo "antes 8%, agora 0%"); nunca só estilo CSS de rasurado. O contraste do texto riscado cumpre 4.5:1.

---

## 3. Acessibilidade Obrigatória no Setor Público (WCAG 2.1 AA / DL 83/2018)

**Diferencial competitivo decisivo:** Em Portugal, todos os portais financiados ou detidos por Câmaras Municipais são **legalmente obrigados** (Decreto-Lei n.º 83/2018) a cumprir o nível **WCAG 2.1 AA** e a publicar uma Declaração de Acessibilidade (`acessibilidade.gov.pt`). A maioria das agências WordPress falha esta auditoria.

Todos os 3 templates construídos em **Next.js + Tailwind + `shadcn/ui` (Radix Primitives)** nascem conformes desde o dia 1:
1. **Contraste Garantido:** Validador automático no Backoffice da Câmara que avisa se a cor primária escolhida não atinge rácio de contraste mínimo de `4.5:1`.
2. **Navegação Integral por Teclado e Leitores de Ecrã:** Atributos `aria-*`, *focus rings* visíveis, *skip-to-content link* e textos alternativos (`alt`) gerados automaticamente pela IA nas fotos de produto.
3. **Gerador de Declaração de Acessibilidade:** Página `/acessibilidade` gerada automaticamente em cada portal municipal com os dados da entidade.

---

## 4. SEO Técnico Multi-Domínio (Evitar Penalização de Conteúdo Duplicado)

Como o mesmo produto de um lojista pode estar visível em `compreemgaia.pt/p/azeite-douro` e simultaneamente no agregador `lojaportugal.pt/p/azeite-douro`:
- **Canonical URL Inteligente:** O motor injeta `<link rel="canonical">` apontando para o domínio principal definido (ou varia descrições meta entre canal local e canal nacional) para evitar penalizações do Google.
- **Sitemap Dinâmico por Domínio (`/sitemap.xml`):** Cada domínio gera o seu próprio sitemap em tempo real a partir da réplica PostgreSQL.
- **Dados Estruturados (`Schema.org / JSON-LD`):** Cada página de produto inclui `Product`, `Offer`, `priceCurrency: EUR` e `availability` para indexação rica no Google e Google Shopping.

---

## 5. Estratégia Mobile: Web, PWA, Android e iPhone

Para evitar multiplicar por 3 o custo de manutenção mantendo 3 bases de código (Web + Swift + Kotlin):

### Fase 1: PWA (Progressive Web App) — Incluída de Base (0€ Extra)
- Instalável diretamente a partir do browser no Android e iOS com ícone e nome da Câmara.
- Atualizações instantâneas sem depender de aprovação da Apple/Google.
- Acesso à câmara do telemóvel para ler **QR Codes do Cartão da Cidade** e notificações Push Web (Android e iOS Safari 16.4+).

### Fase 2: Apps Nativas iOS & Android via Capacitor — Módulo *Add-on* (+3.000€ + 600€/ano)
- Quando uma Câmara exige presença oficial na **Apple App Store** e **Google Play**, o **Capacitor (Ionic)** empacota exatamente o mesmo frontend Next.js num binário nativo com Push nativo (Firebase/APNs), biometria e câmara ultrarrápida.
- **Regra Apple anti-rejeição:** A app de cada Câmara é publicada sob a **conta Apple Developer institucional da própria Câmara** (evitando bloqueio por apps *white-label* duplicadas na conta da Segjar).
- **App Única "PT Market Lojista":** Uma única app publicada pela Segjar Soluções onde todos os comerciantes do país fazem login para receber alertas sonoros tipo Uber Eats quando cai uma encomenda.