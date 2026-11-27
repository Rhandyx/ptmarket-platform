# 14. Canais, patrocínio múltiplo, comissões e planos de faturação

> Decisões do owner de 26/11/2026 (auditoria do modelo de negócio antes do épico 03). **Fonte canónica destes temas.** Prevalece sobre: doc de negócio 01 §1 e §4.1; specs 02 (tenants, stores, `sub_orders`), 03 §1 (comissão), 04 (white-label: só o que aqui se acrescenta), 05 (onboarding), 07 (backoffices), 12 (domínios e login). As outras specs apontam para aqui em vez de repetir as regras.

## 1. Modelo: canal ≠ patrocinador
| Conceito | Tabela | O que é |
|---|---|---|
| **Canal** (storefront web) | `tenants` | Um domínio real: `lojaportugal.pt` (canal nacional, `tenant_type = 'national_portal'`, um por país) ou o domínio white-label de uma entidade (`tenant_type = 'municipal'`, também usado por Juntas e Associações com domínio; `niche` no futuro). Tem `Host`, `theme_config`, `template_layout` (`bairro` / `editorial` / `catalogo`) e PWA. **`custom_domain` continua `NOT NULL UNIQUE`**: um tenant é sempre um canal web real. O `tenancy/resolver.rs` não muda. |
| **Entidade patrocinadora** | `sponsor_entities` | Câmara Municipal (`municipality`), Junta de Freguesia (`parish`) ou Associação (`association`), cada uma com UUID próprio, área em DICOFRE, logótipo/brasão e `channel_tenant_id` (NULL = sem domínio próprio). |
| **Loja** | `stores` | Vive no **catálogo universal**: `stores.tenant_id` aponta sempre para o canal nacional do país da loja. `UNIQUE (tenant_id, slug)` garante URLs sem colisão no portal. |
| **Patrocínio** | `store_sponsorships` | Relação N:N loja ↔ entidade, com estado e vigência próprios. |

### 1.1 Visibilidade (RLS e views; substitui o opt-in `publish_to_national_portal`)
- **Canal nacional:** mostra **todas** as lojas ativas (`is_active`) do mesmo país e os seus produtos ativos. **Não há opt-out.** Restrições de entrega não escondem a loja: controlam-se por `stores.shipping_scope` (`national` / `local_only` / `pickup_only`); a loja aparece sempre, e o checkout só oferece o que o âmbito permite.
- **Canal white-label (domínio próprio):** é uma **vista filtrada** do mesmo catálogo. Só mostra as lojas com pelo menos um patrocínio `active` e vigente de uma entidade cujo `channel_tenant_id` é esse canal. Não há cópia de produtos nem de stock. Tema e template continuam exatamente como na spec 04.
- **Entidade sem domínio:** as suas lojas aparecem no `lojaportugal.pt` com os selos, e numa página/filtro dedicado dentro do portal nacional (`/entidade/<slug>`).
- `publish_to_national_portal` fica deprecado: deixa de ser lido, sai numa migration posterior. A view `portal_stores` (colunas DSA da 0021) mantém-se como forma única de ler lojas fora do backoffice; só muda a condição.
- **RLS (`ptmarket_app`, além da `tenant_isolation` de escrita):**
  - **Contexto:** `app.current_tenant_id` é o canal do pedido.
  - **Leitura pública de `stores`/`products`/`product_variants`:**
    - canal nacional → `store.tenant_id` = canal nacional do mesmo país e `is_active`;
    - canal white-label → `EXISTS` patrocínio ativo e vigente de uma entidade com `channel_tenant_id` = canal.

    Continua a passar só pela view `portal_stores` e pelas policies `portal_read` reescritas, com o mesmo padrão `security_barrier` da 0021.
  - **Escrita (backoffice em `admin.ptmarket.pt`):** contexto = canal nacional da loja + verificação de papel na loja (`RequireStoreRole`).
  - **Isolamento entre lojas:** é feito pelos papéis de loja, porque todas as lojas de um país partilham o mesmo `tenant_id`. Os testes anti-IDOR entre lojas passam a ser obrigatórios em cada handler de loja.
- **Selos:** ordem fixa `municipality` → `parish` → `association`; dentro do mesmo tipo, por nome.

## 2. Patrocínios (`store_sponsorships`)
- **Estados:** `pending` (pedido do lojista ou convite da entidade), `active`, `rejected`, `expired`, `revoked`.
- **Vigência:** `valid_from`, `valid_to` (NULL = sem fim). Uma loja pode ter 0, 1, 2 ou mais patrocínios ativos em simultâneo, cada um com vigência independente.
- **Restrição:** `EXCLUDE USING gist (store_id WITH =, sponsor_entity_id WITH =, tstzrange(valid_from, valid_to) WITH &&) WHERE (status = 'active')`. Nunca há dois períodos ativos sobrepostos para o mesmo par.
- **"Ativo" no cálculo** = `status = 'active' AND now() <@ tstzrange(valid_from, valid_to)`. O job que passa a `expired` é só higiene: o cálculo nunca depende dele.
- **`commission_override_bps INT NOT NULL DEFAULT 0`** (0..10000) por patrocínio: normalmente 0.
- **Elegibilidade** pela morada física da loja (`storefront_dicofre`):
  - `municipality` cobre o concelho (código DDCC);
  - `parish` cobre a freguesia (DDCCFF);
  - `association` cobre uma lista de áreas DICOFRE configurada na entidade.

  Quem aprova é o `sponsor_admin` da entidade, no painel. Nenhuma loja fica patrocinada sem aprovação explícita.

## 3. Comissão efetiva (dinheiro: `i64` cêntimos, `rust_decimal`, bps; nunca float)
Precedência, avaliada no checkout para cada `sub_order`:
1. **Patrocinada** (≥ 1 patrocínio ativo): `applied_bps = MIN(commission_override_bps)` dos ativos (por defeito 0).
2. Senão, **exceção negociada**: `stores.custom_commission_bps` (NULL por defeito; só o `super_admin` a define, auditada).
3. Senão, **plano de faturação** da loja (`stores.billing_plan_code`, §4), com o volume mensal já acumulado.

- **Comissão de referência** (a "âncora" `~~8%~~`): `reference_bps = COALESCE(stores.custom_commission_bps, platform_settings.base_commission_bps)`. A base é 800 bps e configurável, nunca hardcoded.
- **Patrocínio ativo prevalece sobre o plano (decisão do owner, 27/11/2026):** o `billing_plan_code` (`commission_payg` ou `tiered_subscription`) só entra em vigor quando a loja **não** tem patrocínio `active`. Com ≥ 1 patrocínio ativo, a poupança (`sponsored_discount_cents`) mede-se sempre contra `reference_bps` acima, mesmo que o plano guardado seja `tiered_subscription` (coerência com a âncora `~~8%~~ 0%` e relatórios uniformes para as entidades patrocinadoras), e a loja **não paga mensalidade** (0 €): `money::monthly_fee_due`.
- **Base de cálculo:** subtotal dos produtos (PVP com IVA), **sem portes**.
- **Arredondamento:** half-up, só no módulo `money`.
- **Fórmulas:**
  - `platform_fee_cents = round(subtotal × applied)`, com escalões marginais se for o caso;
  - `sponsored_discount_cents = round(subtotal × reference_bps) − platform_fee_cents`, nunca negativo, e 0 quando não há patrocínio.
- **Contador de poupança do lojista** = Σ `sponsored_discount_cents` das suas `sub_orders` pagas, menos as reembolsadas.
- A comissão **não depende do domínio** onde a compra foi feita. Se todos os patrocínios cessarem, a loja continua no portal e passa à regra 2 ou 3, como aceitou no contrato (§6).
- **Pendente (contabilista):** IVA sobre a comissão. Por defeito, `platform_fee_cents` é o valor sem IVA, e o IVA de 23% do serviço é faturado pela Segjar na fatura mensal ao lojista (épico de pagamentos).

## 4. Planos para lojas sem patrocínio ativo (escalões marginais, tipo IRS)
- **Escalões:** vêm da tabela `billing_plan_tiers` (editável só pelo `super_admin`, auditada; nunca hardcoded em Rust). Cada escalão tem `plan_code`, `gmv_from_cents`, `gmv_to_cents` (NULL = sem teto), `monthly_fee_cents` e `marginal_commission_bps`. Esta comissão aplica-se **só à parte do volume dentro do escalão**.
- **Volume mensal (`store_monthly_gmv_cents`):** subtotal de produtos (sem portes) das `sub_orders` pagas da loja no mês civil, em Europe/Lisbon. Um reembolso não muda retroativamente o escalão de vendas já liquidadas.
- **Venda que atravessa um limite:** é partida em Rust pela parte abaixo e pela parte acima.

| Plano | Escalão (volume mensal da loja) | Mensalidade | Comissão marginal |
|---|---|---|---|
| `commission_payg` (default; âncora `~~8%~~ 0%`) | 0 € – 20.000 € | 0 € | 8% (800 bps) |
| | > 20.000 € | — | 6% (600 bps) só sobre o excedente |
| `tiered_subscription` (100% mensalidade fixa, 0% comissão) | ≤ 1.000 € | 5 € | 0% |
| | 1.000,01 € – 5.000 € | 10 € | 0% |
| | 5.000,01 € – 10.000 € | 50 € | 0% |
| | 10.000,01 € – 25.000 € | 100 € | 0% |
| | 25.000,01 € – 50.000 € | 175 € | 0% |
| | 50.000,01 € – 100.000 € | 300 € | 0% |
| | > 100.000 € | 500 € | 0% |

- **`tiered_subscription` (decisão do owner, 27/11/2026; migration 0034):** só mensalidade fixa por escalão, 0% de comissão em todos, para proteger o retalho de margem curta (informática, eletrodomésticos). Há degraus de mensalidade entre escalões, por desenho. Loja neste plano sem patrocínio ativo: `platform_fee_cents = 0`, `applied_commission_bps = 0`, `sponsored_discount_cents = 0`.
- **Cálculo marginal:** continua em `money::effective_commission` para o `commission_payg` (8% → 6%) e para qualquer plano híbrido (mensalidade + bps) que o `super_admin` configure.
- **Mensalidade:** a do escalão atingido no fim do mês (`money::monthly_fee_for`). A cobrança usa `money::monthly_fee_due`: 0 € se a loja tiver patrocínio `active` (§3), mesmo com `billing_plan_code = tiered_subscription` (ex.: loja independente que passou a patrocinada).
- **Épico 03:** modelo de dados (`billing_plan_code` com default `commission_payg`, `billing_plan_tiers`) e a função `effective_commission_bps(store, at, store_monthly_gmv_cents)`.
- **Épico de pagamentos:** cobrança recorrente das mensalidades (Stripe Billing / fatura mensal da Segjar / incumprimento).

## 5. Geografia oficial (DICOFRE) e moradas
- **`geo_dicofre`:** tabela de referência (distrito DD, concelho DDCC, freguesia DDCCFF, nome, `caop_version`), carregada da **CAOP da DGT** (dados abertos) por script de seed, não por migration. A versão da CAOP fica registada, porque a reorganização de freguesias de 2025 alterou códigos e os patrocínios antigos têm de continuar a resolver.
- **`stores`:**
  - `fiscal_address` (JSONB, faturação);
  - `storefront_address` (JSONB, morada física; é a que dá elegibilidade ao patrocínio);
  - `storefront_dicofre` (FK `geo_dicofre`).

  O `address_json` fica deprecado.
- **Código postal → DICOFRE:** um código postal não corresponde sempre a uma só freguesia. No registo, o código postal **sugere** o concelho e as freguesias possíveis, e o lojista confirma. A deteção de patrocinadores usa a freguesia confirmada. A fonte CP→concelho está por fechar: a base dos CTT é licenciada; a alternativa é geocodificação + polígonos da CAOP.

## 6. Contrato, verificação e documentos
- **`stores`:** guarda `accepted_base_commission_bps`, `terms_version`, `terms_accepted_at` e `billing_plan_code`.
- **Aceitação:** gravada na mesma transação do registo da loja e auditada.
- **Formulário de criação de conta:**
  1. mostra 8%;
  2. com a freguesia confirmada, deteta os patrocinadores parceiros e mostra `~~8%~~ 0%` com os logótipos;
  3. avisa que a isenção depende de validação e que, se cessar, se aplica a comissão padrão (plano escolhido).
- **NIF** (módulo 11, `identity::nif::validate_pt`):

| Tipo | NIF | Documentos |
|---|---|---|
| Empresa | começa por `5` | código de acesso à Certidão Permanente; PDF opcional |
| Empresário em nome individual (ENI) | começa por `1`, `2` ou `3` | Declaração de Início/Alteração de Atividade (AT) ou Comprovativo de Domicílio Fiscal (PDF) |
| Outros prefixos válidos | — | revisão manual |

- **`store_verifications`:**
  - **Dados:** `kind`, `sha256`, `storage_key`, `status` (`pending` / `approved` / `rejected`), `reviewed_by`, `reviewed_at`, `delete_after`, `metadata`.
  - **Ficheiros:** num **armazenamento privado** (nunca `/media` público), acessíveis só por URL assinado de 5 min, gerado por um `super_admin` em revisão e auditado.
  - **Eliminação:** o ficheiro é apagado até 30 dias depois da decisão. O hash e os metadados ficam (prova).

## 7. Snapshot em `sub_orders` (congelado no checkout, nunca recalculado)
- **Colunas:**
  - `base_commission_bps` (a referência);
  - `applied_commission_bps`;
  - `platform_fee_cents`;
  - `sponsored_discount_cents`;
  - `billing_plan_code`;
  - `store_monthly_gmv_before_cents`;
  - `active_sponsor_ids UUID[] NOT NULL DEFAULT '{}'` (índice **GIN**);
  - `store_dicofre`;
  - `origin_channel_id` (o canal onde foi feita a compra: nacional vs. domínio próprio).
- **Regras dos relatórios (sem dupla contagem):**
  - **Relatório de uma entidade:** `WHERE active_sponsor_ids @> ARRAY[:entity]`. A venda co-patrocinada aparece inteira em cada entidade.
  - **Vários patrocinadores:** a união ("qualquer dos selecionados") usa `active_sponsor_ids && ARRAY[...]`; a interseção ("co-patrocinado por todos") usa `@> ARRAY[...]`.
  - **Totais** (combinados, multi-entidade ou globais): volume, n.º de encomendas e poupança calculam-se **diretamente sobre `sub_orders` únicas**, nunca somando linhas desagregadas por entidade.
  - **Desagregação por patrocinador:** o "Total Geral" vem sempre do agregado deduplicado e assinala quando há sobreposição por co-patrocínio.
  - **Dados pessoais:** os relatórios das entidades **nunca** expõem dados dos compradores (só agregados por loja, data, canal e DICOFRE).

## 8. Acesso: painel único `admin.ptmarket.pt`
- **Quem entra:** lojistas (`merchant_owner`, `merchant_staff`), staff das entidades (`sponsor_admin`, âmbito = `sponsor_entity_id`) e `super_admin` autenticam-se todos em `admin.ptmarket.pt` (`PLATFORM_ADMIN_HOST`).
- **Âmbito:** vem do papel (loja, entidade ou plataforma), nunca do Host.
- **Passkeys de staff:** um só `rp_id` (`admin.ptmarket.pt`).
- **`tenant_admin`:** mantém-se só para canais operados sem entidade (por exemplo, nichos). O `sponsor_admin` de uma entidade com domínio gere também o tema e o template do seu canal.
- **Clientes:** continuam a comprar e a autenticar-se em qualquer canal (conta global, spec 11 D4).

## 9. Auditoria e alertas (spec 13)
- **Eventos novos:**
  - `sponsorship.requested` / `approved` / `rejected` / `revoked` / `expired`;
  - `platform_settings.update`, `billing_plan_tiers.*`;
  - `store.commission_override`, `store.billing_plan_changed`;
  - `store_verification.url_issued` / `approved` / `rejected` / `file_deleted`.
- **Kinds críticos** (alerta imediato): mudança de `base_commission_bps`, de escalões, de `custom_commission_bps` e revogação de patrocínio.
