# 90 — Nota (não é cartão): pré-requisitos para o épico de encomendas e para o de pagamentos

> Fora do épico 03 por decisão de âmbito: `sub_orders`/snapshot (épico de encomendas) e cobrança das mensalidades (épico de pagamentos). Esta nota diz o que o épico 03 deixa pronto e o que os próximos têm de respeitar. Fonte: spec 14 §3, §4, §7.

## O que o épico 03 entrega e os próximos usam
- `payments::commission::effective_commission_bps(tx, store_id, at, store_monthly_gmv_cents, subtotal)` → `CommissionSnapshot` (cartão 18), com os campos a congelar. O checkout chama-a uma vez por `sub_order`, dentro da transação do checkout, e grava o resultado tal como vem.
- `money::effective_commission` e `money::monthly_fee_for` (cartão 12): toda a aritmética e todo o arredondamento. Nenhuma conta de comissão fora de `money`.
- Isolamento por loja na BD (cartões 08b e 14): GUC `app.store_id` + policies RESTRICTIVE. Kinds críticos e eventos de patrocínio (cartões 11, 19, 20).

## Colunas do snapshot em `sub_orders` (congelado no checkout, nunca recalculado)
`base_commission_bps` (a referência), `applied_commission_bps`, `platform_fee_cents`, `sponsored_discount_cents`, `billing_plan_code`, `store_monthly_gmv_before_cents`, `active_sponsor_ids UUID[] NOT NULL DEFAULT '{}'` (índice **GIN**), `store_dicofre`, `origin_channel_id` (canal onde foi feita a compra). Dinheiro em `BIGINT`, percentagens em `INT` bps.

## Regras que o épico de encomendas tem de cumprir
1. **Volume mensal:** `store_monthly_gmv_cents` = subtotal de produtos (PVP com IVA, sem portes) das `sub_orders` pagas da loja no mês civil, em Europe/Lisbon. Um reembolso não muda retroativamente o escalão de vendas já liquidadas.
2. **Concorrência:** duas vendas simultâneas da mesma loja perto de um limite de escalão têm de ler o volume de forma serializada (ex.: linha de contador por loja/mês com `FOR UPDATE`), senão as duas calculam no escalão antigo.
3. **Checkout e RLS por loja (a desenhar no 1.º cartão de BD desse épico):** o checkout é de um cliente e toca em várias lojas, mas `stores` e `store_sponsorships` só se leem com `app.store_id` da loja ou com ator admin. Opções: um âmbito de loja por `sub_order` criado por um tipo que prova que o carrinho contém essa loja, ou uma função `identity_*` de leitura dos termos de comissão. As tabelas novas (`sub_orders`, itens, reservas de stock) levam a mesma policy RESTRICTIVE por loja, com a exceção explícita do cliente dono da encomenda.
4. **Comissão não depende do canal:** `origin_channel_id` é só para relatórios.
5. **Relatórios sem dupla contagem (testes de co-patrocínio obrigatórios, Câmara + Junta na mesma loja):**
   - relatório de uma entidade: `WHERE active_sponsor_ids @> ARRAY[:entity]` (a venda co-patrocinada aparece inteira em cada entidade);
   - união: `&& ARRAY[...]`; interseção: `@> ARRAY[...]`;
   - totais (volume, n.º de encomendas, poupança) calculados sobre `sub_orders` únicas, nunca somando linhas por entidade; na desagregação por patrocinador, o "Total Geral" vem do agregado deduplicado e assinala a sobreposição;
   - as entidades nunca veem dados de compradores: só agregados por loja, data, canal e DICOFRE (RGPD, minimização).
6. **Contador de poupança do lojista** = Σ `sponsored_discount_cents` das `sub_orders` pagas, menos as reembolsadas.
7. **Anti-IDOR:** cada handler de loja usa `RequireStoreRole`/`RequireStoreOwner` + `begin_store_tx` (cartão 14) e tem teste entre duas lojas do mesmo país, dos dois lados (extractor e RLS).
8. **`shipping_scope`:** o checkout só oferece o que o âmbito da loja permite (`national` / `local_only` / `pickup_only`).
9. **Art. 53.º e IVA:** a base da comissão é o PVP com IVA; numa loja em Art. 53.º (IVA 0%) a base é o mesmo subtotal. `platform_fee_cents` é sem IVA; o IVA de 23% do serviço é faturado pela Segjar na fatura mensal (pendente de confirmação do contabilista).

## Para o épico de pagamentos
- Mensalidade = `money::monthly_fee_for(tiers, volume do mês fechado)`; cobrança recorrente, fatura mensal e incumprimento ficam lá.
- Edição de `platform_settings`, `billing_plan_tiers` e `stores.custom_commission_bps` pelo super_admin: função `identity_*` com 2FA + evento `store.commission_override` (o kind crítico já existe).

## Para o épico de onboarding (spec 05)
- Endpoint de registo da loja (cria utilizador + `merchant_owner` + loja no canal nacional + aceitação do contrato na mesma transação, auditada): precisa de uma função `identity_*`, porque a app não escreve `user_roles` nem insere lojas sem âmbito. Liga o botão final do cartão 26.
- Regra de ativação da loja (`kyc_verified`) a partir das verificações aprovadas; convites da entidade (`initiated_by = 'sponsor'`) e CRUD de entidades e de `sponsor_admin` pelo super_admin.
