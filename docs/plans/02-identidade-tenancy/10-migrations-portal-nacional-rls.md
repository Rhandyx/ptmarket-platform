# 10 — RLS do portal nacional: leitura só de lojas com `publish_to_national_portal` (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 04 · **Paralelo com:** 07

## Objetivo
Uma transação marcada como portal nacional lê (e só lê) lojas, produtos e variantes de qualquer tenant que tenham optado por publicar no portal; tudo o resto continua isolado.

## Pode alterar
- `migrations/0016_national_portal_policies.sql`, `migrations/tests/portal.sql` (criar)

## Não tocar
- `migrations/0001–0015` — imutáveis (as policies `tenant_isolation` ficam como estão; aqui só se ACRESCENTAM policies de SELECT); `backend-rust/`, `workers-go/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
CLAUDE.md regra 2: multi-tenant = RLS + filtro tenant_id + verificação de dono em cada handler. Portal nacional só lojas com publish_to_national_portal.
tenants.tenant_type ∈ ('municipal','national_portal','niche'); tenants.country_code ∈ ('PT','ES'); stores.publish_to_national_portal BOOLEAN DEFAULT false (opt-in do lojista); stores.is_active; products.is_published; product_variants.is_active.
Existente (0003/0004): CREATE POLICY tenant_isolation ON <t> FOR ALL TO ptmarket_app USING (tenant_id = T) WITH CHECK (tenant_id = T), T := NULLIF(current_setting('app.current_tenant_id', true), '')::uuid.
A criar:
  app_is_national_portal() RETURNS boolean, STABLE, SECURITY INVOKER, search_path fixo: current_setting('app.portal_national', true) = 'on' AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = T AND t.tenant_type = 'national_portal' AND t.is_active)
    → a flag sozinha não chega: o tenant do contexto tem de SER um portal nacional ativo (um tenant municipal nunca lê outros, mesmo que a app se engane).
  portal_read ON stores FOR SELECT TO ptmarket_app USING (app_is_national_portal() AND publish_to_national_portal AND is_active AND EXISTS (SELECT 1 FROM tenants o, tenants p WHERE o.id = stores.tenant_id AND o.is_active AND p.id = T AND o.country_code = p.country_code))
    → mesmo país do portal: o IVA de ES/ilhas ainda não está decidido pelo owner; lojas de outro país não aparecem até lá.
  portal_read ON products FOR SELECT … USING (app_is_national_portal() AND is_published AND EXISTS (loja do produto visível pela regra acima))
  portal_read ON product_variants FOR SELECT … USING (app_is_national_portal() AND is_active AND EXISTS (produto visível pela regra acima))
  Só FOR SELECT: INSERT/UPDATE/DELETE continuam a exigir tenant_id = T. product_price_history NÃO ganha policy de portal (o Omnibus lê-se em product_variants.lowest_price_30d_cents).
  Índices: confirmar que (publish_to_national_portal) WHERE … de 0003 serve; acrescentar só se o EXPLAIN do teste mostrar seq scan em products por loja.
Colunas sensíveis: a policy é por linha; a API nunca seleciona iban, invoicing_credentials_enc, eupago_split_key, stripe_account_id em modo portal (regra do cartão 11, não da BD). Nenhuma tabela nova (o teste de cobertura do cartão 03 continua verde).
```

## Feito quando
- [ ] `portal.sql` (sempre `SET ROLE ptmarket_app`): contexto do tenant portal + `app.portal_national = 'on'` vê as lojas publicadas e ativas de A e B e nenhuma não publicada; produtos/variantes seguem a loja; loja inativa, produto não publicado e variante inativa não aparecem
- [ ] Sem a flag, o portal vê só as suas próprias linhas; tenant municipal COM a flag continua a ver só as suas (anti-IDOR); sem contexto: 0 linhas
- [ ] Em modo portal, INSERT/UPDATE/DELETE numa loja, produto ou variante de outro tenant falha ou afeta 0 linhas; loja de tenant `ES` não aparece num portal `PT`

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Isolamento base (`rls.sql`), Omnibus (`omnibus.sql`) e caixa negra (`audit_*.sql`) — todos no `run.sh` · `cd backend-rust && … cargo test -p ptmarket-api --test rls_isolation`
