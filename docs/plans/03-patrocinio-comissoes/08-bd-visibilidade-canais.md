# 08 — BD: visibilidade por canal (`portal_stores`, `portal_read`, selos) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 06, 07 · **Par atómico com:** 16 (o 16 corre logo a seguir; um só commit, com tudo verde, no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
O canal nacional vê todas as lojas ativas do país; um canal white-label vê só as lojas com patrocínio ativo e vigente de uma entidade desse canal; `publish_to_national_portal` deixa de ser lido.

## Pode alterar
- `migrations/0033_channel_visibility.sql`, `migrations/tests/channel_visibility.sql` (criar); `migrations/tests/{portal,rls,identity_portal_hardening}.sql` (reescrever só os casos que dependem do opt-in ou de lojas em tenants municipais)

## Não tocar
- `migrations/0001–0032`; `app_is_national_portal()` (0016) fica igual; as policies `tenant_isolation`; as colunas já existentes de `portal_stores` (DSA: só se acrescenta no fim); o isolamento por loja (cartão 08b). Nunca ler `.env`.

## Contexto exato (spec 14 §1.1 + 0021)
```
Contexto: app.current_tenant_id é o canal do pedido. Sem opt-out no nacional. Não há cópia de produtos nem de stock. portal_stores continua a ser a forma única de ler lojas fora do backoffice.
Condição nova, igual na view e na policy portal_view (FOR SELECT TO ptmarket_portal) de stores (hoje: app_is_national_portal() AND publish_to_national_portal AND is_active AND EXISTS tenants o/p do mesmo país):
  s.is_active AND EXISTS (SELECT 1 FROM public.tenants o WHERE o.id = s.tenant_id AND o.is_active) AND (
    ((SELECT public.app_is_national_portal()) AND s.tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    OR EXISTS (SELECT 1 FROM public.store_sponsorships sp JOIN public.sponsor_entities e ON e.id = sp.sponsor_entity_id AND e.is_active
                 JOIN public.tenants c ON c.id = e.channel_tenant_id AND c.is_active JOIN public.tenants o ON o.id = s.tenant_id AND o.country_code = c.country_code
               WHERE sp.store_id = s.id AND sp.status = 'active' AND now() <@ tstzrange(sp.valid_from, sp.valid_to) AND e.channel_tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid))
View: CREATE OR REPLACE VIEW portal_stores WITH (security_barrier = true), mesmas colunas e ordem da 0021 + no fim shipping_scope, storefront_address, storefront_dicofre. Dona continua ptmarket_portal; REVOKE ALL FROM PUBLIC; SELECT só para ptmarket_app.
  Substituir a view sem SET ROLE: padrão da 0021 secção D (GRANT ptmarket_portal TO <migrator> WITH INHERIT TRUE; alterar; repor WITH INHERIT FALSE, SET TRUE). Nunca SET ROLE ptmarket_portal (não tem acesso a audit: lição L2).
ptmarket_portal: GRANT SELECT por coluna só do que a condição e as views leem (stores: + shipping_scope, storefront_address, storefront_dicofre; store_sponsorships: store_id, sponsor_entity_id, status, valid_from, valid_to; sponsor_entities: id, kind, name, slug, logo_key, channel_tenant_id, is_active) + policies FOR SELECT TO ptmarket_portal nessas duas tabelas (só active e vigente / só is_active).
products e product_variants: DROP + CREATE das portal_read (0021) SEM o gate app_is_national_portal(): is_published (is_active nas variantes) AND EXISTS em portal_stores com o mesmo tenant_id e store_id. O gate vive na view. Trinco: trigger em stores (INSERT ou UPDATE OF tenant_id) que recusa um tenant que não seja national_portal.
Selos: CREATE VIEW portal_store_badges (security_barrier, dona ptmarket_portal, SELECT só app): store_id, sponsor_entity_id, kind, name, slug, logo_key de patrocínios ativos e vigentes de entidades ativas, só para lojas presentes em portal_stores. Ordem fixa (no COMMENT): municipality → parish → association; no mesmo tipo, por nome. Views não levam bloco L1.
```

## Feito quando
- [ ] Teste `channel_visibility`, **isolamento entre canais**: o canal da Câmara A vê só lojas patrocinadas por entidades do canal A; não vê as do canal B nem as sem patrocínio; `pending`, `rejected`, `revoked`, `expired`, e `active` com `valid_to` passado ou `valid_from` futuro não aparecem (sem depender do job)
- [ ] **Co-patrocínio:** loja com Câmara (canal A) + Junta (sem canal) aparece **uma só vez** em `portal_stores` no canal A e no nacional, com 2 linhas em `portal_store_badges` pela ordem fixa
- [ ] Nacional PT vê todas as lojas ativas PT, mesmo com `publish_to_national_portal = false` e `shipping_scope = 'pickup_only'`; não vê lojas ES, inativas ou de tenant inativo; loja criada num tenant `municipal` → erro do trinco
- [ ] Num white-label a app lê produtos publicados das lojas visíveis e 0 linhas das outras; nunca obtém `iban`, chaves ou comissões pela view; `ptmarket_portal` continua sem LOGIN/BYPASSRLS; `EXPLAIN` sem Seq Scan em `store_sponsorships` com 1.000 linhas

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `channel_visibility`, `portal`, `rls`, `identity_portal_hardening` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Dentro do par, `cargo test -p ptmarket-api` pode falhar só em `rls_isolation` (opt-in antigo): listar as falhas para o 16, que as fecha. O par só é entregue com `run.sh`, `cargo test -p ptmarket-api` e `go test -race ./...` verdes.
