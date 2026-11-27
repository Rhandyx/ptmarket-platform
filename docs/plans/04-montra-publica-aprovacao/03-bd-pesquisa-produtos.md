# 03 — BD 0040: pesquisa de produtos (FTS sem acentos) por função do portal (épico: 04-montra-publica-aprovacao)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** par 01 + 02 · **Par atómico com:** 04 (corre logo a seguir; um só commit no fim do par) · **Auditoria:** security-auditor obrigatório

## Objetivo
A pesquisa por texto usa um índice GIN e devolve só ids de produtos visíveis no canal, por uma função do portal (a view `security_barrier` não deixa o `@@` usar o índice).

## Pode alterar
- `migrations/0040_product_search.sql` (criar); `migrations/tests/product_search.sql` (criar) + registo em `migrations/tests/run.sh`

## Não tocar
- Migrations 0001–0039; `audit.*` e a máscara da L1 (seladas); as views da 0039 e `portal_stores`; `backend-rust/`, `frontend-web/`. Nunca ler `.env`.

## Contexto exato (spec 11 D9; padrão DEFINER das `identity_*` e do portal)
```
Extensão: CREATE EXTENSION IF NOT EXISTS unaccent (trusted, como btree_gist na 0031). Se o migrator não a conseguir criar em dev → PARAR e reportar (bootstrap como superuser), não contornar.
f_unaccent(text) RETURNS text: LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT, SET search_path = pg_catalog; corpo: public.unaccent('public.unaccent'::regdictionary, $1). REVOKE ALL FROM PUBLIC; EXECUTE para ptmarket_app e ptmarket_portal.
products.search_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, public.f_unaccent(coalesce(title->>'pt','') || ' ' || coalesce(title->>'es','')))) STORED.
Índice: products_search_idx USING gin (search_tsv) WHERE is_published (exceção documentada à regra "começa por tenant_id": é GIN).
Caixa negra: confirmar em audit_l1.sql que a tabela continua coberta. Se o trigger L1 gravar search_tsv nos eventos → PARAR e reportar (mexer na máscara é alteração selada, fora deste cartão).
Função portal_search_product_ids(p_query text, p_after uuid, p_limit int) RETURNS SETOF uuid:
  LANGUAGE sql STABLE SECURITY DEFINER, SET search_path = pg_catalog, pg_temp; dona ptmarket_portal (GRANT CREATE ON SCHEMA só durante o ALTER … OWNER; sem SET ROLE; padrão da 0033); REVOKE ALL FROM PUBLIC; GRANT EXECUTE só a ptmarket_app.
  Corpo: ids de public.products p WHERE p.search_tsv @@ websearch_to_tsquery('simple', public.f_unaccent(left(p_query, 200))) AND p.is_published AND EXISTS loja em public.portal_stores (tenant_id + id) AND EXISTS variante is_active AND (p_after IS NULL OR p.id < p_after) ORDER BY p.id DESC LIMIT least(greatest(p_limit, 1), 49). Texto vazio ou só espaços → 0 linhas.
  Os GUC do canal (app.current_tenant_id, app.portal_national) são da transação e valem dentro da DEFINER. A função corre como ptmarket_portal: as policies portal_view (0039) continuam a aplicar-se (defesa em profundidade).
  Grants que faltam ao portal para isto funcionar: SELECT (search_tsv) ON products; EXECUTE ON FUNCTION app_is_national_portal() (INVOKER, usada dentro de portal_stores); SELECT (tenant_type) ON tenants (lida por essa função). Nada mais.
Ordem v1 = mais recentes primeiro (sem ts_rank): a relevância fica para o motor externo (SearchBackend, spec 11 D9).
Topo da migration: rollback mental completo (DROP FUNCTION, DROP INDEX, DROP COLUMN, REVOKEs; a extensão fica).
```

## Feito quando
- [ ] `product_search.sql`: "pao" encontra "Pão de Mafra" e "PÃO"; dois termos = E; texto vazio → 0; aspas e operadores (`"a b" -c`, `' OR 1=1`) não dão erro nem SQL injetado
- [ ] Isolamento: no canal A a função só devolve produtos de lojas patrocinadas por A; no nacional, todos os publicados; sem contexto → 0; produto não publicado ou só com variantes inativas nunca sai
- [ ] `EXPLAIN` da consulta interna usa `products_search_idx`; `p_limit` 0, negativo e 1000 ficam limitados; `PUBLIC` e o migrator sem INHERIT não executam a função; `prosecdef`, dono e `proacl` verificados no teste
- [ ] `ptmarket_portal` continua NOLOGIN, sem BYPASSRLS e sem mais grants do que os listados (teste compara `information_schema.column_privileges`)

## Prova (um comando)
`migrations/tests/run.sh` → esperado: tudo verde, incluindo `product_search`, `portal_catalog` e `audit_l1`

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Omnibus (`omnibus.sql`: alterar o título não gera histórico de preços) e `store_scope_rls.sql`, incluídos no `run.sh`; `cargo test -p ptmarket-api` (o `build.rs` recompila com a migration nova) verde antes do commit do par
