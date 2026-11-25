-- Teste de RLS/grants das migrations 0001-0006.
-- Asserções correm sempre com SET ROLE (ptmarket_app / ptmarket_worker), nunca como superuser.
-- Só os tenants (tabela global sem grant de escrita) são criados pelo dono das migrations.
-- Tudo numa transação com ROLLBACK: a BD fica como estava.

BEGIN;

-- Auxiliares (SECURITY INVOKER: executam com o papel corrente).
CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %: %)', p_label, p_state, v_state, v_msg;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado erro %, mas passou)', p_label, p_state;
END
$$;

CREATE FUNCTION pg_temp.expect_count(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql INTO v_n;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado %, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Tenants de teste (globais; só o dono das migrations escreve).
INSERT INTO tenants (id, slug, custom_domain, name) VALUES
    ('00000000-0000-7000-8000-00000000000a', 'rls-teste-a', 'rls-a.teste.invalid', 'Tenant A'),
    ('00000000-0000-7000-8000-00000000000b', 'rls-teste-b', 'rls-b.teste.invalid', 'Tenant B');

-- ---------------------------------------------------------------------------
-- Papéis: nenhum é superuser nem ignora RLS.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname IN ('ptmarket_app', 'ptmarket_worker')
         AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin$q$,
    2, 'papéis sem rolsuper/rolbypassrls/login');

-- ---------------------------------------------------------------------------
-- App sem contexto de tenant (GUC nunca definido): não escreve.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email)
       VALUES ('00000000-0000-7000-8000-00000000000a', 'X', 'x', 'X', '1', 'PT50', 'x@x.pt')$q$,
    '42501', 'app sem contexto não insere loja');

-- ---------------------------------------------------------------------------
-- Dados de cada tenant, criados pela própria app com o contexto certo.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000000b';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000000b1', '00000000-0000-7000-8000-00000000000b',
     'Loja B', 'loja-b', 'Loja B Lda', '500000002', 'PT50000000000000000000002', 'b@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000000b2', '00000000-0000-7000-8000-00000000000b',
     '00000000-0000-7000-8000-0000000000b1', '{"pt":"Produto B"}', 2300);
INSERT INTO product_variants (tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000000000b', '00000000-0000-7000-8000-0000000000b2', 199);

SET app.current_tenant_id = '00000000-0000-7000-8000-00000000000a';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000000a1', '00000000-0000-7000-8000-00000000000a',
     'Loja A', 'loja-a', 'Loja A Lda', '500000001', 'PT50000000000000000000001', 'a@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000000a2', '00000000-0000-7000-8000-00000000000a',
     '00000000-0000-7000-8000-0000000000a1', '{"pt":"Produto A"}', 600);
INSERT INTO product_variants (tenant_id, product_id, price_cents, stock_qty) VALUES
    ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-0000000000a2', 250, 3);

-- ---------------------------------------------------------------------------
-- App sem contexto (já com lojas A e B na BD): zero linhas.
-- ---------------------------------------------------------------------------
RESET app.current_tenant_id;
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'app sem contexto vê 0 lojas');
SELECT pg_temp.expect_count('SELECT count(*) FROM products', 0, 'app sem contexto vê 0 produtos');
SELECT pg_temp.expect_count('SELECT count(*) FROM product_variants', 0, 'app sem contexto vê 0 variantes');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000000a';

-- ---------------------------------------------------------------------------
-- Tenant A só vê o que é seu.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 1, 'tenant A vê 1 loja');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE tenant_id <> '00000000-0000-7000-8000-00000000000a'$q$,
    0, 'tenant A não vê lojas de outro tenant');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id <> '00000000-0000-7000-8000-00000000000a'$q$,
    0, 'tenant A não vê produtos de outro tenant');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants WHERE tenant_id <> '00000000-0000-7000-8000-00000000000a'$q$,
    0, 'tenant A não vê variantes de outro tenant');

SET app.current_tenant_id = '';
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'contexto vazio vê 0 lojas');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000000a';

-- ---------------------------------------------------------------------------
-- Escritas para o tenant B a partir do contexto A: 42501.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email)
       VALUES ('00000000-0000-7000-8000-00000000000b', 'Intrusa', 'intrusa', 'X', '1', 'PT50', 'x@x.pt')$q$,
    '42501', 'INSERT de loja para o tenant B falha');
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-00000000000b'
       WHERE id = '00000000-0000-7000-8000-0000000000a1'$q$,
    '42501', 'UPDATE que move loja para o tenant B falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, title, vat_rate_bps, store_id)
       VALUES ('00000000-0000-7000-8000-00000000000b', '{}', 2300, '00000000-0000-7000-8000-0000000000b1')$q$,
    '42501', 'INSERT de produto para o tenant B falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
       VALUES ('00000000-0000-7000-8000-00000000000b', '00000000-0000-7000-8000-0000000000b2', 1)$q$,
    '42501', 'INSERT de variante para o tenant B falha');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE stores SET name = 'pirata'
                  WHERE id = '00000000-0000-7000-8000-0000000000b1' RETURNING 1)
       SELECT count(*) FROM u$q$,
    0, 'UPDATE de loja do tenant B não afeta linhas');
SELECT pg_temp.expect_count(
    $q$WITH d AS (DELETE FROM products
                  WHERE id = '00000000-0000-7000-8000-0000000000b2' RETURNING 1)
       SELECT count(*) FROM d$q$,
    0, 'DELETE de produto do tenant B não afeta linhas');

-- ---------------------------------------------------------------------------
-- Integridade: FK composta e CHECKs.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-0000000000b1', '{}', 2300)$q$,
    '23503', 'produto do tenant A com loja do tenant B falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents, stock_qty)
       VALUES ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-0000000000a2', 100, -1)$q$,
    '23514', 'stock_qty = -1 falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_variants (tenant_id, product_id, price_cents)
       VALUES ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-0000000000a2', -1)$q$,
    '23514', 'price_cents negativo falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO products (tenant_id, store_id, title, vat_rate_bps)
       VALUES ('00000000-0000-7000-8000-00000000000a', '00000000-0000-7000-8000-0000000000a1', '{}', 10001)$q$,
    '23514', 'vat_rate_bps > 10000 falha');

-- ---------------------------------------------------------------------------
-- App: customers fechada; outbox só INSERT.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error('SELECT count(*) FROM customers', '42501', 'app não lê customers');
SELECT pg_temp.expect_error(
    $q$INSERT INTO customers (email) VALUES ('c@teste.invalid')$q$,
    '42501', 'app não escreve customers');
SELECT pg_temp.expect_error('SELECT count(*) FROM outbox_events', '42501', 'app não lê outbox_events');
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
       VALUES ('00000000-0000-7000-8000-00000000000b', 'store',
               '00000000-0000-7000-8000-0000000000b1', 'store.updated', '{}')$q$,
    '42501', 'app não insere evento do tenant B');
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
       VALUES (NULL, 'system', '00000000-0000-7000-8000-0000000000a1', 'system.ping', '{}')$q$,
    '42501', 'app no contexto do tenant A não insere evento global');
INSERT INTO outbox_events (id, tenant_id, aggregate, aggregate_id, event_type, payload) VALUES
    ('00000000-0000-7000-8000-0000000000e1', '00000000-0000-7000-8000-00000000000a', 'store',
     '00000000-0000-7000-8000-0000000000a1', 'store.created', '{"v":1}');

-- Sem contexto de tenant: evento global OK; evento de tenant recusado.
RESET app.current_tenant_id;
INSERT INTO outbox_events (id, tenant_id, aggregate, aggregate_id, event_type, payload) VALUES
    ('00000000-0000-7000-8000-0000000000e2', NULL, 'system',
     '00000000-0000-7000-8000-0000000000a1', 'system.ping', '{"v":1}');
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
       VALUES ('00000000-0000-7000-8000-00000000000a', 'store',
               '00000000-0000-7000-8000-0000000000a1', 'store.updated', '{}')$q$,
    '42501', 'app sem contexto não insere evento de tenant');
SET app.current_tenant_id = '';
SELECT pg_temp.expect_error(
    $q$INSERT INTO outbox_events (tenant_id, aggregate, aggregate_id, event_type, payload)
       VALUES ('00000000-0000-7000-8000-00000000000a', 'store',
               '00000000-0000-7000-8000-0000000000a1', 'store.updated', '{}')$q$,
    '42501', 'app com contexto vazio não insere evento de tenant');

RESET app.current_tenant_id;
RESET ROLE;

-- ---------------------------------------------------------------------------
-- Worker: lê o outbox, só altera published_at.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM outbox_events
       WHERE id IN ('00000000-0000-7000-8000-0000000000e1', '00000000-0000-7000-8000-0000000000e2')$q$,
    2, 'worker lê os eventos do outbox');
SELECT pg_temp.expect_error(
    $q$UPDATE outbox_events SET payload = '{"v":2}'
       WHERE id = '00000000-0000-7000-8000-0000000000e1'$q$,
    '42501', 'worker não altera payload');
SELECT pg_temp.expect_count(
    $q$WITH u AS (UPDATE outbox_events SET published_at = now()
                  WHERE id = '00000000-0000-7000-8000-0000000000e1' RETURNING 1)
       SELECT count(*) FROM u$q$,
    1, 'worker marca published_at');
SELECT pg_temp.expect_error(
    $q$UPDATE outbox_events SET published_at = NULL
       WHERE id = '00000000-0000-7000-8000-0000000000e1'$q$,
    '42501', 'worker não repõe published_at = NULL (replay)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM outbox_events
       WHERE id = '00000000-0000-7000-8000-0000000000e1' AND published_at IS NOT NULL$q$,
    1, 'evento continua publicado');
SELECT pg_temp.expect_error('SELECT count(*) FROM stores', '42501', 'worker não lê stores');
SELECT pg_temp.expect_error('SELECT count(*) FROM customers', '42501', 'worker não lê customers');
SELECT pg_temp.expect_error(
    $q$DELETE FROM outbox_events WHERE id = '00000000-0000-7000-8000-0000000000e1'$q$,
    '42501', 'worker não apaga eventos');
RESET ROLE;

ROLLBACK;
