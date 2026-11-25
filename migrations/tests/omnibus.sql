-- Teste Omnibus (0007): histórico de preços só de acréscimo e lowest_price_30d_cents calculado pela BD.
-- Alterações de preço e asserções com SET ROLE ptmarket_app + contexto de tenant;
-- só os tenants e o recuo de datas do histórico são feitos pelo superuser (RESET ROLE).
-- Tudo numa transação com ROLLBACK (now() é constante dentro dela).

BEGIN;

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

CREATE FUNCTION pg_temp.expect_value(p_sql text, p_expected bigint, p_label text)
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

INSERT INTO tenants (id, slug, custom_domain, name) VALUES
    ('00000000-0000-7000-8000-00000000100a', 'omni-teste-a', 'omni-a.teste.invalid', 'Omni A'),
    ('00000000-0000-7000-8000-00000000100b', 'omni-teste-b', 'omni-b.teste.invalid', 'Omni B');

-- ---------------------------------------------------------------------------
-- Dados do tenant B (para o teste de isolamento).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000100b';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000010b1', '00000000-0000-7000-8000-00000000100b',
     'Omni B', 'omni-b', 'Omni B Lda', '500000012', 'PT50000000000000000000012', 'ob@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000010b2', '00000000-0000-7000-8000-00000000100b',
     '00000000-0000-7000-8000-0000000010b1', '{"pt":"Produto B"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000010b3', '00000000-0000-7000-8000-00000000100b',
     '00000000-0000-7000-8000-0000000010b2', 999);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE variant_id = '00000000-0000-7000-8000-0000000010b3'$q$,
    1, 'tenant B vê o seu histórico (controlo positivo)');

-- ---------------------------------------------------------------------------
-- Dados do tenant A: 3 variantes.
-- ---------------------------------------------------------------------------
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000100a';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000010a1', '00000000-0000-7000-8000-00000000100a',
     'Omni A', 'omni-a', 'Omni A Lda', '500000011', 'PT50000000000000000000011', 'oa@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000010a2', '00000000-0000-7000-8000-00000000100a',
     '00000000-0000-7000-8000-0000000010a1', '{"pt":"Produto A"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-0000000010f1', '00000000-0000-7000-8000-00000000100a',
     '00000000-0000-7000-8000-0000000010a2', 1000),
    ('00000000-0000-7000-8000-0000000010f2', '00000000-0000-7000-8000-00000000100a',
     '00000000-0000-7000-8000-0000000010a2', 1000);

-- ---------------------------------------------------------------------------
-- Vetor 3: variante nova ⇒ lowest NULL (mesmo que a app o escreva) e 1 linha no histórico.
-- ---------------------------------------------------------------------------
INSERT INTO product_variants (id, tenant_id, product_id, price_cents, lowest_price_30d_cents) VALUES
    ('00000000-0000-7000-8000-0000000010f3', '00000000-0000-7000-8000-00000000100a',
     '00000000-0000-7000-8000-0000000010a2', 500, 5);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_variants
       WHERE id = '00000000-0000-7000-8000-0000000010f3' AND lowest_price_30d_cents IS NULL$q$,
    1, 'variante nova: lowest NULL (valor da app ignorado)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE variant_id = '00000000-0000-7000-8000-0000000010f3' AND price_cents = 500$q$,
    1, 'variante nova: 1 linha no histórico');

-- ---------------------------------------------------------------------------
-- Vetor 1: 1000 (há 40 d) → 2000 (há 5 d) → 1500 agora ⇒ lowest = 1000.
-- ---------------------------------------------------------------------------
RESET ROLE;
UPDATE product_price_history SET recorded_at = now() - interval '40 days'
 WHERE variant_id = '00000000-0000-7000-8000-0000000010f1' AND price_cents = 1000;
SET ROLE ptmarket_app;
UPDATE product_variants SET price_cents = 2000 WHERE id = '00000000-0000-7000-8000-0000000010f1';
RESET ROLE;
UPDATE product_price_history SET recorded_at = now() - interval '5 days'
 WHERE variant_id = '00000000-0000-7000-8000-0000000010f1' AND price_cents = 2000;
SET ROLE ptmarket_app;
UPDATE product_variants SET price_cents = 1500, lowest_price_30d_cents = 1
 WHERE id = '00000000-0000-7000-8000-0000000010f1';
SELECT pg_temp.expect_value(
    $q$SELECT lowest_price_30d_cents FROM product_variants
       WHERE id = '00000000-0000-7000-8000-0000000010f1'$q$,
    1000, 'vetor 1: lowest = 1000 (valor da app ignorado)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE variant_id = '00000000-0000-7000-8000-0000000010f1'$q$,
    3, 'vetor 1: 3 linhas no histórico');

-- ---------------------------------------------------------------------------
-- Vetor 2: 1000 (há 40 d) → 2000 (há 35 d) → 1500 agora ⇒ lowest = 2000.
-- ---------------------------------------------------------------------------
RESET ROLE;
UPDATE product_price_history SET recorded_at = now() - interval '40 days'
 WHERE variant_id = '00000000-0000-7000-8000-0000000010f2' AND price_cents = 1000;
SET ROLE ptmarket_app;
UPDATE product_variants SET price_cents = 2000 WHERE id = '00000000-0000-7000-8000-0000000010f2';
RESET ROLE;
UPDATE product_price_history SET recorded_at = now() - interval '35 days'
 WHERE variant_id = '00000000-0000-7000-8000-0000000010f2' AND price_cents = 2000;
SET ROLE ptmarket_app;
UPDATE product_variants SET price_cents = 1500 WHERE id = '00000000-0000-7000-8000-0000000010f2';
SELECT pg_temp.expect_value(
    $q$SELECT lowest_price_30d_cents FROM product_variants
       WHERE id = '00000000-0000-7000-8000-0000000010f2'$q$,
    2000, 'vetor 2: lowest = 2000');

-- ---------------------------------------------------------------------------
-- UPDATE sem mudança de preço: sem linha nova; lowest escrito pela app é ignorado.
-- ---------------------------------------------------------------------------
UPDATE product_variants SET stock_qty = 7, lowest_price_30d_cents = 1
 WHERE id = '00000000-0000-7000-8000-0000000010f1';
UPDATE product_variants SET price_cents = 1500
 WHERE id = '00000000-0000-7000-8000-0000000010f1';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE variant_id = '00000000-0000-7000-8000-0000000010f1'$q$,
    3, 'UPDATE sem mudança de preço não cria linha');
SELECT pg_temp.expect_value(
    $q$SELECT lowest_price_30d_cents FROM product_variants
       WHERE id = '00000000-0000-7000-8000-0000000010f1'$q$,
    1000, 'UPDATE sem mudança de preço mantém lowest (valor da app ignorado)');

-- ---------------------------------------------------------------------------
-- Casos de erro. ON DELETE RESTRICT (spec) devolve 23001 restrict_violation, não 23503.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO product_price_history (tenant_id, variant_id, price_cents)
       VALUES ('00000000-0000-7000-8000-00000000100a', '00000000-0000-7000-8000-0000000010f1', 1)$q$,
    '42501', 'app não insere no histórico');
SELECT pg_temp.expect_error(
    $q$UPDATE product_price_history SET price_cents = 1
       WHERE variant_id = '00000000-0000-7000-8000-0000000010f1'$q$,
    '42501', 'app não altera o histórico');
SELECT pg_temp.expect_error(
    $q$DELETE FROM product_price_history
       WHERE variant_id = '00000000-0000-7000-8000-0000000010f1'$q$,
    '42501', 'app não apaga o histórico');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE tenant_id = '00000000-0000-7000-8000-00000000100b'$q$,
    0, 'tenant A não lê o histórico do B');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM product_price_history
       WHERE tenant_id <> '00000000-0000-7000-8000-00000000100a'$q$,
    0, 'tenant A só vê histórico do próprio tenant');
SELECT pg_temp.expect_error(
    $q$DELETE FROM product_variants WHERE id = '00000000-0000-7000-8000-0000000010f3'$q$,
    '23001', 'apagar variante com histórico falha');
SELECT pg_temp.expect_error(
    $q$DELETE FROM products WHERE id = '00000000-0000-7000-8000-0000000010a2'$q$,
    '23001', 'apagar produto com variantes com histórico falha');

RESET ROLE;
ROLLBACK;
