-- run.sh: superuser
-- Teste da 0025 (cartão 02/23a): timeline global do Super-Admin.
--   public.identity_admin_read_events (porta: super_admin global + TOTP + sessão app.session_id com 2FA, não revogada,
--   não expirada) → audit.admin_read_events (selada; só lê audit.*): filtros, cursor (3 páginas sem repetidos nem
--   buracos), validação 22023, recusas 42501, chain_ok com a cadeia adulterada, EXPLAIN sem Seq Scan, selagem,
--   grants e a guarda de memberships da 0022 para ptmarket_identity.
-- Superuser só para semear contas, ler audit.* (conjuntos esperados), adulterar a cadeia (dono NOLOGIN, trigger
-- desligado só nesta transação) e ler catálogos; cada chamada às funções faz SET ROLE do papel em causa.
-- Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- L2 (0013) desligada só nesta transação: este teste não é sobre DDL

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

-- EXPLAIN (FORMAT JSON) de p_sql: sem Seq Scan em nenhum nó e cada índice de p_roots usado (raiz da árvore de
-- partições; partições vazias podem ir por outro índice).
CREATE FUNCTION pg_temp.expect_index_plan(p_sql text, p_roots text[], p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_plan    jsonb;
    v_seq     bigint;
    v_missing text;
BEGIN
    EXECUTE 'EXPLAIN (FORMAT JSON) ' || p_sql INTO v_plan;
    SELECT count(*) INTO v_seq
    FROM jsonb_path_query(v_plan, 'strict $.**."Node Type"') AS n(t)
    WHERE n.t #>> '{}' = 'Seq Scan';
    SELECT string_agg(r.root, ', ') INTO v_missing
    FROM unnest(p_roots) AS r(root)
    WHERE NOT EXISTS (
        SELECT 1 FROM jsonb_path_query(v_plan, 'strict $.**."Index Name"') AS i(t)
        WHERE pg_partition_root(('audit.' || quote_ident(i.t #>> '{}'))::regclass)::text = r.root);
    IF v_seq > 0 OR v_missing IS NOT NULL THEN
        RAISE EXCEPTION 'FALHOU: % (seq scans %, índices em falta: %) plano: %',
            p_label, v_seq, v_missing, left(v_plan::text, 2000);
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Resultados das chamadas (feitas como ptmarket_app), comparados depois como superuser.
CREATE TEMP TABLE res (
    label text, id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean, ord bigint);
GRANT SELECT, INSERT ON res TO ptmarket_app;

-- Janela fixa [now() − 1 dia, now() + 1 dia); devolve quantas linhas gravou em res.
CREATE FUNCTION pg_temp.grab(p_label text, p_tenant uuid, p_store uuid, p_actor uuid, p_order uuid, p_prefix text,
    p_outcome text, p_cur_at timestamptz, p_cur_id uuid, p_limit integer)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    INSERT INTO pg_temp.res
    SELECT p_label, f.*
    FROM public.identity_admin_read_events(now() - interval '1 day', now() + interval '1 day', p_tenant, p_store,
                                           p_actor, p_order, p_prefix, p_outcome, p_cur_at, p_cur_id, p_limit)
         WITH ORDINALITY AS f;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    RETURN v_n;
END
$$;

-- ---------------------------------------------------------------------------
-- 0. Contas e sessões (superuser; RLS não se aplica). A = super_admin com TOTP; B = super_admin sem TOTP;
--    C = sem papel, com TOTP.
-- ---------------------------------------------------------------------------
INSERT INTO public.users (id, email, full_name, totp_secret_enc, totp_enabled) VALUES
    ('00000000-0000-7000-8000-0000002a0001', 'a@ptm25.test', 'A', 'v1:a', true),
    ('00000000-0000-7000-8000-0000002a0002', 'b@ptm25.test', 'B', NULL, false),
    ('00000000-0000-7000-8000-0000002a0003', 'c@ptm25.test', 'C', 'v1:c', true);
INSERT INTO public.user_roles (user_id, role) VALUES
    ('00000000-0000-7000-8000-0000002a0001', 'super_admin'),
    ('00000000-0000-7000-8000-0000002a0002', 'super_admin');
INSERT INTO public.sessions (id, subject_type, subject_id, token_hash, mfa_verified_at, revoked_at,
                             impersonator_user_id, created_at, expires_at) VALUES
    -- A: válida com 2FA, sem 2FA, revogada, expirada, impersonada
    ('00000000-0000-7000-8000-0000002a5001', 'user', '00000000-0000-7000-8000-0000002a0001', sha256('s1'::bytea),
     now(), NULL, NULL, now(), now() + interval '8 hours'),
    ('00000000-0000-7000-8000-0000002a5002', 'user', '00000000-0000-7000-8000-0000002a0001', sha256('s2'::bytea),
     NULL, NULL, NULL, now(), now() + interval '8 hours'),
    ('00000000-0000-7000-8000-0000002a5003', 'user', '00000000-0000-7000-8000-0000002a0001', sha256('s3'::bytea),
     now(), now(), NULL, now(), now() + interval '8 hours'),
    ('00000000-0000-7000-8000-0000002a5004', 'user', '00000000-0000-7000-8000-0000002a0001', sha256('s4'::bytea),
     now() - interval '9 hours', NULL, NULL, now() - interval '9 hours', now() - interval '2 hours'),
    ('00000000-0000-7000-8000-0000002a5007', 'user', '00000000-0000-7000-8000-0000002a0001', sha256('s7'::bytea),
     now(), NULL, '00000000-0000-7000-8000-0000002a0002', now(), now() + interval '8 hours'),
    -- B e C: válidas com 2FA
    ('00000000-0000-7000-8000-0000002a5005', 'user', '00000000-0000-7000-8000-0000002a0002', sha256('s5'::bytea),
     now(), NULL, NULL, now(), now() + interval '8 hours'),
    ('00000000-0000-7000-8000-0000002a5006', 'user', '00000000-0000-7000-8000-0000002a0003', sha256('s6'::bytea),
     now(), NULL, NULL, now(), now() + interval '8 hours');

-- ---------------------------------------------------------------------------
-- 1. Eventos (ptmarket_app pela audit_append). T1/S1: 25 'orders.update' (paginação); T1/S3: encomenda O1 (alvo)
--    + pagamento com changes.order_id = O1 + encomenda O2 (engodo) + refunds_create/refundsxcreate (escape do _);
--    T2/S2 (ator M2): 3 eventos (filtros e adulteração); T3: 3 eventos (buraco).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000002a0a01';
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-0000002a0c01';
SELECT count(audit.audit_append('orders.update', 'order', 'x' || g, 'success', NULL, NULL,
                                '00000000-0000-7000-8000-0000002a0501'::uuid))
FROM generate_series(1, 25) AS g;
SELECT audit.audit_append('orders.create', 'order', '00000000-0000-7000-8000-0000002a0d01', 'success', NULL, NULL,
    '00000000-0000-7000-8000-0000002a0503'::uuid) AS ord_target_id \gset
SELECT audit.audit_append('payments.capture', 'payment', 'p1', 'error', NULL,
    '{"order_id": "00000000-0000-7000-8000-0000002a0d01"}'::jsonb,
    '00000000-0000-7000-8000-0000002a0503'::uuid) AS ord_pay_id \gset
SELECT audit.audit_append('orders.create', 'order', '00000000-0000-7000-8000-0000002a0d02', 'success', NULL,
    '{"order_id": "00000000-0000-7000-8000-0000002a0d02"}'::jsonb, '00000000-0000-7000-8000-0000002a0503'::uuid);
SELECT audit.audit_append('refunds_create', 'refund', 'r1', 'success', NULL, NULL,
    '00000000-0000-7000-8000-0000002a0503'::uuid) AS refund_us_id \gset
SELECT audit.audit_append('refundsxcreate', 'refund', 'r2', 'success', NULL, NULL,
    '00000000-0000-7000-8000-0000002a0503'::uuid);
SET app.current_tenant_id = '00000000-0000-7000-8000-0000002a0a02';
SET app.actor_id = '00000000-0000-7000-8000-0000002a0c02';
SELECT count(audit.audit_append('stores.update', 'store', 's2', 'success', NULL, NULL,
                                '00000000-0000-7000-8000-0000002a0502'::uuid))
FROM generate_series(1, 3);
SET app.current_tenant_id = '00000000-0000-7000-8000-0000002a0a03';
SET app.actor_id = '00000000-0000-7000-8000-0000002a0c03';
SELECT count(audit.audit_append('stores.update', 'store', 's3', 'success', NULL, NULL, NULL))
FROM generate_series(1, 3);
RESET app.current_tenant_id;
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 2. Porta (42501): contexto errado, conta sem super_admin/TOTP, sessão sem 2FA/revogada/expirada/de outro/impersonada.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE gate_cases (label text, actor_type text, actor_id text, session_id text, impersonator text);
INSERT INTO gate_cases VALUES
    ('merchant',                  'merchant', '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5001', ''),
    ('customer',                  'customer', '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5001', ''),
    ('sem actor_type',            '',         '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5001', ''),
    ('super_admin sem TOTP',      'admin',    '00000000-0000-7000-8000-0000002a0002', '00000000-0000-7000-8000-0000002a5005', ''),
    ('sem papel super_admin',     'admin',    '00000000-0000-7000-8000-0000002a0003', '00000000-0000-7000-8000-0000002a5006', ''),
    ('sessão sem mfa_verified_at','admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5002', ''),
    ('sessão revogada',           'admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5003', ''),
    ('sessão expirada',           'admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5004', ''),
    ('sessão impersonada',        'admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5007', ''),
    ('sessão de outro utilizador','admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5005', ''),
    ('sem sessão no contexto',    'admin',    '00000000-0000-7000-8000-0000002a0001', '',                                     ''),
    ('sessão que não é uuid',     'admin',    '00000000-0000-7000-8000-0000002a0001', 'x',                                    ''),
    ('sem actor_id',              'admin',    '',                                     '00000000-0000-7000-8000-0000002a5001', ''),
    ('app.impersonator_id posto', 'admin',    '00000000-0000-7000-8000-0000002a0001', '00000000-0000-7000-8000-0000002a5001',
                                                                                     '00000000-0000-7000-8000-0000002a0002');
GRANT SELECT ON gate_cases TO ptmarket_app;

SET ROLE ptmarket_app;
DO $$
DECLARE
    c record;
BEGIN
    FOR c IN SELECT * FROM pg_temp.gate_cases LOOP
        PERFORM set_config('app.actor_type', c.actor_type, true);
        PERFORM set_config('app.actor_id', c.actor_id, true);
        PERFORM set_config('app.session_id', c.session_id, true);
        PERFORM set_config('app.impersonator_id', c.impersonator, true);
        PERFORM pg_temp.expect_error(
            $q$SELECT pg_temp.grab('gate', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
            '42501', 'porta recusa: ' || c.label);
    END LOOP;
END
$$;
RESET app.impersonator_id;

-- Contexto válido de super_admin (A, sessão 5001) para o resto.
SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-0000002a0001';
SET app.session_id = '00000000-0000-7000-8000-0000002a5001';

-- A app não chama a selada diretamente; nem a sessão válida lhe dá isso.
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL, NULL,
                                             NULL, NULL, 10)$q$,
    '42501', 'ptmarket_app sem EXECUTE em audit.admin_read_events');

-- ---------------------------------------------------------------------------
-- 3. Validação (22023), já com a porta aberta.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '32 days', now(), NULL, NULL, NULL, NULL,
                                                       NULL, NULL, NULL, NULL, 10)$q$,
    '22023', 'janela > 31 dias');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now(), now(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
    '22023', 'p_from = p_to');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(NULL, now(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 10)$q$,
    '22023', 'p_from NULL');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL,
                                                       NULL, NULL, NULL, 101)$q$,
    '22023', 'limit 101');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL,
                                                       NULL, NULL, NULL, 0)$q$,
    '22023', 'limit 0');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL,
                                                       NULL, NULL, NULL, NULL)$q$,
    '22023', 'limit NULL');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL,
                                                       'orders%', NULL, NULL, NULL, 10)$q$,
    '22023', 'prefixo com %');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL,
                                                       'Orders', NULL, NULL, NULL, 10)$q$,
    '22023', 'prefixo com maiúscula');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL,
                                                       '', NULL, NULL, NULL, 10)$q$,
    '22023', 'prefixo vazio');
SELECT pg_temp.expect_error(
    format($q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL,
                                                       %L, NULL, NULL, NULL, 10)$q$, repeat('a', 101)),
    '22023', 'prefixo com 101 caracteres');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL,
                                                       'ok', NULL, NULL, 10)$q$,
    '22023', 'outcome fora da lista');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL,
                                                       NULL, now(), NULL, 10)$q$,
    '22023', 'cursor só com created_at');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.identity_admin_read_events(now() - interval '31 days', now(), NULL, NULL, NULL,
                                                              NULL, NULL, NULL, NULL, NULL, 1)$q$,
    1, 'janela de 31 dias exatos e limit 1 aceites');

-- ---------------------------------------------------------------------------
-- 4. Filtros e paginação (como ptmarket_app; comparação como superuser).
-- ---------------------------------------------------------------------------
SELECT pg_temp.grab('tenant',  '00000000-0000-7000-8000-0000002a0a02', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('store',   NULL, '00000000-0000-7000-8000-0000002a0502', NULL, NULL, NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('actor',   NULL, NULL, '00000000-0000-7000-8000-0000002a0c02', NULL, NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('order',   NULL, NULL, NULL, '00000000-0000-7000-8000-0000002a0d01', NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('payerr',  '00000000-0000-7000-8000-0000002a0a01', NULL, NULL, NULL, 'payments.', 'error', NULL,
                    NULL, 100);
SELECT pg_temp.grab('refund_', '00000000-0000-7000-8000-0000002a0a01', NULL, NULL, NULL, 'refunds_', NULL, NULL, NULL,
                    100);
DO $$
DECLARE
    v_at timestamptz;
    v_id uuid;
BEGIN
    FOR i IN 1 .. 4 LOOP
        PERFORM pg_temp.grab('page' || i, NULL, '00000000-0000-7000-8000-0000002a0501', NULL, NULL, NULL, NULL,
                             v_at, v_id, 10);
        SELECT r.created_at, r.id INTO v_at, v_id
        FROM pg_temp.res r WHERE r.label = 'page' || i ORDER BY r.ord DESC LIMIT 1;
    END LOOP;
END
$$;
RESET ROLE;

-- Conjuntos esperados (superuser lê audit.*).
CREATE TEMP TABLE expected AS
SELECT 'tenant' AS label, e.id FROM audit.audit_events e WHERE e.tenant_id = '00000000-0000-7000-8000-0000002a0a02'
UNION ALL
SELECT 'store', e.id FROM audit.audit_events e WHERE e.store_id = '00000000-0000-7000-8000-0000002a0502'
UNION ALL
SELECT 'actor', e.id FROM audit.audit_events e WHERE e.actor_id = '00000000-0000-7000-8000-0000002a0c02'
UNION ALL
SELECT 'order', v.id FROM (VALUES (:'ord_target_id'::uuid), (:'ord_pay_id'::uuid)) v(id)
UNION ALL
SELECT 'payerr', :'ord_pay_id'::uuid
UNION ALL
SELECT 'refund_', :'refund_us_id'::uuid
UNION ALL
SELECT 'pages', e.id FROM audit.audit_events e WHERE e.store_id = '00000000-0000-7000-8000-0000002a0501';

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM expected GROUP BY label HAVING label = 'tenant'$q$, 3, 'esperados: 3 eventos em T2');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM expected WHERE label = 'pages'$q$, 25, 'esperados: 25 eventos em S1');

-- Por filtro: as linhas devolvidas são exatamente as esperadas (diferença simétrica com multiplicidade = 0).
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM (
               (SELECT id FROM res WHERE label = %1$L EXCEPT ALL SELECT id FROM expected WHERE label = %1$L)
               UNION ALL
               (SELECT id FROM expected WHERE label = %1$L EXCEPT ALL SELECT id FROM res WHERE label = %1$L)) d$q$,
           l.label),
    0, 'filtro ' || l.label || ' devolve só os eventos certos')
FROM (VALUES ('tenant'), ('store'), ('actor'), ('order'), ('payerr'), ('refund_')) l(label);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label IN ('tenant', 'store', 'actor', 'order', 'payerr', 'refund_')$q$,
    3 + 3 + 3 + 2 + 1 + 1, 'filtros: contagens 3/3/3/2/1/1 (engodo O2 e refundsxcreate fora)');

-- Paginação: 10 + 10 + 5 + 0, ordem (created_at, id) DESC dentro e entre páginas, união = as 25, sem repetidos.
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES ('page1', 10), ('page2', 10), ('page3', 5), ('page4', 0)) v(l, n)
       WHERE (SELECT count(*) FROM res WHERE label = v.l) <> v.n$q$,
    0, 'páginas com 10, 10, 5 e 0 linhas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           (SELECT id FROM res WHERE label LIKE 'page%' EXCEPT ALL SELECT id FROM expected WHERE label = 'pages')
           UNION ALL
           (SELECT id FROM expected WHERE label = 'pages' EXCEPT ALL SELECT id FROM res WHERE label LIKE 'page%')) d$q$,
    0, '3 páginas pelo cursor: as 25, sem repetidos nem buracos');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (
           SELECT (created_at, id) < lag((created_at, id)) OVER (ORDER BY label, ord) AS ok, label, ord
           FROM res WHERE label LIKE 'page%') x
       WHERE NOT x.ok$q$,
    0, 'ordem (created_at, id) DESC contínua entre páginas');

-- Colunas: changes devolvido como gravado; chain_seq e chain_ok certos antes da adulteração.
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM res r JOIN audit.audit_events e ON e.id = r.id
              WHERE r.label = 'order' AND r.id = %L
                AND r.changes = e.changes AND r.chain_seq = e.chain_seq AND r.tenant_id = e.tenant_id
                AND r.store_id = e.store_id AND r.actor_type = e.actor_type AND r.outcome = e.outcome$q$,
           :'ord_pay_id'),
    1, 'linha devolvida igual à gravada (changes, chain_seq, tenant, loja, ator, outcome)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE chain_ok IS DISTINCT FROM true$q$, 0, 'chain_ok = true em todas antes da adulteração');

-- ---------------------------------------------------------------------------
-- 5. Selada chamada por ptmarket_identity: a guarda de app.actor_type também está lá.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_identity;
SET app.actor_type = 'merchant';
SELECT pg_temp.expect_error(
    $q$SELECT * FROM audit.admin_read_events(now() - interval '1 day', now(), NULL, NULL, NULL, NULL, NULL, NULL,
                                             NULL, NULL, 10)$q$,
    '42501', 'selada recusa app.actor_type <> admin (mesmo a ptmarket_identity)');
SET app.actor_type = 'admin';
SELECT pg_temp.expect_error(
    $q$SELECT count(*) FROM audit.audit_events$q$, '42501', 'ptmarket_identity não lê audit.audit_events');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. Adulteração (dono NOLOGIN, trigger desligado SÓ nesta transação). T2: hash do seq 1 (⇒ seq 1 'hash' e seq 2
--    'link') e reason do seq 3 (⇒ seq 3 'hash'). T3: apaga o seq 2 (⇒ seq 3 sem anterior, com linhas mais antigas).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_audit_owner;
ALTER TABLE audit.audit_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE audit.audit_events DISABLE TRIGGER audit_events_no_update_delete;
GRANT UPDATE, DELETE ON audit.audit_events TO CURRENT_USER;
UPDATE audit.audit_events SET hash = sha256('x'::bytea)
WHERE tenant_id = '00000000-0000-7000-8000-0000002a0a02' AND chain_seq = 1;
UPDATE audit.audit_events SET reason = 'adulterado'
WHERE tenant_id = '00000000-0000-7000-8000-0000002a0a02' AND chain_seq = 3;
DELETE FROM audit.audit_events
WHERE tenant_id = '00000000-0000-7000-8000-0000002a0a03' AND chain_seq = 2;
ALTER TABLE audit.audit_events ENABLE TRIGGER audit_events_no_update_delete;
REVOKE UPDATE, DELETE ON audit.audit_events FROM CURRENT_USER;
ALTER TABLE audit.audit_events FORCE ROW LEVEL SECURITY;
RESET ROLE;

SET ROLE ptmarket_app;
SELECT pg_temp.grab('tamper2', '00000000-0000-7000-8000-0000002a0a02', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('tamper3', '00000000-0000-7000-8000-0000002a0a03', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100);
SELECT pg_temp.grab('tamper1', '00000000-0000-7000-8000-0000002a0a01', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 100);
RESET ROLE;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tamper2' AND NOT chain_ok$q$,
    3, 'T2 adulterada: seq 1 (hash), seq 2 (elo) e seq 3 (hash) com chain_ok = false');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tamper3' AND chain_ok IS DISTINCT FROM (chain_seq = 1)$q$,
    0, 'T3 sem o seq 2: seq 1 true, seq 3 false (falta o anterior e há linhas mais antigas)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tamper3'$q$, 2, 'T3: 2 linhas depois do DELETE');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'tamper1' AND chain_ok IS DISTINCT FROM true$q$,
    0, 'T1 intacta: chain_ok = true em todas');

-- ---------------------------------------------------------------------------
-- 7. Índices: o texto que a selada executa (audit._admin_read_events_sql) com tenant, loja, ator e encomenda usa
--    os índices da 0008/0015, sem Seq Scan. enable_seqscan = off: BD de teste com poucas linhas.
-- ---------------------------------------------------------------------------
SELECT audit._admin_read_events_sql(true, false, false, false, false, false, true) AS q_tenant,
       audit._admin_read_events_sql(false, true, false, false, true, true, false) AS q_store,
       audit._admin_read_events_sql(false, false, true, false, false, false, false) AS q_actor,
       audit._admin_read_events_sql(false, false, false, true, false, false, false) AS q_order \gset
SET LOCAL enable_seqscan = off;
SET ROLE ptmarket_audit_writer;
PREPARE q_tenant(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_tenant;
PREPARE q_store(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_store;
PREPARE q_actor(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_actor;
PREPARE q_order(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer) AS :q_order;
SELECT pg_temp.expect_index_plan(
    $q$EXECUTE q_tenant(now() - interval '30 days', now() + interval '1 day', '00000000-0000-7000-8000-0000002a0a01',
                        NULL, NULL, NULL, NULL, NULL, now(), '00000000-0000-7000-8000-0000002affff', 50)$q$,
    ARRAY['audit.audit_events_tenant_created_idx'], 'timeline por tenant (com cursor) usa (tenant_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$EXECUTE q_store(now() - interval '30 days', now() + interval '1 day', NULL,
                       '00000000-0000-7000-8000-0000002a0501', NULL, NULL, 'orders.%', 'success', NULL, NULL, 50)$q$,
    ARRAY['audit.audit_events_store_created_idx'], 'timeline por loja (com prefixo e outcome) usa (store_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$EXECUTE q_actor(now() - interval '30 days', now() + interval '1 day', NULL, NULL,
                       '00000000-0000-7000-8000-0000002a0c01', NULL, NULL, NULL, NULL, NULL, 50)$q$,
    ARRAY['audit.audit_events_actor_created_idx'], 'timeline por ator usa (actor_id, created_at)');
SELECT pg_temp.expect_index_plan(
    $q$EXECUTE q_order(now() - interval '30 days', now() + interval '1 day', NULL, NULL, NULL,
                       '00000000-0000-7000-8000-0000002a0d01', NULL, NULL, NULL, NULL, 50)$q$,
    ARRAY['audit.audit_events_target_created_idx', 'audit.audit_events_order_created_idx'],
    'timeline por encomenda usa (target_type, target_id, created_at) + ((changes->>order_id), created_at)');
DEALLOCATE q_tenant;
DEALLOCATE q_store;
DEALLOCATE q_actor;
DEALLOCATE q_order;
RESET ROLE;
RESET enable_seqscan;

-- ---------------------------------------------------------------------------
-- 8. Selagem, donos e grants; guarda de memberships da 0022 para ptmarket_identity.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name = '0025_admin_read_events'$q$,
    1, 'alteração aprovada 0025_admin_read_events aplicada');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure
         AND prosecdef AND proowner = 'ptmarket_audit_writer'::regrole
         AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'audit.admin_read_events: DEFINER, dono ptmarket_audit_writer, search_path fixo');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'audit._admin_read_events_sql(boolean, boolean, boolean, boolean, boolean, boolean, boolean)'::regprocedure
         AND NOT prosecdef AND provolatile = 'i' AND proowner = 'ptmarket_audit_owner'::regrole$q$,
    1, 'audit._admin_read_events_sql: INVOKER, IMMUTABLE, dono ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure
         AND prosecdef AND proowner = 'ptmarket_identity'::regrole
         AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'public.identity_admin_read_events: DEFINER, dono ptmarket_identity, search_path fixo');
-- EXECUTE: só o par previsto (além do dono).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES
           ('audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)', 'ptmarket_identity'),
           ('audit._admin_read_events_sql(boolean, boolean, boolean, boolean, boolean, boolean, boolean)', 'ptmarket_audit_writer'),
           ('public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)', 'ptmarket_app')
       ) v(f, r)
       JOIN pg_proc p ON p.oid = v.f::regprocedure
       CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
       WHERE a.grantee <> p.proowner AND NOT (a.grantee = v.r::regrole AND a.privilege_type = 'EXECUTE')$q$,
    0, 'EXECUTE: selada só ptmarket_identity; construtor só writer; porta só ptmarket_app (nem PUBLIC)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES ('ptmarket_migrator'), ('ptmarket_app'), ('ptmarket_worker')) v(r)
       WHERE has_function_privilege(v.r, 'audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)', 'EXECUTE')
          OR has_function_privilege(v.r, 'audit._admin_read_events_sql(boolean, boolean, boolean, boolean, boolean, boolean, boolean)', 'EXECUTE')
          OR (v.r <> 'ptmarket_app' AND has_function_privilege(v.r, 'public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)', 'EXECUTE'))$q$,
    0, 'migrator, app e worker sem EXECUTE nas funções de audit; migrator e worker sem a porta');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE has_schema_privilege('ptmarket_identity', 'audit', 'USAGE')
                       AND NOT has_schema_privilege('ptmarket_identity', 'audit', 'CREATE')
                       AND NOT has_schema_privilege('ptmarket_identity', 'public', 'CREATE')$q$,
    1, 'ptmarket_identity: USAGE em audit, sem CREATE em audit nem em public');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'public.user_roles'::regclass AND polname = 'identity_lookup' AND polcmd = 'r'
         AND polroles = ARRAY['ptmarket_identity'::regrole::oid]$q$,
    1, 'user_roles: política identity_lookup só FOR SELECT TO ptmarket_identity');
-- Guarda B da 0022 (mesmos critérios): ptmarket_identity não é membro de nada; só o migrator é membro dele, sem
-- INHERIT (ADMIN implícito com grantor superuser, ou SET sem ADMIN).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_auth_members m
       LEFT JOIN pg_roles g ON g.oid = m.grantor
       WHERE m.member = 'ptmarket_identity'::regrole
          OR (m.roleid = 'ptmarket_identity'::regrole
              AND NOT (m.member = 'ptmarket_migrator'::regrole
                       AND NOT m.inherit_option
                       AND ((m.admin_option AND COALESCE(g.rolsuper, false))
                            OR (m.set_option AND NOT m.admin_option))))$q$,
    0, 'guarda de memberships da 0022 continua a passar para ptmarket_identity');
SET ROLE ptmarket_migrator;
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid,
           p_store_id uuid, p_actor_id uuid, p_order_id uuid, p_action_prefix text, p_outcome text,
           p_cursor_at timestamptz, p_cursor_id uuid, p_limit integer)
       RETURNS TABLE (id uuid) LANGUAGE sql AS 'SELECT NULL::uuid'$q$,
    '42501', 'migrator não substitui audit.admin_read_events (selada)');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit._admin_read_events_sql(p_tenant boolean, p_store boolean, p_actor boolean,
           p_order boolean, p_action boolean, p_outcome boolean, p_cursor boolean)
       RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT ''SELECT 1'''$q$,
    '42501', 'migrator não substitui audit._admin_read_events_sql (selada)');
RESET ROLE;
DO $$ BEGIN RAISE NOTICE 'OK: audit_seal() continua a passar'; END $$;

ROLLBACK;
