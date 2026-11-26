-- run.sh: superuser
-- Teste da 0020 (cartão 02/03e): máscara v2 (vetores partilhados docs/testdata/redaction-vectors.json, passados
-- pelo run.sh como :'redaction_vectors'), _chain_insert como único ponto de máscara, iban_change pela L1 (medido
-- antes da máscara), tolerância explícita (sem pg_trigger_depth; PG_CONTEXT ancorado) e REVOKE TEMPORARY.
-- Corre como superuser só para assumir papéis NOLOGIN, criar tenants e mexer em audit_admin.sealed_changes (em
-- savepoint); cada asserção é feita com SET ROLE do papel em causa. Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- L2 ligada só na secção 5

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

-- Erro com SQLSTATE p_state; mensagem/detalhe/dica/contexto sem p_secret e mensagem com p_must.
CREATE FUNCTION pg_temp.expect_error_msg(p_sql text, p_state text, p_secret text, p_must text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state  text;
    v_msg    text;
    v_detail text;
    v_hint   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT,
                                v_detail = PG_EXCEPTION_DETAIL, v_hint = PG_EXCEPTION_HINT;
        IF v_state = p_state
           AND strpos(concat_ws(' ', v_msg, v_detail, v_hint), p_secret) = 0
           AND strpos(v_msg, p_must) > 0 THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado % sem o valor e com "%", obtido %: %)', p_label, p_state, p_must,
            v_state, left(v_msg, 200);
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

-- Lista vazia = passou; senão falha com os ids (nunca com os valores).
CREATE FUNCTION pg_temp.expect_none(p_sql text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_bad text;
BEGIN
    EXECUTE p_sql INTO v_bad;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'FALHOU: % (%)', p_label, v_bad;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Texto não compressível com p_chars caracteres.
CREATE FUNCTION pg_temp.blob(p_chars int)
RETURNS text LANGUAGE sql AS $$
    SELECT left(string_agg(md5(i::text), '' ORDER BY i), p_chars) FROM generate_series(1, p_chars / 32 + 1) AS i
$$;

-- Saída da máscara para um vetor: text → audit._redact_text; json → audit.audit_redact (tabela neutra).
CREATE FUNCTION pg_temp.vec_out(p_kind text, p_input jsonb)
RETURNS jsonb LANGUAGE sql AS $$
    SELECT CASE p_kind
        WHEN 'text' THEN to_jsonb(audit._redact_text(p_input #>> '{}'))
        ELSE audit.audit_redact('vectors'::text, p_input) END
$$;

-- Texto pesquisável da saída (string sem aspas JSON; objeto como texto JSON).
CREATE FUNCTION pg_temp.vec_text(p_value jsonb)
RETURNS text LANGUAGE sql AS $$
    SELECT CASE WHEN jsonb_typeof(p_value) = 'string' THEN p_value #>> '{}' ELSE p_value::text END
$$;

-- ---------------------------------------------------------------------------
-- 1. Alteração selada 0020_mask_v2, _chain_insert de 3 argumentos, allowlist e cadeia linear.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes c JOIN audit_admin.sealed_changes_applied a USING (name)
       WHERE c.name = '0020_mask_v2' AND c.requires = '0015_critical_timeline'
         AND c.sha256 = encode(sha256(convert_to(c.sql, 'UTF8')), 'hex')
         AND c.sha256 = '11ddb2a27f1e3c1e3b6e1615bda42acf3937a166cb604761adfb0b0a90cff237'$q$,
    1, '0020_mask_v2 aprovada (requires 0015_critical_timeline), aplicada, com o sha256 que a 0020 dispara');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc WHERE pronamespace = 'audit'::regnamespace AND proname = '_chain_insert'$q$,
    1, '_chain_insert: uma só assinatura (a de 2 argumentos desapareceu)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid = 'audit._chain_insert(audit.audit_events,boolean,boolean)'::regprocedure
         AND p.prosecdef AND r.rolname = 'ptmarket_audit_writer'
         AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee <> p.proowner)
         AND strpos(p.prosrc, 'pg_trigger_depth') = 0$q$,
    1, '_chain_insert(…, boolean, boolean): DEFINER do writer, sem EXECUTE para mais ninguém, sem pg_trigger_depth()');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE pronamespace = 'audit'::regnamespace
         AND (strpos(prosrc, '_chain_insert(v_row, false)') > 0 OR strpos(prosrc, '_chain_insert(v_row, true)') > 0
              OR strpos(prosrc, 'pg_trigger_depth') > 0)$q$,
    0, 'nenhuma função de audit chama a assinatura antiga nem usa pg_trigger_depth()');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid IN ('audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'::regprocedure,
                     'audit.audit_row_trigger()'::regprocedure)
         AND strpos(prosrc, 'audit_redact') > 0$q$,
    0, 'audit_append_db e audit_row_trigger já não mascaram antes (changes em cru até _chain_insert)');

SAVEPOINT seal;
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT audit_admin.audit_seal();
RESET SESSION AUTHORIZATION;
-- Sobrecarga plantada com a assinatura antiga → a selagem recusa (fora da allowlist depois da 0020).
CREATE FUNCTION audit._chain_insert(p_row audit.audit_events, p_dedupe boolean)
RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT NULL::uuid';
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT pg_temp.expect_error($q$SELECT audit_admin.audit_seal()$q$, 'P0001',
    'audit_seal recusa a _chain_insert de 2 argumentos depois da 0020');
RESET SESSION AUTHORIZATION;
ROLLBACK TO SAVEPOINT seal;

SAVEPOINT chain;
INSERT INTO audit_admin.sealed_changes (name, requires, sql, sha256) VALUES
    ('zz_03e_a', '0020_mask_v2', 'SELECT 1', encode(sha256(convert_to('SELECT 1', 'UTF8')), 'hex')),
    ('zz_03e_b', 'zz_03e_a',     'SELECT 2', encode(sha256(convert_to('SELECT 2', 'UTF8')), 'hex'));
SELECT encode(sha256(convert_to('SELECT 1', 'UTF8')), 'hex') AS sha_a,
       encode(sha256(convert_to('SELECT 2', 'UTF8')), 'hex') AS sha_b \gset
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit_admin.audit_upgrade('zz_03e_b'::text, %L::text)$q$, :'sha_b'),
    'P0001', '__nada__', 'exige zz_03e_a', 'audit_upgrade fora de ordem (anterior não aplicada) → erro');
SELECT audit_admin.audit_upgrade('zz_03e_a'::text, :'sha_a'::text);
SELECT audit_admin.audit_upgrade('zz_03e_b'::text, :'sha_b'::text);
SELECT audit_admin.audit_seal();
RESET SESSION AUTHORIZATION;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name IN ('zz_03e_a', 'zz_03e_b')$q$,
    2, 'audit_upgrade pela ordem certa passa; audit_seal() passa');
ROLLBACK TO SAVEPOINT chain;

-- ---------------------------------------------------------------------------
-- 2. Vetores (docs/testdata/redaction-vectors.json): todos os que têm "db" em layers.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE vectors AS
    SELECT x.n, x.v ->> 'id' AS id, x.v ->> 'kind' AS kind, x.v -> 'input' AS input,
           x.v -> 'must_not_contain' AS must_not_contain, (x.v ->> 'must_equal_input')::boolean AS must_equal_input,
           x.v -> 'layers' AS layers
    FROM jsonb_array_elements(:'redaction_vectors'::jsonb) WITH ORDINALITY AS x(v, n);
GRANT SELECT ON vectors TO ptmarket_app, ptmarket_audit_writer;

SELECT pg_temp.expect_none(
    $q$SELECT string_agg(COALESCE(id, '#' || n), ', ') FROM vectors
       WHERE id IS NULL OR kind NOT IN ('text', 'json') OR input IS NULL
          OR (kind = 'text' AND jsonb_typeof(input) <> 'string')
          OR (kind = 'json' AND jsonb_typeof(input) NOT IN ('object', 'array'))
          OR jsonb_typeof(must_not_contain) <> 'array' OR must_equal_input IS NULL
          OR jsonb_typeof(layers) <> 'array' OR jsonb_array_length(layers) = 0
          OR NOT layers <@ '["db", "rust", "go"]'::jsonb
          OR (must_equal_input AND jsonb_array_length(must_not_contain) > 0)
          OR id IN (SELECT id FROM vectors GROUP BY id HAVING count(*) > 1)$q$,
    'vetores: formato {id, kind, input, must_not_contain, must_equal_input, layers}, ids únicos');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(r.id, ', ') FROM unnest(ARRAY[
           'key-tax_id', 'key-vat_id', 'key-national_id', 'key-taxId-camel', 'key-vatNumber-camel', 'key-mobile',
           'key-nib', 'key-accountNumber-camel', 'key-cardPan-camel', 'pair-path-last-segment', 'pair-k-v',
           'tuple-nif', 'value-nif-valid', 'value-dni-valid', 'value-phone-e164-pt', 'value-pan-luhn-spaces',
           'value-iban-lowercase', 'value-iban-dashes', 'value-iban-dots', 'value-iban-nbsp',
           'value-iban-double-spaces', 'value-nib-21-digits', 'clear-store_id', 'clear-uuid-digits-only',
           'clear-iso-datetime', 'clear-nif-wrong-check-digit', 'clear-16-digits-no-luhn', 'clear-title']) AS r(id)
       WHERE NOT EXISTS (SELECT 1 FROM vectors v WHERE v.id = r.id AND v.layers ? 'db')$q$,
    'vetores: os casos do "Feito quando" existem e correm na BD');

SET ROLE ptmarket_app; -- audit_redact e _redact_text são INVOKER: a app usa-as (como o Rust usaria a sua)
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(v.id, ', ' ORDER BY v.n) FROM vectors v
       CROSS JOIN LATERAL (SELECT pg_temp.vec_out(v.kind, v.input) AS o) AS m
       WHERE v.layers ? 'db' AND v.must_equal_input AND m.o IS DISTINCT FROM v.input$q$,
    'vetores em claro: saída = entrada');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(v.id, ', ' ORDER BY v.n) FROM vectors v
       CROSS JOIN LATERAL (SELECT pg_temp.vec_out(v.kind, v.input) AS o) AS m
       WHERE v.layers ? 'db' AND NOT v.must_equal_input
         AND (m.o IS NOT DISTINCT FROM v.input
              OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(v.must_not_contain) AS c(s)
                         WHERE strpos(pg_temp.vec_text(m.o), c.s) > 0))$q$,
    'vetores mascarados: saída ≠ entrada e sem nenhum must_not_contain');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(v.id, ', ' ORDER BY v.n) FROM vectors v
       CROSS JOIN LATERAL (SELECT pg_temp.vec_out(v.kind, v.input) AS o) AS m
       WHERE v.layers ? 'db' AND pg_temp.vec_out(v.kind, m.o) IS DISTINCT FROM m.o$q$,
    'vetores: a segunda passagem da máscara não altera nada (idempotente)');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(v.id, ', ' ORDER BY v.n) FROM vectors v
       WHERE v.layers ? 'db' AND v.kind = 'text'
         AND audit.audit_redact('vectors'::text, jsonb_build_object('note', v.input))
             IS DISTINCT FROM jsonb_build_object('note', pg_temp.vec_out(v.kind, v.input))$q$,
    'vetores de texto: o mesmo resultado sob uma chave neutra de changes');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FILTER (WHERE layers ? 'db') FROM vectors$q$,
    (SELECT count(*) FROM jsonb_array_elements(:'redaction_vectors'::jsonb) e WHERE e -> 'layers' ? 'db'),
    'o teste correu todos os vetores com "db" em layers');
SELECT pg_temp.expect_value(
    $q$SELECT (count(*) >= 50)::int FROM vectors WHERE layers ? 'db'$q$, 1, 'vetores: pelo menos 50 casos na BD');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. Ponta a ponta: nada em cru chega a audit_events (app e worker), por chaves neutras c<n>.
-- ---------------------------------------------------------------------------
-- Desde a 0033 as lojas só vivem em tenants national_portal.
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type) VALUES
    ('00000000-0000-7000-8000-0000000003ea', 'mask-03e', 'mask-03e.teste.invalid', 'Mask 03e', 'national_portal');
SELECT jsonb_object_agg('c' || n, input) AS e2e FROM vectors
 WHERE layers ? 'db' AND NOT must_equal_input \gset
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000003ea', true);
SELECT set_config('app.actor_type', 'merchant', true);
SELECT audit.audit_append('test.vectors'::text, 'vectors'::text, 'v1'::text, 'success'::text,
    'NIF 512345678 e IBAN pt50 0002 0123 1234 5678 9015 4'::text, :'e2e'::jsonb, NULL::uuid) AS app_ev \gset
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT audit.audit_append_event(jsonb_build_object(
    'id', uuidv7(), 'tenant_id', '00000000-0000-7000-8000-0000000003ea', 'store_id', NULL,
    'actor_type', 'merchant', 'actor_id', NULL, 'actor_label', '+351 912 345 678', 'impersonator_id', NULL,
    'action', 'test.vectors_worker', 'target_type', 'vectors', 'target_id', 'v2', 'outcome', 'success',
    'reason', 'cartão 4111 1111 1111 1111', 'changes', :'e2e'::jsonb,
    'request_id', '00000000-0000-7000-8000-0000000003f1', 'ip', NULL, 'user_agent_hash', NULL,
    'occurred_at', to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"')));
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(DISTINCT v.id || ' em ' || e.action, ', ') FROM audit.audit_events e
       CROSS JOIN vectors v
       CROSS JOIN LATERAL jsonb_array_elements_text(v.must_not_contain) AS c(s)
       WHERE e.action IN ('test.vectors', 'test.vectors_worker') AND v.layers ? 'db'
         AND strpos(concat_ws(' ', e.changes::text, e.reason, e.actor_label), c.s) > 0$q$,
    'app e worker: nenhum valor em cru dos vetores em audit_events (changes, reason, actor_label)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action IN ('test.vectors', 'test.vectors_worker') AND reason IN ('[pii]', '[redacted]')$q$,
    2, 'reason com NIF/IBAN (app) e com PAN (worker) mascarados por valor');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. iban_change pela L1: UPDATE stores SET iban (app com ator e migrator) → stores.update + 1 alerta sem IBAN,
--    mesmo com os mesmos 4 últimos dígitos; outra coluna → sem iban_change.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE alert_base AS SELECT id FROM audit.audit_alerts;
CREATE TEMP TABLE event_base AS SELECT id FROM audit.audit_events;
GRANT SELECT ON alert_base, event_base TO ptmarket_audit_writer;
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000003ea', true);
SELECT set_config('app.actor_type', 'merchant', true);
SELECT set_config('app.actor_id', '00000000-0000-7000-8000-0000000003e9', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000003c1', '00000000-0000-7000-8000-0000000003ea',
     'Loja 03e', 'loja-03e', 'Loja 03e Lda', '512345678', 'PT50000201231234567890154', 'l@teste.invalid');
-- Mesmos 4 últimos (0154), outro IBAN: com a máscara antes, os dois pareciam iguais (****0154).
UPDATE stores SET iban = 'PT50003501230000123450154' WHERE id = '00000000-0000-7000-8000-0000000003c1';
UPDATE stores SET name = 'Loja 03e renomeada' WHERE id = '00000000-0000-7000-8000-0000000003c1';
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.actor_id', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;
-- Migrator (caminho db): dono de stores; sem FORCE RLS só nesta transação (a política é só da app).
ALTER TABLE stores NO FORCE ROW LEVEL SECURITY;
SET SESSION AUTHORIZATION ptmarket_migrator;
UPDATE stores SET iban = 'PT50000201231234567890154' WHERE id = '00000000-0000-7000-8000-0000000003c1';
UPDATE stores SET name = 'Loja 03e (db)' WHERE id = '00000000-0000-7000-8000-0000000003c1';
RESET SESSION AUTHORIZATION;
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000003ea', true);
SELECT set_config('app.actor_type', 'merchant', true);
DELETE FROM stores WHERE id = '00000000-0000-7000-8000-0000000003c1';
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;
ALTER TABLE stores FORCE ROW LEVEL SECURITY;

-- Leitura como superuser: nenhum papel lê audit_events e audit_alerts ao mesmo tempo (writer só insere alertas).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e JOIN audit.audit_alerts a ON a.id = e.id
       WHERE e.id NOT IN (SELECT id FROM event_base) AND e.action = 'stores.update' AND e.actor_type = 'merchant'
         AND e.changes -> 'after' ->> 'iban' = '****0154' AND e.changes -> 'before' ->> 'iban' = '****0154'
         AND a.kind = 'iban_change' AND a.event_type = 'audit.critical'
         AND NOT a.payload ? 'changes' AND NOT a.payload ? 'reason'$q$,
    1, 'app: UPDATE stores SET iban (mesmos 4 últimos) → stores.update + 1 alerta iban_change sem changes/reason');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e JOIN audit.audit_alerts a ON a.id = e.id
       WHERE e.id NOT IN (SELECT id FROM event_base) AND e.action = 'stores.update' AND e.actor_type = 'db'
         AND e.actor_label = 'ptmarket_migrator' AND e.changes -> 'after' ->> 'iban' = '****0154'
         AND a.kind = 'iban_change' AND NOT a.payload ? 'changes' AND NOT a.payload ? 'reason'$q$,
    1, 'migrator: UPDATE stores SET iban → stores.update (db) + 1 alerta iban_change');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e JOIN audit.audit_alerts a ON a.id = e.id
       WHERE e.id NOT IN (SELECT id FROM event_base) AND e.action = 'stores.insert' AND a.kind = 'iban_change'$q$,
    1, 'INSERT com IBAN conta como iban_change');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events e
       WHERE e.id NOT IN (SELECT id FROM event_base) AND e.target_id = '00000000-0000-7000-8000-0000000003c1'
         AND (e.action = 'stores.delete' OR (e.action = 'stores.update' AND e.changes -> 'after' ? 'name'))
         AND NOT EXISTS (SELECT 1 FROM audit.audit_alerts a WHERE a.id = e.id)$q$,
    3, 'UPDATE de outra coluna (app e db) e DELETE → sem alerta iban_change');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts WHERE id NOT IN (SELECT id FROM alert_base)$q$,
    3, 'exatamente 3 alertas novos (INSERT, UPDATE da app, UPDATE do migrator)');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(DISTINCT x.where_, ', ') FROM (
           SELECT 'audit_events ' || e.action AS where_, e.changes::text || coalesce(e.reason, '') AS t
           FROM audit.audit_events e WHERE e.id NOT IN (SELECT id FROM event_base)
           UNION ALL
           SELECT 'audit_alerts ' || a.kind, a.payload::text FROM audit.audit_alerts a
           WHERE a.id NOT IN (SELECT id FROM alert_base)) AS x
       WHERE x.t ~ '(PT50|0002012312345678|0035012300001234|512345678)'
          OR (x.where_ LIKE 'audit_alerts%' AND strpos(x.t, '****') > 0)$q$,
    'IBAN/NIF em cru nunca chegam a audit_events nem a audit_alerts (o alerta nem mascarado)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. Tolerância: sem TEMPORARY para os papéis da app; audit_append direto (DO, EXECUTE forjado) acima do limite →
--    PTA02 e nada gravado; L1, L2 e db acima do limite gravam (cortado).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['public', 'ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer']) r
       WHERE CASE WHEN r = 'public'
                  THEN EXISTS (SELECT 1 FROM pg_database d, aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
                               WHERE d.datname = current_database() AND a.grantee = 0 AND a.privilege_type = 'TEMPORARY')
                  ELSE has_database_privilege(r, current_database(), 'TEMPORARY') END$q$,
    0, 'TEMPORARY revogado na BD a PUBLIC, app, worker e price_writer');
SELECT pg_temp.expect_value(
    $q$SELECT has_database_privilege('ptmarket_migrator', current_database(), 'TEMPORARY')::int$q$,
    1, 'o migrator (dono da BD) mantém TEMPORARY');
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error($q$CREATE TEMP TABLE ptm_03e_tmp (id int)$q$, '42501', 'app: CREATE TEMP TABLE → 42501');
SELECT pg_temp.expect_error(
    $q$CREATE FUNCTION pg_temp.audit_row_trigger() RETURNS int LANGUAGE sql AS 'SELECT 1'$q$, '42501',
    'app: CREATE FUNCTION em pg_temp → 42501');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error($q$CREATE TEMP TABLE ptm_03e_tmp (id int)$q$, '42501', 'worker: CREATE TEMP TABLE → 42501');
RESET ROLE;
SET ROLE ptmarket_price_writer;
SELECT pg_temp.expect_error($q$CREATE TEMP TABLE ptm_03e_tmp (id int)$q$, '42501',
    'price_writer: CREATE TEMP TABLE → 42501');
RESET ROLE;

SELECT 'PT50 0002 0123 1234 5678 9015 4 ' || pg_temp.blob(70000) AS big \gset
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000003ea', true);
SELECT set_config('app.actor_type', 'merchant', true);
SELECT pg_temp.expect_error_msg(
    format($q$DO $do$ BEGIN
                  PERFORM audit.audit_append('test.do_big'::text, 'stores'::text, 's1'::text, 'success'::text,
                      NULL::text, jsonb_build_object('blob', %L::text), NULL::uuid);
              END $do$$q$, :'big'),
    'PTA02', '0002 0123', '64 KiB', 'app: audit_append > 64 KiB num bloco DO → PTA02 (sem o valor)');
-- Alias com quebras de linha via EXECUTE (o texto imita a linha da L1): a linha 2 é 'SQL statement "…' → PTA02.
SELECT format('SELECT audit.audit_append(''test.do_big''::text, ''stores''::text, ''s1''::text, ''success''::text, '
              'NULL::text, jsonb_build_object(''blob'', %L::text), NULL::uuid)', :'big')
       || E'"\nPL/pgSQL function audit.audit_row_trigger() line 1 at assignment\n"' AS forged \gset
SELECT pg_temp.expect_error_msg(
    format($q$DO $do$ BEGIN EXECUTE %L; END $do$$q$, :'forged'),
    'PTA02', '0002 0123', '64 KiB', 'app: alias com quebras de linha via EXECUTE → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT query_to_xml(%L, false, false, '')$q$, :'forged'),
    'PTA02', '0002 0123', '64 KiB', 'app: o mesmo alias via query_to_xml (SPI sem DO) → PTA02');
RESET ROLE;
-- Função noutro schema com um nome entre aspas que imita a L1 (criada pelo superuser; a app tem EXECUTE e o schema
-- está no search_path, por isso a assinatura sai sem schema): a linha 2 é '"audit.audit_row_trigger"()' → PTA02.
CREATE SCHEMA zz_03e_forge;
CREATE FUNCTION zz_03e_forge."audit.audit_row_trigger"(p_blob text) RETURNS uuid LANGUAGE plpgsql AS $fn$
DECLARE
    v_ev uuid;
BEGIN
    v_ev := audit.audit_append('test.do_big'::text, 'stores'::text, 's1'::text, 'success'::text,
                               NULL::text, jsonb_build_object('blob', p_blob), NULL::uuid);
    RETURN v_ev;
END
$fn$;
GRANT USAGE ON SCHEMA zz_03e_forge TO ptmarket_app;
GRANT EXECUTE ON FUNCTION zz_03e_forge."audit.audit_row_trigger"(text) TO ptmarket_app;
SET ROLE ptmarket_app;
SET LOCAL search_path = zz_03e_forge, public;
SELECT pg_temp.expect_error_msg(
    format($q$SELECT "audit.audit_row_trigger"(%L::text)$q$, :'big'),
    'PTA02', '0002 0123', '64 KiB', 'app: função com nome entre aspas a imitar a L1 → PTA02');
RESET search_path;
SELECT set_config('app.actor_label', 'L' || repeat('x', 200), true);
SELECT pg_temp.expect_error(
    $q$DO $do$ BEGIN
           PERFORM audit.audit_append('test.do_big'::text, 'stores'::text, 's1'::text, 'success'::text,
               NULL::text, NULL::jsonb, NULL::uuid);
       END $do$$q$,
    'PTA02', 'app: actor_label > 128 num bloco DO → PTA02');
-- L1 acima do limite (actor_label > 128 e changes > 64 KiB): a escrita de negócio passa, cortado e marcado.
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000003c2', '00000000-0000-7000-8000-0000000003ea',
     'Loja 03e L1', 'loja-03e-l1', 'Loja 03e L1 Lda', '512345678', 'PT50000201231234567890154', 'l1@teste.invalid');
UPDATE stores SET vacation_message = pg_temp.blob(70000) WHERE id = '00000000-0000-7000-8000-0000000003c2';
SELECT set_config('app.actor_label', '', true);
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;

-- L2 acima do limite pela app (audit_ddl_end → audit_append): tabela de que a app é dona; actor_label > 128.
SET LOCAL event_triggers = on;
CREATE TABLE public.zz_03e_app (id int);
ALTER TABLE public.zz_03e_app OWNER TO ptmarket_app; -- superuser: a app não tem CREATE em public
SET ROLE ptmarket_app;
SELECT set_config('app.actor_type', 'merchant', true);
SELECT set_config('app.actor_label', 'L2' || repeat('y', 200), true);
ALTER TABLE public.zz_03e_app ADD COLUMN c int;
SELECT set_config('app.actor_label', '', true);
SELECT set_config('app.actor_type', '', true);
RESET ROLE;
SET LOCAL event_triggers = off;

-- db acima do limite (audit_append_db): grava, cortado.
SET SESSION AUTHORIZATION ptmarket_migrator;
SELECT audit.audit_append_db('test.db_big'::text, 'x'::text, 'd1'::text,
    jsonb_build_object('blob', :'big'::text), NULL::uuid, NULL::uuid) AS db_ev \gset
RESET SESSION AUTHORIZATION;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE action = 'test.do_big'$q$,
    0, 'nada gravado pelas recusas (DO e EXECUTE forjado)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'stores.update' AND target_id = '00000000-0000-7000-8000-0000000003c2'
         AND actor_type = 'merchant' AND actor_label LIKE '%…[truncated]' AND char_length(actor_label) <= 128
         AND changes #>> '{after,vacation_message,truncated}' = 'true' AND octet_length(changes::text) <= 65536$q$,
    1, 'L1 (app) acima do limite → grava, actor_label e folha cortados');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'ddl.alter_table' AND target_id = 'public.zz_03e_app' AND actor_type = 'merchant'
         AND actor_label LIKE 'L2%…[truncated]' AND char_length(actor_label) <= 128$q$,
    1, 'L2 (app) acima do limite → grava, actor_label cortado');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L AND actor_type = 'db'
              AND changes #>> '{blob,truncated}' = 'true' AND strpos(changes::text, '0002 0123') = 0$q$, :'db_ev'),
    1, 'db acima do limite → grava, folha cortada (sem o IBAN em cru)');
RESET ROLE;

ROLLBACK;
