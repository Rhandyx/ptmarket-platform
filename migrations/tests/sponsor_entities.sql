-- Teste 0028 sponsor_entities + sponsor_entity_areas: área por kind (length + FK; códigos com letras), canal
-- (não national_portal, mesmo país), áreas só para associações, RLS/grants (a app só lê), caixa negra L1.
-- Inserts como migrator (policy migrator_all); asserções de acesso com SET ROLE ptmarket_app. Tudo com ROLLBACK.
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

SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação: geografia de teste (distrito 97) e tenants (municipal PT, niche PT, portal PT, municipal ES).
-- ---------------------------------------------------------------------------
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('97', 'district', NULL, 'Distrito Teste', 'T'),
    ('9701', 'municipality', '97', 'Concelho Teste A', 'T'),
    ('9702', 'municipality', '97', 'Concelho Teste B', 'T'),
    ('970101', 'parish', '9701', 'Freguesia Teste 01', 'T'),
    ('9701FA', 'parish', '9701', 'Freguesia Teste FA', 'T');

INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000028a0', 'spon-mun', 'spon-mun.teste.invalid', 'Canal Municipal', 'municipal', 'PT'),
    ('00000000-0000-7000-8000-0000000028a1', 'spon-nic', 'spon-nic.teste.invalid', 'Canal Nicho', 'niche', 'PT'),
    ('00000000-0000-7000-8000-0000000028a2', 'spon-por', 'spon-por.teste.invalid', 'Portal', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000028a3', 'spon-es', 'spon-es.teste.invalid', 'Canal ES', 'municipal', 'ES');

-- ---------------------------------------------------------------------------
-- 1. Casos válidos.
-- ---------------------------------------------------------------------------
INSERT INTO sponsor_entities (id, kind, name, slug, area_code, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000028e1', 'municipality', 'Câmara Teste', 'camara-teste', '9701',
     '00000000-0000-7000-8000-0000000028a0'),
    ('00000000-0000-7000-8000-0000000028e2', 'parish', 'Junta Teste', 'junta-teste', '9701FA', NULL),
    ('00000000-0000-7000-8000-0000000028e3', 'association', 'Associação Teste', 'assoc-teste', NULL,
     '00000000-0000-7000-8000-0000000028a1'),
    ('00000000-0000-7000-8000-0000000028e4', 'parish', 'Junta Numérica', 'junta-num', '970101', NULL);
INSERT INTO sponsor_entity_areas (sponsor_entity_id, area_code) VALUES
    ('00000000-0000-7000-8000-0000000028e3', '9702'),
    ('00000000-0000-7000-8000-0000000028e3', '970101');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM sponsor_entities WHERE id::text LIKE '00000000-0000-7000-8000-0000000028e%'$q$,
    4, 'Câmara (4), Junta (6, com letras e só algarismos) e Associação passam');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM sponsor_entity_areas WHERE sponsor_entity_id = '00000000-0000-7000-8000-0000000028e3'$q$,
    2, 'Associação com 2 áreas (DDCC e DDCCFF)');

-- ---------------------------------------------------------------------------
-- 2. Casos que falham.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('municipality', 'C', 'c6', '970101')$q$,
    '23514', 'Câmara com área de 6 caracteres falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('municipality', 'C', 'c2', '97')$q$,
    '23514', 'Câmara com distrito falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug) VALUES ('municipality', 'C', 'c0')$q$,
    '23514', 'Câmara sem área falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('parish', 'J', 'j4', '9701')$q$,
    '23514', 'Junta com área de 4 caracteres falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('association', 'A', 'a1', '9701')$q$,
    '23514', 'Associação com area_code falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('municipality', 'C', 'cx', '9799')$q$,
    '23503', 'Câmara com área inexistente falha (FK)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug) VALUES ('district', 'D', 'd1')$q$,
    '23514', 'kind fora da lista falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code) VALUES ('parish', 'J', 'junta-teste', '970101')$q$,
    '23505', 'slug repetido no mesmo país falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code, channel_tenant_id) VALUES
       ('municipality', 'C', 'cp', '9702', '00000000-0000-7000-8000-0000000028a2')$q$,
    '23514', 'canal national_portal falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code, channel_tenant_id) VALUES
       ('municipality', 'C', 'ce', '9702', '00000000-0000-7000-8000-0000000028a3')$q$,
    '23514', 'canal de outro país falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug, area_code, channel_tenant_id) VALUES
       ('municipality', 'C', 'ci', '9702', '00000000-0000-7000-8000-0000000028ff')$q$,
    '23503', 'canal inexistente falha (FK)');
SELECT pg_temp.expect_error(
    $q$UPDATE sponsor_entities SET channel_tenant_id = '00000000-0000-7000-8000-0000000028a2'
       WHERE id = '00000000-0000-7000-8000-0000000028e1'$q$,
    '23514', 'UPDATE para canal national_portal falha');
SELECT pg_temp.expect_error(
    $q$UPDATE sponsor_entities SET country_code = 'ES' WHERE id = '00000000-0000-7000-8000-0000000028e1'$q$,
    '23514', 'UPDATE do país com canal PT falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e1', '9702')$q$,
    '23514', 'área numa Câmara falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e2', '9702')$q$,
    '23514', 'área numa Junta falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e3', '97')$q$,
    '23514', 'área de distrito numa Associação falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e3', '9799')$q$,
    '23503', 'área inexistente falha (FK)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e3', '9702')$q$,
    '23505', 'área repetida falha');
SELECT pg_temp.expect_error(
    $q$UPDATE sponsor_entities SET kind = 'municipality', area_code = '9702'
       WHERE id = '00000000-0000-7000-8000-0000000028e3'$q$,
    '23514', 'Associação com áreas não muda de kind');
SELECT pg_temp.expect_error(
    $q$DELETE FROM tenants WHERE id = '00000000-0000-7000-8000-0000000028a0'$q$,
    '23001', 'tenant usado como canal não se apaga (RESTRICT)');

-- ---------------------------------------------------------------------------
-- 3. Estrutura: RLS, caixa negra, grants, triggers INVOKER.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('sponsor_entities'::regclass, 'sponsor_entity_areas'::regclass)
         AND relrowsecurity AND relforcerowsecurity$q$,
    2, 'RLS ENABLE + FORCE nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid IN ('sponsor_entities'::regclass, 'sponsor_entity_areas'::regclass) AND tgenabled = 'A'
         AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    4, 'zz_audit_row + zz_audit_truncate (ALWAYS) nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid IN ('sponsor_entities_check()'::regprocedure, 'sponsor_entity_areas_check()'::regprocedure)
         AND NOT prosecdef AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    2, 'triggers de coerência INVOKER com search_path fixo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['sponsor_entities', 'sponsor_entity_areas']) AS t(tab),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', t.tab, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE', 'REFERENCES') AND has_any_column_privilege('ptmarket_app', t.tab, p.priv))$q$,
    0, 'app: só SELECT nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('sponsor_entities'::regclass, 'sponsor_entity_areas'::regclass) AND a.grantee = 0$q$,
    0, 'sem privilégios para PUBLIC');

-- ---------------------------------------------------------------------------
-- 4. Como ptmarket_app: lê (dados públicos), não escreve.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM sponsor_entities WHERE id::text LIKE '00000000-0000-7000-8000-0000000028e%'$q$,
    4, 'app lê as entidades');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM sponsor_entity_areas WHERE sponsor_entity_id = '00000000-0000-7000-8000-0000000028e3'$q$,
    2, 'app lê as áreas');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entities (kind, name, slug) VALUES ('association', 'A', 'app-a')$q$,
    '42501', 'app não cria entidades');
SELECT pg_temp.expect_error(
    $q$UPDATE sponsor_entities SET name = 'x' WHERE id = '00000000-0000-7000-8000-0000000028e1'$q$,
    '42501', 'app não altera entidades');
SELECT pg_temp.expect_error(
    $q$DELETE FROM sponsor_entities WHERE id = '00000000-0000-7000-8000-0000000028e1'$q$,
    '42501', 'app não apaga entidades');
SELECT pg_temp.expect_error('TRUNCATE sponsor_entities', '42501', 'app não faz TRUNCATE de sponsor_entities');
SELECT pg_temp.expect_error(
    $q$INSERT INTO sponsor_entity_areas VALUES ('00000000-0000-7000-8000-0000000028e3', '9701')$q$,
    '42501', 'app não acrescenta áreas');
SELECT pg_temp.expect_error(
    $q$UPDATE sponsor_entity_areas SET area_code = '9701' WHERE sponsor_entity_id = '00000000-0000-7000-8000-0000000028e3'$q$,
    '42501', 'app não altera áreas');
SELECT pg_temp.expect_error(
    $q$DELETE FROM sponsor_entity_areas WHERE sponsor_entity_id = '00000000-0000-7000-8000-0000000028e3'$q$,
    '42501', 'app não apaga áreas');
SELECT pg_temp.expect_error('TRUNCATE sponsor_entity_areas', '42501', 'app não faz TRUNCATE de sponsor_entity_areas');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error('SELECT count(*) FROM sponsor_entities', '42501', 'worker não lê sponsor_entities');
RESET ROLE;

ROLLBACK;
