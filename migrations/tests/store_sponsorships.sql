-- Teste 0031 store_sponsorships: co-patrocínio (várias entidades ativas na mesma loja), EXCLUDE só em 'active' por par,
-- transições trancadas pelo trigger, imutáveis, país, RLS/grants da app (sem commission_override_bps nem DELETE) e do
-- worker (vê 'active' vencido e 'expired'; só 'active' vencido → 'expired', com o UPDATE exato do cartão 24), revogação
-- de um active futuro (intervalo vazio), FK para stores sem CASCADE (loja com patrocínios não muda de tenant), L1.
-- Lojas com SET ROLE ptmarket_app; entidades e casos do dono pelo migrator (policy migrator_all). Tudo com ROLLBACK.
-- now() é constante na transação: as vigências são relativas a ele.
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

-- Linhas afetadas por um UPDATE/DELETE (sem RETURNING).
CREATE FUNCTION pg_temp.expect_rows(p_sql text, p_expected bigint, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_n bigint;
BEGIN
    EXECUTE p_sql;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    IF v_n IS DISTINCT FROM p_expected THEN
        RAISE EXCEPTION 'FALHOU: % (esperado % linhas, obtido %)', p_label, p_expected, v_n;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

CREATE FUNCTION pg_temp.as_actor(p_type text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_type, true);
END
$$;

SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 0. Preparação (migrator): geografia (distrito 96), tenants T1 (nacional PT) e T3 (nacional ES), entidades.
--    Desde a 0033 as lojas só vivem em tenants national_portal (um por país): o "outro tenant" é o T3.
--    e1 Câmara PT · e2 Junta PT · e3 Câmara ES · e4 Associação PT.
-- ---------------------------------------------------------------------------
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('96', 'district', NULL, 'Distrito Teste 31', 'T'),
    ('9601', 'municipality', '96', 'Concelho Teste 31', 'T'),
    ('960101', 'parish', '9601', 'Freguesia Teste 31', 'T');

INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000031a1', 'ssp-npt', 'ssp-npt.teste.invalid', 'Nacional PT 31', 'national_portal', 'PT'),
    ('00000000-0000-7000-8000-0000000031a3', 'ssp-nes', 'ssp-nes.teste.invalid', 'Nacional ES 31', 'national_portal', 'ES');

INSERT INTO sponsor_entities (id, kind, country_code, name, slug, area_code) VALUES
    ('00000000-0000-7000-8000-0000000031e1', 'municipality', 'PT', 'Câmara 31', 'camara-31', '9601'),
    ('00000000-0000-7000-8000-0000000031e2', 'parish', 'PT', 'Junta 31', 'junta-31', '960101'),
    ('00000000-0000-7000-8000-0000000031e3', 'municipality', 'ES', 'Ayuntamiento 31', 'ayto-31', '9601'),
    ('00000000-0000-7000-8000-0000000031e4', 'association', 'PT', 'Associação 31', 'assoc-31', NULL);

-- Lojas: S1 e S1b em T1, S2 em T3 (pela app, cada uma no seu tenant).
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('system');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000031a1', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031a1',
     'Loja S1', 'ssp-s1', 'Loja S1 Lda', '500003101', 'PT50000000000000000003101', 's1@teste.invalid'),
    ('00000000-0000-7000-8000-0000000031b3', '00000000-0000-7000-8000-0000000031a1',
     'Loja S1b', 'ssp-s1b', 'Loja S1b Lda', '500003103', 'PT50000000000000000003103', 's1b@teste.invalid'),
    ('00000000-0000-7000-8000-0000000031b4', '00000000-0000-7000-8000-0000000031a1',
     'Loja S1c', 'ssp-s1c', 'Loja S1c Lda', '500003104', 'PT50000000000000000003104', 's1c@teste.invalid');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000031a3', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000031b2', '00000000-0000-7000-8000-0000000031a3',
     'Loja S2', 'ssp-s2', 'Loja S2 Lda', '500003102', 'PT50000000000000000003102', 's2@teste.invalid');

-- ---------------------------------------------------------------------------
-- 1. Co-patrocínio e EXCLUDE (como ptmarket_app no tenant T1: pedidos nascem pending, decisão por UPDATE).
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000031a1', true);
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id, initiated_by) VALUES
    ('00000000-0000-7000-8000-000000003101', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e1', 'store'),
    ('00000000-0000-7000-8000-000000003102', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e2', 'sponsor');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE store_id = '00000000-0000-7000-8000-0000000031b1'
         AND status = 'pending' AND commission_override_bps = 0$q$,
    2, 'app cria dois pedidos pending (override 0 por defeito)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b1',
        '00000000-0000-7000-8000-0000000031e1')$q$,
    '23505', 'segundo pending para o mesmo par falha');

-- sp1 (S1, Câmara) ativo [now-10d, now+10d); sp2 (S1, Junta) ativo [now-10d, sem fim): Câmara + Junta ao mesmo tempo.
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '10 days',
       valid_to = now() + interval '10 days', decided_at = now()
WHERE id = '00000000-0000-7000-8000-000000003101';
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '10 days', decided_at = now()
WHERE id = '00000000-0000-7000-8000-000000003102';
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE store_id = '00000000-0000-7000-8000-0000000031b1'
         AND status = 'active' AND now() <@ tstzrange(valid_from, valid_to)$q$,
    2, 'co-patrocínio: Câmara e Junta ativas na mesma loja ao mesmo tempo');

-- sp3 (S1, Câmara) consecutivo [now+10d, now+20d): passa ([) não se sobrepõe).
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003103', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e1');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() + interval '10 days',
           valid_to = now() + interval '20 days' WHERE id = '00000000-0000-7000-8000-000000003103'$q$,
    1, 'mesmo par com período consecutivo passa');

-- sp4 (S1, Câmara) pending; ativar sobreposto a sp1/sp3 → 23P01 (fica pending, sobreposto: passa).
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003104', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e1');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() + interval '5 days',
           valid_to = now() + interval '15 days' WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23P01', 'mesmo par com dois active sobrepostos falha (23P01)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
       WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23P01', 'active sem fim sobreposto a um active com fim falha (23P01)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET valid_from = now(), valid_to = now() + interval '15 days'
       WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    1, 'pending com vigência sobreposta a um active passa');

-- Par (S1, Junta): r1 revogado e x1 expirado sobrepostos a sp2 (active).
--   sp2 passa primeiro a revoked para libertar o período; depois r1/x1 e por fim sp2b active de novo.
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked', decision_reason = 'teste'
       WHERE id = '00000000-0000-7000-8000-000000003102'$q$,
    1, 'active → revoked passa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003102'
         AND valid_to = now()$q$,
    1, 'revoked sem fim: valid_to = now()');
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003105', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e2');
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '40 days',
       valid_to = now() + interval '1 day'
WHERE id = '00000000-0000-7000-8000-000000003105';
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'expired' WHERE id = '00000000-0000-7000-8000-000000003105'$q$,
    1, 'active → expired passa');
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003106', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e2');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '20 days'
       WHERE id = '00000000-0000-7000-8000-000000003106'$q$,
    1, 'active sobreposto a um revoked e a um expired do mesmo par passa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE store_id = '00000000-0000-7000-8000-0000000031b1'
         AND status = 'active' AND now() <@ tstzrange(valid_from, valid_to)$q$,
    2, 'continuam dois patrocínios vigentes na loja (Câmara + Junta)');

-- ---------------------------------------------------------------------------
-- 2. Transições proibidas, imutáveis, override e país.
-- ---------------------------------------------------------------------------
-- Par (S1, Associação): w1 active vencido (para o worker) e rj rejeitado.
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003107', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e4');
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '20 days',
       valid_to = now() - interval '1 day'
WHERE id = '00000000-0000-7000-8000-000000003107';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003108', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b1', '00000000-0000-7000-8000-0000000031e4');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'rejected', decision_reason = 'fora da área'
       WHERE id = '00000000-0000-7000-8000-000000003108'$q$,
    1, 'pending → rejected passa');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = now() + interval '100 days'
       WHERE id = '00000000-0000-7000-8000-000000003108'$q$,
    '23514', 'rejected → active falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active' WHERE id = '00000000-0000-7000-8000-000000003105'$q$,
    '23514', 'expired → active falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active' WHERE id = '00000000-0000-7000-8000-000000003102'$q$,
    '23514', 'revoked → active falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'pending' WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    '23514', 'active → pending falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'expired' WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23514', 'pending → expired falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'active', valid_from = NULL
       WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23514', 'pending → active sem valid_from falha');
-- Revogar um active que ainda não começou: intervalo vazio (valid_to = valid_from), nunca vigorou.
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000003103'$q$,
    1, 'revogar um active futuro passa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003103'
         AND valid_from = now() + interval '10 days' AND valid_to = valid_from
         AND isempty(tstzrange(valid_from, valid_to))$q$,
    1, 'active futuro revogado: valid_to = valid_from (intervalo vazio)');
-- (S1b, Câmara) ativo com valid_from = now() e revogado na mesma transação.
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000003109', '00000000-0000-7000-8000-0000000031a1',
     '00000000-0000-7000-8000-0000000031b3', '00000000-0000-7000-8000-0000000031e1');
UPDATE store_sponsorships SET status = 'active', valid_from = now() WHERE id = '00000000-0000-7000-8000-000000003109';
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000003109'$q$,
    1, 'revogar um active com valid_from = now() na mesma transação passa');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003109'
         AND valid_from = now() AND valid_to = now()$q$,
    1, 'valid_from = now() revogado: valid_to = valid_from = now()');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET valid_to = valid_from WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    '23514', 'intervalo vazio num active falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b3',
        '00000000-0000-7000-8000-0000000031e3')$q$,
    '23514', 'entidade de outro país (ES) numa loja PT falha');
RESET ROLE;

-- Pelo migrator (as colunas que a app nem tem grant para tocar).
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id, status, valid_from) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b3',
        '00000000-0000-7000-8000-0000000031e2', 'active', now())$q$,
    '23514', 'INSERT já active falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET store_id = '00000000-0000-7000-8000-0000000031b3'
       WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    '23514', 'mudar store_id falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET sponsor_entity_id = '00000000-0000-7000-8000-0000000031e4'
       WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23514', 'mudar sponsor_entity_id falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET initiated_by = 'sponsor' WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23514', 'mudar initiated_by falha');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET commission_override_bps = 100 WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    '23514', 'commission_override_bps não muda em active');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET commission_override_bps = 100 WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    1, 'commission_override_bps muda em pending (migrator)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET commission_override_bps = 10001 WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '23514', 'commission_override_bps acima de 10000 falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000031a3', '00000000-0000-7000-8000-0000000031b1',
        '00000000-0000-7000-8000-0000000031e3')$q$,
    '23503', 'loja de outro tenant (FK composta) falha');
SELECT pg_temp.expect_error(
    $q$DELETE FROM sponsor_entities WHERE id = '00000000-0000-7000-8000-0000000031e1'$q$,
    '23001', 'entidade com patrocínios não se apaga (RESTRICT)');

-- ---------------------------------------------------------------------------
-- 3. Estrutura: RLS, caixa negra, trigger INVOKER, grants.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'store_sponsorships'::regclass
         AND relrowsecurity AND relforcerowsecurity$q$,
    1, 'RLS ENABLE + FORCE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'store_sponsorships'::regclass AND tgenabled = 'A'
         AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    2, 'zz_audit_row + zz_audit_truncate (ALWAYS)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc WHERE oid = 'store_sponsorships_guard()'::regprocedure
         AND NOT prosecdef AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'trigger de estado INVOKER com search_path fixo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['INSERT', 'UPDATE', 'REFERENCES']) AS p(priv)
       WHERE has_column_privilege('ptmarket_app', 'store_sponsorships', 'commission_override_bps', p.priv)$q$,
    0, 'app sem INSERT/UPDATE/REFERENCES em commission_override_bps');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', 'store_sponsorships', p.priv)
          OR has_table_privilege('ptmarket_worker', 'store_sponsorships', p.priv)$q$,
    0, 'app e worker sem DELETE/TRUNCATE/REFERENCES/TRIGGER');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'store_sponsorships' AND grantee = 'ptmarket_worker'
         AND privilege_type IN ('INSERT', 'UPDATE')$q$,
    2, 'worker: UPDATE só em status e updated_at, sem INSERT');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid = 'store_sponsorships'::regclass AND a.grantee = 0$q$,
    0, 'sem privilégios para PUBLIC');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_constraint WHERE conrelid = 'store_sponsorships'::regclass AND contype = 'x'$q$,
    1, 'EXCLUDE presente');

-- ---------------------------------------------------------------------------
-- 4. Como ptmarket_app: isolamento por tenant e trinco de dinheiro.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000031a3', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE tenant_id = '00000000-0000-7000-8000-0000000031a1'$q$,
    0, 'outro tenant não vê os patrocínios de T1');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    0, 'outro tenant não altera patrocínios de T1 (0 linhas)');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b3',
        '00000000-0000-7000-8000-0000000031e2')$q$,
    '42501', 'outro tenant não cria patrocínios em T1');
SELECT pg_temp.expect_rows(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id) VALUES
       ('00000000-0000-7000-8000-0000000031a3', '00000000-0000-7000-8000-0000000031b2',
        '00000000-0000-7000-8000-0000000031e3')$q$,
    1, 'T3 cria o seu pedido');

SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000031a1', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships$q$, 9, 'T1 vê só os seus 9 patrocínios');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id, commission_override_bps) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b3',
        '00000000-0000-7000-8000-0000000031e2', 0)$q$,
    '42501', 'app não insere commission_override_bps');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET commission_override_bps = 0 WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '42501', 'app não altera commission_override_bps');
SELECT pg_temp.expect_error(
    $q$INSERT INTO store_sponsorships (tenant_id, store_id, sponsor_entity_id, status) VALUES
       ('00000000-0000-7000-8000-0000000031a1', '00000000-0000-7000-8000-0000000031b3',
        '00000000-0000-7000-8000-0000000031e2', 'pending')$q$,
    '42501', 'app não escolhe o status no INSERT');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET store_id = '00000000-0000-7000-8000-0000000031b3'
       WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    '42501', 'app não altera store_id');
SELECT pg_temp.expect_error(
    $q$DELETE FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    '42501', 'app não apaga patrocínios');
SELECT pg_temp.expect_error('TRUNCATE store_sponsorships', '42501', 'app não faz TRUNCATE');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. Como ptmarket_worker: vê 'active' vencido e 'expired'; só 'active' vencido → 'expired'.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.as_actor('system');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships$q$, 2, 'worker vê só o active vencido e o expired');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships
       WHERE status IN ('pending', 'rejected', 'revoked') OR (status = 'active' AND (valid_to IS NULL OR valid_to > now()))$q$,
    0, 'worker não vê pending, rejected, revoked nem active em vigor');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'expired', updated_at = now()
       WHERE id = '00000000-0000-7000-8000-000000003101'$q$,
    0, 'worker não altera um active vigente (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET status = 'expired', updated_at = now()
       WHERE id = '00000000-0000-7000-8000-000000003104'$q$,
    0, 'worker não altera um pending (0 linhas)');
SELECT pg_temp.expect_rows(
    $q$UPDATE store_sponsorships SET updated_at = now() WHERE id = '00000000-0000-7000-8000-000000003105'$q$,
    0, 'worker não altera um expired (0 linhas)');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-000000003107'$q$,
    '42501', 'worker não passa um active vencido a revoked');
SELECT pg_temp.expect_error(
    $q$UPDATE store_sponsorships SET valid_to = now() WHERE id = '00000000-0000-7000-8000-000000003107'$q$,
    '42501', 'worker não altera valid_to');
SELECT pg_temp.expect_error(
    $q$DELETE FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003107'$q$,
    '42501', 'worker não apaga');
-- UPDATE exato do job (cartão 24).
-- (o worker não cria tabelas temporárias: o RETURNING é verificado na própria consulta)
SELECT pg_temp.expect_count(
    $q$WITH u AS (
           UPDATE store_sponsorships SET status='expired', updated_at=now() WHERE id IN (SELECT id FROM store_sponsorships WHERE status='active' AND valid_to <= now() ORDER BY valid_to LIMIT 500 FOR UPDATE SKIP LOCKED) RETURNING id, tenant_id, store_id, sponsor_entity_id
       )
       SELECT count(*) FROM u
       WHERE id = '00000000-0000-7000-8000-000000003107' AND tenant_id = '00000000-0000-7000-8000-0000000031a1'
         AND store_id = '00000000-0000-7000-8000-0000000031b1'
         AND sponsor_entity_id = '00000000-0000-7000-8000-0000000031e4'
         AND (SELECT count(*) FROM u) = 1$q$,
    1, 'job do cartão 24 (WHERE id IN … FOR UPDATE SKIP LOCKED, RETURNING): só o vencido, com os 4 ids');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE status = 'expired'$q$, 2, 'worker vê os dois expired');
RESET ROLE;

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE id = '00000000-0000-7000-8000-000000003107' AND status = 'expired'$q$,
    1, 'o vencido ficou expired');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM store_sponsorships WHERE status = 'active'
         AND store_id = '00000000-0000-7000-8000-0000000031b1'$q$,
    2, 'os active vigentes ficaram como estavam');

-- ---------------------------------------------------------------------------
-- 6. FK para stores sem CASCADE: loja com patrocínios não muda de tenant; sem patrocínios continua a mudar.
--    (migrator; FORCE RLS de stores desligado só nesta transação, como em stores_national_channel.sql.)
-- ---------------------------------------------------------------------------
ALTER TABLE stores NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_error(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-0000000031a3'
       WHERE id = '00000000-0000-7000-8000-0000000031b3'$q$,
    '23503', 'loja com patrocínio não muda de tenant (23503)');
SELECT pg_temp.expect_rows(
    $q$UPDATE stores SET tenant_id = '00000000-0000-7000-8000-0000000031a3'
       WHERE id = '00000000-0000-7000-8000-0000000031b4'$q$,
    1, 'loja sem patrocínios muda de tenant');
ALTER TABLE stores FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class WHERE oid = 'stores'::regclass AND relforcerowsecurity$q$,
    1, 'FORCE RLS de stores reposto');

ROLLBACK;
