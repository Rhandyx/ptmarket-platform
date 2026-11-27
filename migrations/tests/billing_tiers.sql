-- Teste 0032 + 0034 platform_settings + billing_plan_tiers: seed (1 + 2 + 7 linhas; tiered_subscription só mensalidade
-- fixa, 0 bps em todos os escalões, mensalidade a crescer com o volume), CHECKs,
-- sobreposição (23P01), constraint trigger diferido (buraco, sem escalão aberto, 1.º fora de 0, plano vazio → 23514
-- no COMMIT; reorganização em vários comandos passa), RLS/grants (app só lê, sem tenant), caixa negra L1.
-- Corre como o migrator (policy migrator_all). "Erro no COMMIT" = SET CONSTRAINTS … IMMEDIATE (mesmo disparo do
-- COMMIT, sem terminar a transação do teste). Tudo com ROLLBACK.
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

-- O comando passa; o constraint trigger diferido falha (23514) quando dispara (como no COMMIT).
CREATE FUNCTION pg_temp.expect_commit_error(p_sql text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        RAISE EXCEPTION 'FALHOU: % (o comando devia passar e falhar só no COMMIT; obtido %: %)', p_label, v_state, v_msg;
    END;
    BEGIN
        SET CONSTRAINTS billing_plan_tiers_contiguous IMMEDIATE;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        SET CONSTRAINTS billing_plan_tiers_contiguous DEFERRED;
        IF v_state = '23514' THEN
            -- Desfaz o comando (a exceção só reverteu o SET CONSTRAINTS): re-levanta para o bloco exterior.
            RAISE EXCEPTION USING ERRCODE = 'PTT01', MESSAGE = 'ok';
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado 23514 no COMMIT, obtido %: %)', p_label, v_state, v_msg;
    END;
    RAISE EXCEPTION 'FALHOU: % (esperado 23514 no COMMIT, mas passou)', p_label;
END
$$;

-- Envolve expect_commit_error para reverter o comando quando o erro diferido é o esperado.
CREATE FUNCTION pg_temp.expect_deferred(p_sql text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        PERFORM pg_temp.expect_commit_error(p_sql, p_label);
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = 'PTT01' THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION '%', v_msg;
    END;
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

SELECT set_config('app.actor_type', 'system', true);
SELECT set_config('app.actor_label', 'test', true);

-- ---------------------------------------------------------------------------
-- 1. Seed.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM platform_settings WHERE id AND base_commission_bps = 800 AND updated_by IS NULL$q$,
    1, 'platform_settings: uma linha, base 800 bps');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers$q$, 9, 'billing_plan_tiers: 2 + 7 linhas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers b
       JOIN (VALUES ('commission_payg', 0::bigint, 2000000::bigint, 0::bigint, 800),
                    ('commission_payg', 2000000, NULL, 0, 600),
                    ('tiered_subscription', 0, 100000, 500, 0),
                    ('tiered_subscription', 100000, 500000, 1000, 0),
                    ('tiered_subscription', 500000, 1000000, 5000, 0),
                    ('tiered_subscription', 1000000, 2500000, 10000, 0),
                    ('tiered_subscription', 2500000, 5000000, 17500, 0),
                    ('tiered_subscription', 5000000, 10000000, 30000, 0),
                    ('tiered_subscription', 10000000, NULL, 50000, 0)) AS e(plan, f, t, fee, bps)
         ON b.plan_code = e.plan AND b.gmv_from_cents = e.f AND b.gmv_to_cents IS NOT DISTINCT FROM e.t
        AND b.monthly_fee_cents = e.fee AND b.marginal_commission_bps = e.bps$q$,
    9, 'seed com os valores da spec 14 §4 (0034)');
-- tiered_subscription (0034): 0% de comissão em todos os escalões; a mensalidade sobe estritamente com o volume.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers
       WHERE plan_code = 'tiered_subscription' AND marginal_commission_bps <> 0$q$,
    0, 'tiered_subscription: 0 bps em todos os escalões');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (
         SELECT monthly_fee_cents,
                lag(monthly_fee_cents) OVER (ORDER BY gmv_from_cents) AS prev_fee
           FROM billing_plan_tiers WHERE plan_code = 'tiered_subscription') AS t
       WHERE t.prev_fee IS NOT NULL AND t.monthly_fee_cents <= t.prev_fee$q$,
    0, 'tiered_subscription: mensalidade estritamente crescente');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers
       WHERE plan_code = 'commission_payg' AND monthly_fee_cents <> 0$q$,
    0, 'commission_payg: sem mensalidade (inalterado)');

-- ---------------------------------------------------------------------------
-- 2. CHECKs e sobreposição (imediatos).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    'INSERT INTO platform_settings DEFAULT VALUES', '23505', 'segunda linha em platform_settings falha (PK)');
SELECT pg_temp.expect_error(
    'INSERT INTO platform_settings (id) VALUES (false)', '23514', 'platform_settings com id = false falha (CHECK)');
SELECT pg_temp.expect_error(
    'UPDATE platform_settings SET base_commission_bps = 10001', '23514', 'base_commission_bps 10001 falha');
SELECT pg_temp.expect_error(
    'UPDATE platform_settings SET base_commission_bps = -1', '23514', 'base_commission_bps -1 falha');
SELECT pg_temp.expect_error(
    $q$UPDATE billing_plan_tiers SET marginal_commission_bps = 10001
       WHERE plan_code = 'commission_payg' AND gmv_from_cents = 0$q$,
    '23514', 'marginal_commission_bps 10001 falha');
SELECT pg_temp.expect_error(
    $q$UPDATE billing_plan_tiers SET monthly_fee_cents = -1
       WHERE plan_code = 'tiered_subscription' AND gmv_from_cents = 0$q$,
    '23514', 'monthly_fee_cents negativo falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
       VALUES ('free', 0, NULL, 0, 0)$q$,
    '23514', 'plan_code fora da lista falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
       VALUES ('commission_payg', 5000000, 5000000, 0, 0)$q$,
    '23514', 'escalão vazio (to = from) falha');
SELECT pg_temp.expect_error(
    $q$INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
       VALUES ('commission_payg', 1000000, 3000000, 0, 700)$q$,
    '23P01', 'escalão sobreposto no mesmo plano → 23P01');
SELECT pg_temp.expect_error(
    $q$INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
       VALUES ('commission_payg', 9000000, NULL, 0, 500)$q$,
    '23P01', 'segundo escalão aberto no mesmo plano → 23P01');

-- ---------------------------------------------------------------------------
-- 3. Continuidade (constraint trigger diferido: erro no COMMIT).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'billing_plan_tiers'::regclass AND tgname = 'billing_plan_tiers_contiguous'
         AND tgconstraint <> 0 AND tgdeferrable AND tginitdeferred AND tgenabled = 'O'
         AND tgfoid = 'billing_plan_tiers_check_plan()'::regprocedure$q$,
    1, 'constraint trigger DEFERRABLE INITIALLY DEFERRED');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'billing_plan_tiers_check_plan()'::regprocedure
         AND NOT prosecdef AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'função de continuidade INVOKER com search_path fixo');

SELECT pg_temp.expect_deferred(
    $q$UPDATE billing_plan_tiers SET gmv_from_cents = 150000
       WHERE plan_code = 'tiered_subscription' AND gmv_from_cents = 100000$q$,
    'buraco entre escalões → 23514 no COMMIT');
SELECT pg_temp.expect_deferred(
    $q$UPDATE billing_plan_tiers SET gmv_to_cents = 9000000
       WHERE plan_code = 'commission_payg' AND gmv_to_cents IS NULL$q$,
    'plano sem escalão aberto → 23514 no COMMIT');
SELECT pg_temp.expect_deferred(
    $q$UPDATE billing_plan_tiers SET gmv_from_cents = 1
       WHERE plan_code = 'tiered_subscription' AND gmv_from_cents = 0$q$,
    '1.º escalão que não começa em 0 → 23514 no COMMIT');
SELECT pg_temp.expect_deferred(
    $q$DELETE FROM billing_plan_tiers WHERE plan_code = 'commission_payg'$q$,
    'plano sem nenhum escalão → 23514 no COMMIT');
SELECT pg_temp.expect_deferred(
    $q$UPDATE billing_plan_tiers SET gmv_to_cents = 1500000
       WHERE plan_code = 'commission_payg' AND gmv_from_cents = 0$q$,
    'escalão que não fecha no from do seguinte → 23514 no COMMIT');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers$q$, 9, 'os casos recusados não deixaram alterações');

-- Reorganização válida em dois comandos (estado intermédio com buraco) passa no COMMIT.
SAVEPOINT reorganiza;
UPDATE billing_plan_tiers SET gmv_to_cents = 1000000 WHERE plan_code = 'commission_payg' AND gmv_from_cents = 0;
INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
VALUES ('commission_payg', 1000000, 2000000, 0, 700);
SET CONSTRAINTS billing_plan_tiers_contiguous IMMEDIATE;
SET CONSTRAINTS billing_plan_tiers_contiguous DEFERRED;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers WHERE plan_code = 'commission_payg'$q$,
    3, 'reorganização em vários comandos na mesma transação passa no COMMIT');
ROLLBACK TO SAVEPOINT reorganiza;

-- ---------------------------------------------------------------------------
-- 4. Estrutura: RLS, caixa negra, grants.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid IN ('platform_settings'::regclass, 'billing_plan_tiers'::regclass)
         AND relrowsecurity AND relforcerowsecurity$q$,
    2, 'RLS ENABLE + FORCE nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid IN ('platform_settings'::regclass, 'billing_plan_tiers'::regclass) AND tgenabled = 'A'
         AND tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((tgname = 'zz_audit_row' AND tgtype = 29) OR (tgname = 'zz_audit_truncate' AND tgtype = 34))$q$,
    4, 'zz_audit_row + zz_audit_truncate (ALWAYS) nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['platform_settings', 'billing_plan_tiers']) AS t(tab),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_app', t.tab, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE', 'REFERENCES') AND has_any_column_privilege('ptmarket_app', t.tab, p.priv))$q$,
    0, 'app: só SELECT nas duas tabelas');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['platform_settings', 'billing_plan_tiers']) AS t(tab),
                            unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_worker', t.tab, p.priv)
          OR has_table_privilege('ptmarket_price_writer', t.tab, p.priv)$q$,
    0, 'worker e price_writer: sem privilégios');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid IN ('platform_settings'::regclass, 'billing_plan_tiers'::regclass) AND a.grantee = 0$q$,
    0, 'sem privilégios para PUBLIC');

-- ---------------------------------------------------------------------------
-- 5. Como ptmarket_app, sem tenant no contexto: lê as duas, não escreve.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '', true);
SET ROLE ptmarket_app;
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM platform_settings WHERE base_commission_bps = 800$q$, 1, 'app lê platform_settings sem tenant');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM billing_plan_tiers$q$, 9, 'app lê os 9 escalões sem tenant');
SELECT pg_temp.expect_error(
    'INSERT INTO platform_settings DEFAULT VALUES', '42501', 'app não insere em platform_settings');
SELECT pg_temp.expect_error(
    'UPDATE platform_settings SET base_commission_bps = 0', '42501', 'app não altera a comissão base');
SELECT pg_temp.expect_error('DELETE FROM platform_settings', '42501', 'app não apaga platform_settings');
SELECT pg_temp.expect_error('TRUNCATE platform_settings', '42501', 'app não faz TRUNCATE de platform_settings');
SELECT pg_temp.expect_error(
    $q$INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
       VALUES ('commission_payg', 9000000, NULL, 0, 0)$q$,
    '42501', 'app não insere escalões');
SELECT pg_temp.expect_error(
    'UPDATE billing_plan_tiers SET marginal_commission_bps = 0', '42501', 'app não altera escalões');
SELECT pg_temp.expect_error('DELETE FROM billing_plan_tiers', '42501', 'app não apaga escalões');
SELECT pg_temp.expect_error('TRUNCATE billing_plan_tiers', '42501', 'app não faz TRUNCATE de billing_plan_tiers');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error('SELECT count(*) FROM platform_settings', '42501', 'worker não lê platform_settings');
SELECT pg_temp.expect_error('UPDATE billing_plan_tiers SET marginal_commission_bps = 0', '42501',
    'worker não altera escalões');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. Caixa negra: UPDATE da base pelo migrator → platform_settings.update (ator 'db').
--    A tabela não tem tenant_id: o evento leva o app.current_tenant_id do contexto (uuid de teste, sem FK), só para a
--    app o poder ler pela policy tenant_read.
-- ---------------------------------------------------------------------------
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000032a0', true);
UPDATE platform_settings SET base_commission_bps = 750;
SET ROLE ptmarket_app;
-- A 0038 fecha audit_events ao âmbito de loja: leituras como admin sem impersonação; ator anterior reposto a seguir.
SELECT set_config('ptm.prev_actor', COALESCE(current_setting('app.actor_type', true), ''), true), set_config('ptm.prev_imp', COALESCE(current_setting('app.impersonator_id', true), ''), true);
SELECT set_config('app.actor_type', 'admin', true), set_config('app.impersonator_id', '', true);
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'platform_settings.update' AND target_type = 'platform_settings' AND target_id = 'true'
         AND actor_type = 'db' AND outcome = 'success'
         AND changes = '{"before": {"base_commission_bps": 800}, "after": {"base_commission_bps": 750}}'::jsonb$q$,
    1, 'UPDATE de base_commission_bps pelo migrator → platform_settings.update na caixa negra');
SELECT set_config('app.actor_type', current_setting('ptm.prev_actor'), true), set_config('app.impersonator_id', current_setting('ptm.prev_imp'), true);
RESET ROLE;

ROLLBACK;
