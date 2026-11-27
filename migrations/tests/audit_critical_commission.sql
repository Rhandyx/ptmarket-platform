-- run.sh: superuser
-- Teste da 0038 (cartão 03/11 + adenda do supervisor): kinds críticos de comissão e patrocínio em
-- audit.critical_kind / audit.audit_alerts e âmbito por loja na leitura de audit.audit_events (store_scope_read).
-- Corre como superuser só para assumir papéis NOLOGIN, ler catálogos e provar a recusa da audit_seal; cada asserção
-- de dados é feita com SET ROLE do papel em causa. Tudo numa transação com ROLLBACK.
--   T = nacional PT de teste · L1, L2 = lojas de T

BEGIN;
SET LOCAL event_triggers = off; -- L2 (0013) desligada só nesta transação: este teste não é sobre DDL

CREATE TEMP TABLE alert_base AS SELECT id FROM audit.audit_alerts;
GRANT SELECT ON alert_base TO ptmarket_worker;

CREATE FUNCTION pg_temp.expect_error(p_sql text, p_state text, p_msg_like text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_state text;
    v_msg   text;
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
        IF v_state = p_state AND (p_msg_like IS NULL OR v_msg LIKE p_msg_like) THEN
            RAISE NOTICE 'OK: %', p_label;
            RETURN;
        END IF;
        RAISE EXCEPTION 'FALHOU: % (esperado % %, obtido %: %)', p_label, p_state, p_msg_like, v_state, v_msg;
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

-- ---------------------------------------------------------------------------
-- 1. audit.critical_kind: regressão dos 5 kinds antigos (mesma tabela da 0015) + 4 kinds novos (só success).
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE kind_cases (action text, outcome text, actor_type text, expected text);
INSERT INTO kind_cases VALUES
    -- Regressão (0015): devolvem o mesmo que antes.
    ('stores.iban_update',          'success', 'merchant',  'iban_change'),
    ('stores.iban',                 'denied',  'merchant',  'iban_change'),
    ('payout_accounts.create',      'success', 'merchant',  'iban_change'),
    ('payout_accounts.update',      'error',   'db',        'iban_change'),
    ('merchants.iban_change',       'success', 'admin',     'iban_change'),
    ('payments.capture',            'error',   'customer',  'payment_failure'),
    ('refunds.create',              'error',   'merchant',  'payment_failure'),
    ('payments.failed',             'success', 'system',    'payment_failure'),
    ('payments.capture',            'success', 'customer',  NULL),
    ('payments.capture',            'denied',  'customer',  NULL),
    ('refunds.create',              'success', 'merchant',  NULL),
    ('invoices.issue',              'error',   'system',    'invoice_failure'),
    ('invoices.failed',             'success', 'system',    'invoice_failure'),
    ('invoices.issue',              'success', 'system',    NULL),
    ('auth.login',                  'success', 'admin',     'superadmin_login'),
    ('auth.login',                  'denied',  'admin',     'superadmin_login'),
    ('auth.login',                  'success', 'customer',  NULL),
    ('auth.login',                  'denied',  'merchant',  NULL),
    ('audit.verify_failed',         'error',   'system',    'verify_failure'),
    ('audit.verify',                'success', 'system',    NULL),
    ('stores.update',               'success', 'merchant',  NULL),
    ('stores.update',               'success', 'db',        NULL),
    ('stores.ibanx',                'success', 'merchant',  'iban_change'),
    ('store.iban_update',           'success', 'merchant',  NULL),
    ('payment.capture',             'error',   'customer',  NULL),
    ('orders.create',               'error',   'customer',  NULL),
    ('tenants.suspend',             'success', 'admin',     NULL),
    -- Novos (0038): só com outcome success.
    ('platform_settings.update',    'success', 'db',        'commission_base_change'),
    ('platform_settings.update',    'success', 'admin',     'commission_base_change'),
    ('platform_settings.update',    'denied',  'admin',     NULL),
    ('platform_settings.update',    'error',   'db',        NULL),
    ('platform_settings.insert',    'success', 'db',        'commission_base_change'),
    ('platform_settings.delete',    'success', 'db',        'commission_base_change'),
    ('platform_settings.truncate',  'success', 'db',        'commission_base_change'),
    ('platform_settings.delete',    'denied',  'admin',     NULL),
    ('platform_settings.truncate',  'error',   'db',        NULL),
    ('platform_settings.select',    'success', 'admin',     NULL),
    ('billing_plan_tiers.insert',   'success', 'db',        'billing_tiers_change'),
    ('billing_plan_tiers.update',   'success', 'db',        'billing_tiers_change'),
    ('billing_plan_tiers.delete',   'success', 'admin',     'billing_tiers_change'),
    ('billing_plan_tiers.truncate', 'success', 'db',        'billing_tiers_change'),
    ('billing_plan_tiers.update',   'denied',  'admin',     NULL),
    ('billing_plan_tiers.insert',   'error',   'db',        NULL),
    ('billing_plan_tiers.select',   'success', 'admin',     NULL),
    ('store.commission_override',   'success', 'admin',     'store_commission_override'),
    ('store.commission_override',   'denied',  'admin',     NULL),
    ('store.commission_override',   'error',   'admin',     NULL),
    ('sponsorship.revoked',         'success', 'municipal', 'sponsorship_revoked'),
    ('sponsorship.revoked',         'success', 'admin',     'sponsorship_revoked'),
    ('sponsorship.revoked',         'denied',  'municipal', NULL),
    ('sponsorship.revoked',         'error',   'system',    NULL),
    ('sponsorship.revoke',          'success', 'municipal', NULL),
    ('store_sponsorships.update',   'success', 'municipal', NULL);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM kind_cases
       WHERE audit.critical_kind(action, outcome, actor_type) IS DISTINCT FROM expected$q$,
    0, 'critical_kind: 5 kinds antigos iguais; 4 kinds novos só com success; stores.update simples não é crítico');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES (audit.critical_kind(NULL, NULL, NULL)),
                                    (audit.critical_kind('sponsorship.revoked', NULL, NULL)),
                                    (audit.critical_kind('platform_settings.update', NULL, 'db'))) v(k)
       WHERE k IS NOT NULL$q$,
    0, 'critical_kind com outcome NULL nos kinds novos → NULL');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'audit.critical_kind(text, text, text)'::regprocedure
         AND provolatile = 'i' AND NOT prosecdef
         AND proowner = 'ptmarket_audit_owner'::regrole$q$,
    1, 'critical_kind continua IMMUTABLE, SECURITY INVOKER e do ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
       WHERE p.oid = 'audit.critical_kind(text, text, text)'::regprocedure
         AND a.grantee <> 'ptmarket_audit_owner'::regrole
         AND NOT (a.grantee = 'ptmarket_audit_writer'::regrole AND a.privilege_type = 'EXECUTE')$q$,
    0, 'critical_kind: EXECUTE só para ptmarket_audit_writer');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_constraint
       WHERE conrelid = 'audit.audit_alerts'::regclass AND conname = 'audit_alerts_kind_check'
         AND pg_get_constraintdef(oid) LIKE '%commission_base_change%'
         AND pg_get_constraintdef(oid) LIKE '%billing_tiers_change%'
         AND pg_get_constraintdef(oid) LIKE '%store_commission_override%'
         AND pg_get_constraintdef(oid) LIKE '%sponsorship_revoked%'
         AND pg_get_constraintdef(oid) LIKE '%verify_failure%'$q$,
    1, 'audit_alerts_kind_check aceita os 4 kinds novos e mantém os antigos');

-- ---------------------------------------------------------------------------
-- 2. L1 pelo migrator: platform_settings.* e billing_plan_tiers.* geram o alerta crítico.
--    TRUNCATE primeiro (com eventos diferidos pendentes do constraint trigger o TRUNCATE recusa-se); a continuidade
--    dos escalões nunca é verificada (ROLLBACK no fim).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_migrator;
TRUNCATE platform_settings;
INSERT INTO platform_settings DEFAULT VALUES;
UPDATE platform_settings SET base_commission_bps = base_commission_bps + 1;
UPDATE platform_settings SET base_commission_bps = base_commission_bps; -- sem diferenças: sem evento
DELETE FROM platform_settings;
TRUNCATE billing_plan_tiers;
INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
VALUES ('commission_payg', 0, NULL, 0, 800);
UPDATE billing_plan_tiers SET marginal_commission_bps = 700 WHERE plan_code = 'commission_payg';
DELETE FROM billing_plan_tiers WHERE plan_code = 'commission_payg';
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(DISTINCT payload->>'action') FROM audit.audit_alerts
       WHERE id NOT IN (SELECT id FROM alert_base)
         AND kind = 'commission_base_change' AND event_type = 'audit.critical' AND payload->>'actor_type' = 'db'
         AND payload->>'outcome' = 'success'
         AND payload->>'action' IN ('platform_settings.insert', 'platform_settings.update',
                                    'platform_settings.delete', 'platform_settings.truncate')$q$,
    4, 'INSERT/UPDATE/DELETE/TRUNCATE em platform_settings (migrator, L1) ⇒ alerta commission_base_change');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts
       WHERE id NOT IN (SELECT id FROM alert_base) AND kind = 'commission_base_change'$q$,
    4, 'exatamente 4 alertas commission_base_change (UPDATE sem diferenças não grava)');
SELECT pg_temp.expect_value(
    $q$SELECT count(DISTINCT payload->>'action') FROM audit.audit_alerts
       WHERE id NOT IN (SELECT id FROM alert_base)
         AND kind = 'billing_tiers_change' AND event_type = 'audit.critical' AND payload->>'actor_type' = 'db'
         AND payload->>'action' IN ('billing_plan_tiers.insert', 'billing_plan_tiers.update',
                                    'billing_plan_tiers.delete', 'billing_plan_tiers.truncate')$q$,
    4, 'INSERT/UPDATE/DELETE/TRUNCATE em billing_plan_tiers (migrator, L1) ⇒ alerta billing_tiers_change');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts
       WHERE id NOT IN (SELECT id FROM alert_base) AND kind = 'billing_tiers_change'$q$,
    4, 'exatamente 4 alertas billing_tiers_change (um por operação)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. Preparação para a app: tenant (migrator); lojas pela app com o ator admin.
-- ---------------------------------------------------------------------------
TRUNCATE alert_base;
INSERT INTO alert_base SELECT id FROM audit.audit_alerts;

SET ROLE ptmarket_migrator;
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000038a1', 'acc-npt', 'acc-npt.teste.invalid', 'Nacional PT 38', 'national_portal', 'PT');
RESET ROLE;

SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000038a1';
SET app.actor_type = 'admin';
SET app.actor_id = '00000000-0000-7000-8000-00000038adad';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000038b1', '00000000-0000-7000-8000-0000000038a1',
     'Loja L1', 'acc-l1', 'L1 Lda', '500003601', 'PT50000000000000000003601', 'l1@teste.invalid'),
    ('00000000-0000-7000-8000-0000000038b2', '00000000-0000-7000-8000-0000000038a1',
     'Loja L2', 'acc-l2', 'L2 Lda', '500003602', 'PT50000000000000000003602', 'l2@teste.invalid');

-- 3a. store.commission_override (função do super_admin, backoffice) e sponsorship.revoked (app, cartão 20).
SELECT audit.audit_append('store.commission_override', 'store', '00000000-0000-7000-8000-0000000038b1', 'success',
    NULL, '{"before": {"custom_commission_bps": null}, "after": {"custom_commission_bps": 500}}'::jsonb,
    '00000000-0000-7000-8000-0000000038b1') AS ovr_ok \gset
SELECT audit.audit_append('store.commission_override', 'store', '00000000-0000-7000-8000-0000000038b1', 'denied',
    'sem 2FA', NULL, '00000000-0000-7000-8000-0000000038b1') AS ovr_denied_admin \gset
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000038cc01';
SET app.store_id = '00000000-0000-7000-8000-0000000038b1';
SELECT audit.audit_append('store.commission_override', 'store', '00000000-0000-7000-8000-0000000038b1', 'denied',
    'sem permissão', NULL, '00000000-0000-7000-8000-0000000038b1') AS ovr_denied \gset
-- 3b. stores.update simples pela app (L1, ator merchant).
UPDATE stores SET name = 'Loja L1 nova' WHERE id = '00000000-0000-7000-8000-0000000038b1';
RESET app.store_id;
SET app.actor_type = 'municipal';
SET app.actor_id = '00000000-0000-7000-8000-00000038cc02';
SELECT audit.audit_append('sponsorship.revoked', 'store_sponsorship', 'sp-1', 'success', 'fim do protocolo',
    NULL, '00000000-0000-7000-8000-0000000038b1') AS rev_ok \gset
SELECT audit.audit_append('sponsorship.revoked', 'store_sponsorship', 'sp-1', 'denied', 'não é a entidade',
    NULL, '00000000-0000-7000-8000-0000000038b1') AS rev_denied \gset
RESET app.actor_type;
RESET app.actor_id;
RESET app.current_tenant_id;
RESET ROLE;
-- 3c. stores.update pelo superuser (custom_commission_bps; a app não escreve a coluna): L1 'stores.update', ator db.
UPDATE stores SET custom_commission_bps = 500 WHERE id = '00000000-0000-7000-8000-0000000038b1';

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'store_commission_override' AND event_type = 'audit.critical'
         AND payload->>'actor_type' = 'admin'$q$, :'ovr_ok'),
    1, 'store.commission_override de sucesso ⇒ 1 alerta store_commission_override');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind = 'sponsorship_revoked' AND event_type = 'audit.critical'
         AND payload->>'actor_type' = 'municipal'$q$, :'rev_ok'),
    1, 'sponsorship.revoked de sucesso ⇒ 1 alerta sponsorship_revoked');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts WHERE id IN (%L, %L)$q$, :'ovr_denied', :'rev_denied'),
    0, 'store.commission_override / sponsorship.revoked com denied (não admin) ⇒ nenhum alerta');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_alerts
       WHERE id = %L AND kind IS NULL AND event_type = 'audit.superadmin_action'$q$, :'ovr_denied_admin'),
    1, 'store.commission_override denied pelo admin ⇒ só o alerta de ação admin (kind NULL), não crítico');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_alerts
       WHERE id NOT IN (SELECT id FROM alert_base) AND payload->>'action' = 'stores.update'$q$,
    0, 'stores.update simples (app merchant e custom_commission_bps pelo superuser/L1) ⇒ nenhum alerta');
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE store_id = '00000000-0000-7000-8000-0000000038b1' AND action = 'stores.update'
         AND actor_type IN ('merchant', 'db')$q$,
    2, 'os dois stores.update estão na cadeia (merchant e db)');
RESET ROLE;
-- A CHECK alargada aceitou um alerta de cada kind novo (os alertas são só desta transação: ROLLBACK nos outros).
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(DISTINCT kind) FROM audit.audit_alerts
       WHERE kind IN ('commission_base_change', 'billing_tiers_change', 'store_commission_override',
                      'sponsorship_revoked')$q$,
    4, 'audit_alerts_kind_check aceita um alerta de cada kind novo');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Adenda: store_scope_read em audit.audit_events (RESTRICTIVE, SELECT, TO ptmarket_app).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'audit.audit_events'::regclass AND polname = 'store_scope_read'
         AND NOT polpermissive AND polcmd = 'r' AND polroles = ARRAY['ptmarket_app'::regrole::oid]$q$,
    1, 'store_scope_read: RESTRICTIVE, FOR SELECT, só ptmarket_app');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy p
       JOIN pg_depend d ON d.classid = 'pg_policy'::regclass AND d.objid = p.oid
       WHERE p.polrelid = 'audit.audit_events'::regclass AND p.polname = 'store_scope_read'
         AND d.refclassid = 'pg_proc'::regclass
         AND (SELECT pronamespace FROM pg_proc WHERE oid = d.refobjid) <> 'pg_catalog'::regnamespace$q$,
    0, 'store_scope_read só depende de funções de pg_catalog (nada de public)');
-- a) Partições: a app não tem nenhum privilégio direto (só o pai tem GRANT SELECT, que passa pelas policies).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_partition_tree('audit.audit_events') t
       WHERE t.relid <> 'audit.audit_events'::regclass
         AND (has_table_privilege('ptmarket_app', t.relid,
                  'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
              OR has_any_column_privilege('ptmarket_app', t.relid, 'SELECT, INSERT, UPDATE, REFERENCES'))$q$,
    0, 'a app não tem acesso direto a nenhuma partição de audit_events');
SET ROLE ptmarket_app;
SELECT pg_temp.expect_error(
    $q$SELECT count(*) FROM audit.audit_events_standard_default$q$, '42501', NULL,
    'a app não lê uma partição diretamente (fugiria à policy do pai)');
RESET ROLE;

-- b) A gravação é do writer (DEFINER): com app.store_id = L1 a app grava eventos de L2 e sem store_id.
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000038a1';
SET app.actor_type = 'merchant';
SET app.actor_id = '00000000-0000-7000-8000-00000038cc01';
SET app.store_id = '00000000-0000-7000-8000-0000000038b1';
SELECT audit.audit_append('test.scope', 'x', 'e1', 'success', NULL, NULL,
    '00000000-0000-7000-8000-0000000038b1') AS e1 \gset
SELECT audit.audit_append('test.scope', 'x', 'e2', 'success', NULL, NULL,
    '00000000-0000-7000-8000-0000000038b2') AS e2 \gset
SELECT audit.audit_append('test.scope', 'x', 'e0', 'success', NULL, NULL, NULL) AS e0 \gset
-- L1 (trigger, INVOKER) como app com app.store_id = L1: grava por audit_append (DEFINER) e não lê audit_events.
UPDATE stores SET name = 'Loja L1 outra' WHERE id = '00000000-0000-7000-8000-0000000038b1';
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L, %L)$q$, :'e0', :'e1', :'e2'),
    3, 'com app.store_id = L1 a app grava os eventos de L1, de L2 e sem loja (writer vê os 3)');
RESET ROLE;

SET ROLE ptmarket_app;
-- Lojista de L1 (app.store_id = L1).
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L, %L)$q$, :'e0', :'e1', :'e2'),
    1, 'lojista de L1 vê 1 dos 3 eventos');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L$q$, :'e1'),
    1, 'lojista de L1 lê o evento de L1');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE store_id = '00000000-0000-7000-8000-0000000038b2'$q$,
    0, 'lojista de L1 não lê nenhum evento de L2 do mesmo tenant');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE store_id IS DISTINCT FROM
           '00000000-0000-7000-8000-0000000038b1'$q$,
    0, 'lojista de L1 não lê eventos sem store_id do tenant (nem de outras lojas)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE action = 'stores.update'
         AND store_id = '00000000-0000-7000-8000-0000000038b1'$q$,
    3, 'lojista de L1 lê a L1 da sua loja (stores.update da app e do superuser)');
-- Impersonação não herda a exceção do admin.
SET app.actor_type = 'admin';
SET app.impersonator_id = '00000000-0000-7000-8000-00000038adad';
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L, %L)$q$, :'e0', :'e1', :'e2'),
    1, 'admin com impersonação e app.store_id = L1 vê só L1');
-- Admin sem impersonação: lê os dois (e os sem loja), mesmo com app.store_id.
RESET app.impersonator_id;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L, %L)$q$, :'e0', :'e1', :'e2'),
    3, 'admin sem impersonação lê L1, L2 e sem loja');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE store_id IS NULL AND action = 'tenants.insert'$q$,
    1, 'admin sem impersonação lê o tenants.insert do migrator (evento sem loja)');
-- Admin a impersonar sem app.store_id: 0.
RESET app.store_id;
SET app.impersonator_id = '00000000-0000-7000-8000-00000038adad';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events$q$, 0, 'admin a impersonar sem app.store_id ⇒ 0 eventos');
RESET app.impersonator_id;
-- Sem âmbito de loja nem admin: fechado (0 linhas), como a 0035.
SET app.actor_type = 'merchant';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events$q$, 0, 'sem app.store_id e sem admin (contexto de tenant) ⇒ 0 eventos');
SET app.store_id = '';
SET app.actor_type = 'customer';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events$q$, 0, 'app.store_id vazio (contexto de cliente) ⇒ 0 eventos');
RESET app.actor_type;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events$q$, 0, 'sem ator e sem app.store_id ⇒ 0 eventos');
-- tenant_read continua: o admin sem tenant não lê nada.
SET app.actor_type = 'admin';
RESET app.current_tenant_id;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L, %L)$q$, :'e0', :'e1', :'e2'),
    0, 'admin sem app.current_tenant_id nada (tenant_read intacta)');
RESET app.store_id;
RESET app.actor_type;
RESET app.actor_id;
RESET ROLE;

-- Equivalência: com os mesmos GUCs, a policy (expressões inline) mostra exatamente as linhas que as funções de
-- public (0035) mostrariam. Casos: app.store_id ausente/vazio/L1/L2, ator merchant/customer/admin/ausente,
-- impersonator_id ausente/vazio/preenchido.
CREATE TEMP TABLE scope_rows (id uuid, store_id uuid);
INSERT INTO scope_rows VALUES (:'e0', NULL), (:'e1', '00000000-0000-7000-8000-0000000038b1'),
                              (:'e2', '00000000-0000-7000-8000-0000000038b2');
GRANT SELECT ON scope_rows TO ptmarket_app;
CREATE TEMP TABLE scope_cases (store text, actor text, imp text);
INSERT INTO scope_cases
    SELECT s, a, i
    FROM unnest(ARRAY[NULL, '', '00000000-0000-7000-8000-0000000038b1', '00000000-0000-7000-8000-0000000038b2']) s,
         unnest(ARRAY[NULL, 'merchant', 'customer', 'admin']) a,
         unnest(ARRAY[NULL, '', '00000000-0000-7000-8000-00000038adad']) i;
GRANT SELECT ON scope_cases TO ptmarket_app;
CREATE FUNCTION pg_temp.scope_mismatches()
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    c     record;
    v_bad bigint := 0;
    v_n   bigint;
BEGIN
    FOR c IN SELECT * FROM scope_cases LOOP
        PERFORM set_config('app.store_id', COALESCE(c.store, ''), true);
        PERFORM set_config('app.actor_type', COALESCE(c.actor, ''), true);
        PERFORM set_config('app.impersonator_id', COALESCE(c.imp, ''), true);
        IF c.store IS NULL THEN
            RESET app.store_id;
        END IF;
        IF c.actor IS NULL THEN
            RESET app.actor_type;
        END IF;
        IF c.imp IS NULL THEN
            RESET app.impersonator_id;
        END IF;
        SELECT count(*) INTO v_n FROM (
            (SELECT e.id FROM audit.audit_events e JOIN scope_rows r ON r.id = e.id
             EXCEPT
             SELECT r.id FROM scope_rows r
             WHERE r.store_id = public.app_store_id() OR public.app_is_platform_admin())
            UNION ALL
            (SELECT r.id FROM scope_rows r
             WHERE r.store_id = public.app_store_id() OR public.app_is_platform_admin()
             EXCEPT
             SELECT e.id FROM audit.audit_events e JOIN scope_rows r ON r.id = e.id)) d;
        IF v_n > 0 THEN
            RAISE NOTICE 'diferença: store=% actor=% imp=%', c.store, c.actor, c.imp;
            v_bad := v_bad + 1;
        END IF;
    END LOOP;
    RESET app.store_id;
    RESET app.actor_type;
    RESET app.impersonator_id;
    RETURN v_bad;
END
$$;
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000038a1';
SELECT pg_temp.expect_value($q$SELECT count(*) FROM scope_cases$q$, 48, '48 combinações de GUCs');
SELECT pg_temp.expect_value($q$SELECT pg_temp.scope_mismatches()$q$, 0,
    'policy inline = public.app_store_id()/app_is_platform_admin() em todas as combinações');
-- app.store_id que não é uuid: as funções da 0035 dão 22P02 e a policy também (nunca mostra tudo).
SET app.store_id = 'nao-e-uuid';
SELECT pg_temp.expect_error($q$SELECT public.app_store_id()$q$, '22P02', NULL,
    'app_store_id() com app.store_id que não é uuid ⇒ 22P02');
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_events$q$, '22P02', NULL,
    'policy com app.store_id que não é uuid ⇒ 22P02 (como a função; nunca mostra tudo)');
SET app.actor_type = 'admin';
SELECT pg_temp.expect_error($q$SELECT count(*) FROM audit.audit_events$q$, '22P02', NULL,
    'policy com app.store_id que não é uuid e ator admin ⇒ 22P02');
RESET app.store_id;
RESET app.actor_type;
RESET app.current_tenant_id;
RESET ROLE;

-- c) A timeline do super_admin lê como writer (DEFINER), não como ptmarket_app: a policy não se lhe aplica.
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid IN (to_regprocedure('audit.admin_read_events(timestamptz,timestamptz,uuid,uuid,uuid,uuid,text,text,timestamptz,uuid,integer)'),
                     to_regprocedure('audit.audit_append(text,text,text,text,text,jsonb,uuid,uuid)'),
                     to_regprocedure('audit.audit_append_event(jsonb)'),
                     to_regprocedure('audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'),
                     to_regprocedure('audit._chain_insert(audit.audit_events,boolean,boolean)'))
         AND prosecdef AND proowner = 'ptmarket_audit_writer'::regrole$q$,
    5, 'admin_read_events, audit_append, audit_append_event, audit_append_db e _chain_insert: DEFINER do writer');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = to_regprocedure('public.identity_admin_read_events(timestamptz,timestamptz,uuid,uuid,uuid,uuid,text,text,timestamptz,uuid,integer)')
         AND prosecdef AND proowner = 'ptmarket_identity'::regrole$q$,
    1, 'porta da timeline: DEFINER de ptmarket_identity (não corre como ptmarket_app)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'audit.audit_events'::regclass
         AND 'ptmarket_audit_writer'::regrole::oid = ANY (polroles) AND NOT polpermissive$q$,
    0, 'nenhuma policy RESTRICTIVE para o writer em audit_events');

-- d) A selagem recusa uma policy de audit.* que dependa de public.app_store_id() (dono com LOGIN).
SELECT pg_temp.expect_error(
    $q$DO $x$ BEGIN
           CREATE POLICY probe_public ON audit.audit_events AS RESTRICTIVE FOR SELECT TO ptmarket_app
               USING (store_id = (SELECT public.app_store_id()) OR (SELECT public.app_is_platform_admin()));
           PERFORM audit_admin.audit_seal();
       END $x$$q$,
    'P0001', 'audit_seal: audit.* depende de objetos de papéis com LOGIN%',
    'audit_seal recusa a policy com public.app_store_id()/app_is_platform_admin() (dono = migrator, LOGIN)');

-- ---------------------------------------------------------------------------
-- 5. Selagem: alteração aplicada; o migrator não mexe na policy nem na função; audit_seal() passa.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied a
       JOIN audit_admin.sealed_changes c ON c.name = a.name
       WHERE a.name = '0038_critical_kinds_commission' AND c.requires = '0026_admin_read_events_v2'$q$,
    1, 'alteração aprovada 0038_critical_kinds_commission aplicada (exige 0026_admin_read_events_v2)');
SET ROLE ptmarket_migrator;
SELECT audit_admin.audit_seal();
SELECT pg_temp.expect_error(
    $q$DROP POLICY store_scope_read ON audit.audit_events$q$, '42501', NULL,
    'migrator não apaga store_scope_read');
SELECT pg_temp.expect_error(
    $q$ALTER POLICY store_scope_read ON audit.audit_events USING (true)$q$, '42501', NULL,
    'migrator não altera store_scope_read');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.critical_kind(p_action text, p_outcome text, p_actor_type text)
       RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT NULL::text'$q$,
    '42501', NULL, 'migrator não substitui critical_kind (selada)');
RESET ROLE;
DO $$ BEGIN RAISE NOTICE 'OK: audit_seal() continua a passar'; END $$;

ROLLBACK;
