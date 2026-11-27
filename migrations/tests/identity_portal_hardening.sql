-- Teste da 0021 (cartão 02/10b): email novo anula a verificação; código de recuperação de uso único (todos os papéis);
-- portal lê lojas de outros tenants só pela view portal_stores (sem colunas sensíveis); search_path das 4 DEFINER de
-- identidade = pg_catalog, pg_temp.
-- Preparação pelo dono das migrations só do que a app não consegue criar (cliente já verificado, contas de backoffice,
-- tenants): RLS FORCE desligado só durante o seed e reposto logo a seguir. Asserções de acesso com SET ROLE
-- ptmarket_app (ou ptmarket_worker onde se prova que não pode). Tudo numa transação com ROLLBACK.

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

CREATE FUNCTION pg_temp.as_actor(p_type text, p_id text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', p_type, true);
    PERFORM set_config('app.actor_id', p_id, true);
END
$$;

CREATE FUNCTION pg_temp.expect_no_seqscan(p_sql text, p_table text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_line text;
    v_plan text := '';
BEGIN
    PERFORM set_config('enable_seqscan', 'off', true);
    FOR v_line IN EXECUTE 'EXPLAIN (COSTS OFF) ' || p_sql LOOP
        v_plan := v_plan || v_line || E'\n';
    END LOOP;
    PERFORM set_config('enable_seqscan', 'on', true);
    IF v_plan LIKE '%Seq Scan on ' || p_table || ' %' OR v_plan LIKE '%Seq Scan on ' || p_table || E'\n%' THEN
        RAISE EXCEPTION 'FALHOU: % (seq scan em %)%', p_label, p_table, E'\n' || v_plan;
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- Tenants (globais):  P = portal nacional PT · A = municipal PT (canal da entidade EA) · B, M = municipais PT ·
--   E = portal nacional ES · H = tenant de contexto dos eventos de identidade.
--   Desde a 0033 as lojas só vivem em tenants national_portal (P, E). Desde a 0035 há um só national_portal por país:
--   o caso "tenant inativo" desativa o P dentro de um savepoint (secção C).
-- Clientes: C1 = 21c1 (verificado) · C2 = 21c2 (verificado).  Utilizadores: UX = 21e1 · UY = 21e2.
SELECT set_config('app.actor_label', 'test', true);
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000021f9', true);

INSERT INTO tenants (id, slug, custom_domain, name, tenant_type, country_code, is_active) VALUES
    ('00000000-0000-7000-8000-0000000021f0', 'h21-portal', 'h21-portal.teste.invalid', 'Portal PT', 'national_portal', 'PT', true),
    ('00000000-0000-7000-8000-0000000021a0', 'h21-a', 'h21-a.teste.invalid', 'Tenant A', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000021b0', 'h21-b', 'h21-b.teste.invalid', 'Tenant B', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000021c0', 'h21-m', 'h21-m.teste.invalid', 'Tenant M', 'municipal', 'PT', true),
    ('00000000-0000-7000-8000-0000000021e0', 'h21-e', 'h21-e.teste.invalid', 'Portal ES', 'national_portal', 'ES', true),
    ('00000000-0000-7000-8000-0000000021f9', 'h21-h', 'h21-h.teste.invalid', 'Tenant H', 'municipal', 'PT', true);

ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
INSERT INTO customers (id, email, name, password_hash, email_verified_at) VALUES
    ('00000000-0000-7000-8000-0000000021c1', 'h21.c1@teste.invalid', 'Cliente Um', '$argon2id$v=19$m=19456,t=2,p=1$QzE$QzI',
     now() - interval '1 day'),
    ('00000000-0000-7000-8000-0000000021c2', 'h21.c2@teste.invalid', 'Cliente Dois', NULL, now() - interval '1 day');
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
INSERT INTO users (id, email, full_name, password_hash) VALUES
    ('00000000-0000-7000-8000-0000000021e1', 'h21.ux@teste.invalid', 'Utilizador X', '$argon2id$v=19$m=19456,t=2,p=1$VVg$VVg'),
    ('00000000-0000-7000-8000-0000000021e2', 'h21.uy@teste.invalid', 'Utilizador Y', NULL);
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- A. customers: mudar o email anula a verificação.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'customers'::regclass AND tgname = 'customers_email_unverify' AND tgenabled = 'A'
         AND tgfoid = 'customers_email_unverify()'::regprocedure$q$,
    1, 'customers: trigger customers_email_unverify (ALWAYS)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc
       WHERE oid = 'customers_email_unverify()'::regprocedure AND NOT prosecdef
         AND proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    1, 'customers_email_unverify: INVOKER, search_path = pg_catalog, pg_temp');

SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('customer', '00000000-0000-7000-8000-0000000021c1');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET name = 'Cliente Um B' WHERE id = '00000000-0000-7000-8000-0000000021c1'$q$,
    1, 'C1 muda só o nome');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000021c1' AND email_verified_at IS NOT NULL$q$,
    1, 'mudar só o nome não altera email_verified_at');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET email = 'h21.c1@teste.invalid' WHERE id = '00000000-0000-7000-8000-0000000021c1'$q$,
    1, 'C1 reescreve o mesmo email');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000021c1' AND email_verified_at IS NOT NULL$q$,
    1, 'o mesmo email não anula a verificação');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET email = 'h21.c1.novo@teste.invalid' WHERE id = '00000000-0000-7000-8000-0000000021c1'$q$,
    1, 'C1 muda o email');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000021c1' AND email_verified_at IS NULL$q$,
    1, 'email novo → email_verified_at NULL');
SELECT pg_temp.expect_error(
    $q$UPDATE customers SET email = 'h21.c1.x@teste.invalid', email_verified_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000021c1'$q$,
    '42501', 'app continua sem UPDATE de email_verified_at');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.update' AND target_id = '00000000-0000-7000-8000-0000000021c1'
         AND actor_type = 'customer' AND actor_id = '00000000-0000-7000-8000-0000000021c1'
         AND changes->'after'->>'email' = '[pii]'
         AND changes->'before'->>'email_verified_at' IS NOT NULL
         AND changes->'after' ? 'email_verified_at' AND changes->'after'->'email_verified_at' = 'null'::jsonb$q$,
    1, 'evento L1 da mudança de email mostra email_verified_at → null');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.update' AND target_id = '00000000-0000-7000-8000-0000000021c1'
         AND (changes->'after' ? 'email_verified_at' OR changes->'before' ? 'email_verified_at')$q$,
    1, 'só esse evento mexe em email_verified_at (a mudança de nome não)');
RESET ROLE;

-- Fluxo futuro (dono, ator db): confirmar o email novo no MESMO UPDATE não é anulado.
SELECT set_config('app.actor_type', '', true);
ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET email = 'h21.c2.novo@teste.invalid', email_verified_at = now()
       WHERE id = '00000000-0000-7000-8000-0000000021c2'$q$,
    1, 'dono muda email e confirma-o no mesmo UPDATE');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000021c2' AND email_verified_at = now()$q$,
    1, 'confirmação no mesmo UPDATE fica');
SELECT pg_temp.expect_rows(
    $q$UPDATE customers SET email = 'h21.c2.outro@teste.invalid' WHERE id = '00000000-0000-7000-8000-0000000021c2'$q$,
    1, 'dono muda só o email');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM customers
       WHERE id = '00000000-0000-7000-8000-0000000021c2' AND email_verified_at IS NULL$q$,
    1, 'também para o dono: email novo sem confirmação → NULL');
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- B. user_recovery_codes: uso único para todos os papéis.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_trigger
       WHERE tgrelid = 'user_recovery_codes'::regclass AND tgname = 'user_recovery_codes_use_once'
         AND tgenabled = 'A' AND tgfoid = 'user_recovery_codes_use_once()'::regprocedure$q$,
    1, 'user_recovery_codes: trigger user_recovery_codes_use_once (ALWAYS)');

SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000021e1');
INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES
    ('00000000-0000-7000-8000-000000002181', '00000000-0000-7000-8000-0000000021e1', sha256('h21-rc-x1'::bytea)),
    ('00000000-0000-7000-8000-000000002182', '00000000-0000-7000-8000-0000000021e1', sha256('h21-rc-x2'::bytea));
SELECT pg_temp.as_actor('admin', '00000000-0000-7000-8000-0000000021e2');
INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES
    ('00000000-0000-7000-8000-000000002183', '00000000-0000-7000-8000-0000000021e2', sha256('h21-rc-y1'::bytea));

SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000021e1');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_recovery_codes SET used_at = '2000-01-01T00:00:00Z'
       WHERE id = '00000000-0000-7000-8000-000000002181' AND used_at IS NULL$q$,
    1, 'X consome o código (UPDATE … WHERE used_at IS NULL → 1 linha)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_recovery_codes
       WHERE id = '00000000-0000-7000-8000-000000002181' AND used_at = now()$q$,
    1, 'used_at = now() (a data da app é ignorada)');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_recovery_codes SET used_at = now()
       WHERE id = '00000000-0000-7000-8000-000000002181' AND used_at IS NULL$q$,
    0, 'consumo certo repetido → 0 linhas');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET used_at = NULL WHERE id = '00000000-0000-7000-8000-000000002181'$q$,
    '23514', 'repor used_at = NULL → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET used_at = now() - interval '1 day'
       WHERE id = '00000000-0000-7000-8000-000000002181'$q$,
    '23514', 'mudar a data de um código usado → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET used_at = now() WHERE id = '00000000-0000-7000-8000-000000002181'$q$,
    '23514', 'consumir outra vez (sem filtro) → 23514');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM user_recovery_codes WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    0, 'o código de Y continua invisível para X');
SELECT pg_temp.expect_rows(
    $q$UPDATE user_recovery_codes SET used_at = now() WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    0, 'X não consome o código de Y');
SELECT pg_temp.expect_rows(
    $q$DELETE FROM user_recovery_codes WHERE id = '00000000-0000-7000-8000-000000002181'$q$,
    1, 'DELETE de um código usado continua permitido (regenerar a lista)');
RESET ROLE;

-- O dono (sem FORCE) também não reutiliza nem altera colunas fixas.
SELECT set_config('app.actor_type', '', true);
ALTER TABLE user_recovery_codes NO FORCE ROW LEVEL SECURITY;
UPDATE user_recovery_codes SET used_at = now() WHERE id = '00000000-0000-7000-8000-000000002182';
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET used_at = NULL WHERE id = '00000000-0000-7000-8000-000000002182'$q$,
    '23514', 'dono: repor used_at = NULL → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET code_hash = sha256('outro'::bytea) WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    '23514', 'dono: mudar code_hash → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET user_id = '00000000-0000-7000-8000-0000000021e1'
       WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    '23514', 'dono: mudar user_id → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET created_at = now() - interval '1 day'
       WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    '23514', 'dono: mudar created_at → 23514');
SELECT pg_temp.expect_error(
    $q$UPDATE user_recovery_codes SET id = '00000000-0000-7000-8000-000000002189'
       WHERE id = '00000000-0000-7000-8000-000000002183'$q$,
    '23514', 'dono: mudar id → 23514');
ALTER TABLE user_recovery_codes FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- C. Portal: lojas de outros tenants só por portal_stores (visibilidade por canal desde a 0033).
-- ---------------------------------------------------------------------------
-- Entidade EA (associação, canal A), escrita pelo migrator (policy migrator_all).
INSERT INTO sponsor_entities (id, kind, country_code, name, slug, channel_tenant_id) VALUES
    ('00000000-0000-7000-8000-0000000021ea', 'association', 'PT', 'Associação H21', 'h21-assoc',
     '00000000-0000-7000-8000-0000000021a0');

SET ROLE ptmarket_app;
-- Seed de várias lojas de seguida: ator admin (âmbito por loja da 0035); as leituras voltam a 'system'.
SELECT pg_temp.as_actor('admin', '');
-- Todas no portal P: a1 publicada · a2 não publicada · a3 publicada mas inativa · b1 publicada · m1 não publicada.
-- E (portal ES): e1 publicada. EA patrocina a1, b1 e a3 (ativo e vigente).
-- custom_commission_bps/kyc_verified ficam no default: desde a 0029 a app não os escreve (as asserções do portal
-- abaixo não dependem do valor).
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021f0';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, phone, eupago_split_key,
                    invoicing_credentials_enc, stripe_account_id,
                    invoicing_provider, shipping_config, publish_to_national_portal, is_active, vat_exempt_art53) VALUES
    ('00000000-0000-7000-8000-00000021a001', '00000000-0000-7000-8000-0000000021f0', 'Loja A1', 'h21-a1', 'A1 Lda',
     '500002101', 'PT50000000000000000002101', 'a1@teste.invalid', '+351210000001', 'split-a1', 'enc-a1', 'acct_a1',
     'moloni', '{"zona": "a1"}', true, true, true),
    ('00000000-0000-7000-8000-00000021a002', '00000000-0000-7000-8000-0000000021f0', 'Loja A2', 'h21-a2', 'A2 Lda',
     '500002102', 'PT50000000000000000002102', 'a2@teste.invalid', NULL, 'split-a2', 'enc-a2', 'acct_a2',
     'moloni', '{}', false, true, false),
    ('00000000-0000-7000-8000-00000021a003', '00000000-0000-7000-8000-0000000021f0', 'Loja A3', 'h21-a3', 'A3 Lda',
     '500002103', 'PT50000000000000000002103', 'a3@teste.invalid', NULL, NULL, NULL, NULL,
     'none', '{}', true, false, false);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps, is_published) VALUES
    ('00000000-0000-7000-8000-00000021a101', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021a001', '{"pt":"Produto A1"}', 0, true);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000021a201', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021a101', 500);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, eupago_split_key, stripe_account_id,
                    publish_to_national_portal) VALUES
    ('00000000-0000-7000-8000-00000021b001', '00000000-0000-7000-8000-0000000021f0', 'Loja B1', 'h21-b1', 'B1 Lda',
     '500002111', 'PT50000000000000000002111', 'b1@teste.invalid', 'split-b1', 'acct_b1', true);
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-00000021b101', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021b001', '{"pt":"Produto B1"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents) VALUES
    ('00000000-0000-7000-8000-00000021b201', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021b101', 700);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-00000021c001', '00000000-0000-7000-8000-0000000021f0', 'Loja M1', 'h21-m1', 'M1 Lda',
     '500002121', 'PT50000000000000000002121', 'm1@teste.invalid');
-- 0035: o pedido de patrocínio é sempre da loja do contexto (app.store_id = store_id).
SET app.store_id = '00000000-0000-7000-8000-00000021a001';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000021b5', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021a001', '00000000-0000-7000-8000-0000000021ea');
SET app.store_id = '00000000-0000-7000-8000-00000021b001';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000021b6', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021b001', '00000000-0000-7000-8000-0000000021ea');
SET app.store_id = '00000000-0000-7000-8000-00000021a003';
INSERT INTO store_sponsorships (id, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-0000000021b7', '00000000-0000-7000-8000-0000000021f0',
     '00000000-0000-7000-8000-00000021a003', '00000000-0000-7000-8000-0000000021ea');
RESET app.store_id;
UPDATE store_sponsorships SET status = 'active', valid_from = now() - interval '1 day'
WHERE tenant_id = '00000000-0000-7000-8000-0000000021f0';
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021e0';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, publish_to_national_portal) VALUES
    ('00000000-0000-7000-8000-00000021e001', '00000000-0000-7000-8000-0000000021e0', 'Tienda E1', 'h21-e1', 'E1 SL',
     'B00002131', 'ES9100000000000000002131', 'e1@teste.invalid', true);
SELECT pg_temp.as_actor('system', '');

-- Canal A (white-label, com a flag: não muda nada num tenant municipal).
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021a0';
SET app.portal_national = 'on';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 0, 'canal A: modo portal nacional desligado');

DO $$
DECLARE
    c text;
BEGIN
    FOREACH c IN ARRAY ARRAY['iban', 'eupago_split_key', 'invoicing_credentials_enc', 'stripe_account_id',
                             'custom_commission_bps', 'kyc_verified', 'invoicing_provider', 'shipping_config'] LOOP
        PERFORM pg_temp.expect_count(
            format($q$SELECT count(*) FROM (SELECT %I FROM stores
                      WHERE tenant_id <> '00000000-0000-7000-8000-0000000021a0') s$q$, c),
            0, format('canal A: SELECT %s FROM stores de outro tenant → 0 linhas', c));
        PERFORM pg_temp.expect_error(
            format('SELECT %I FROM portal_stores', c), '42703',
            format('canal A: SELECT %s FROM portal_stores → 42703', c));
    END LOOP;
END
$$;
SELECT pg_temp.expect_count('SELECT count(*) FROM stores', 0, 'canal A: stores só mostra as suas (nenhuma)');

SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores
       WHERE id IN ('00000000-0000-7000-8000-00000021a001', '00000000-0000-7000-8000-00000021b001')$q$,
    2, 'canal A: portal_stores mostra as lojas patrocinadas por EA (A1 e B1)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores
       WHERE id IN ('00000000-0000-7000-8000-00000021a002', '00000000-0000-7000-8000-00000021c001',
                    '00000000-0000-7000-8000-00000021a003', '00000000-0000-7000-8000-00000021e001')$q$,
    0, 'canal A: portal_stores sem lojas não patrocinadas, inativas ou de outro país');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores
       WHERE id = '00000000-0000-7000-8000-00000021a001' AND legal_name = 'A1 Lda' AND nif = '500002101'
         AND email = 'a1@teste.invalid' AND phone = '+351210000001' AND vat_exempt_art53$q$,
    1, 'portal_stores tem os dados de exibição obrigatória (DSA, DL 7/2004, Art. 53.º)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products
       WHERE id IN ('00000000-0000-7000-8000-00000021a101', '00000000-0000-7000-8000-00000021b101')$q$,
    2, 'canal A: produtos publicados das lojas visíveis continuam visíveis');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM product_variants
       WHERE id IN ('00000000-0000-7000-8000-00000021a201', '00000000-0000-7000-8000-00000021b201')$q$,
    2, 'canal A: variantes desses produtos continuam visíveis');
SELECT pg_temp.expect_no_seqscan(
    $q$SELECT id FROM products WHERE tenant_id = '00000000-0000-7000-8000-0000000021f0'
                                 AND store_id = '00000000-0000-7000-8000-00000021b001'$q$,
    'products', 'canal A: produtos por loja sem seq scan');
SELECT pg_temp.expect_error(
    $q$INSERT INTO portal_stores (tenant_id, name, slug, legal_name, nif, email)
       VALUES ('00000000-0000-7000-8000-0000000021f0', 'Intrusa', 'h21-intrusa', 'I', '1', 'i@teste.invalid')$q$,
    '42501', 'portal: INSERT em portal_stores falha');
SELECT pg_temp.expect_error(
    $q$UPDATE portal_stores SET name = 'pirata' WHERE id = '00000000-0000-7000-8000-00000021a001'$q$,
    '42501', 'portal: UPDATE em portal_stores falha');
SELECT pg_temp.expect_error(
    $q$DELETE FROM portal_stores WHERE id = '00000000-0000-7000-8000-00000021a001'$q$,
    '42501', 'portal: DELETE em portal_stores falha');

-- Tenant municipal sem entidade, com a flag: nada de terceiros.
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021c0';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'municipal M com flag: portal_stores vazia');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM stores WHERE tenant_id <> '00000000-0000-7000-8000-0000000021c0'$q$,
    0, 'municipal M com flag: 0 lojas de terceiros em stores');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM products WHERE tenant_id <> '00000000-0000-7000-8000-0000000021c0'$q$,
    0, 'municipal M com flag: 0 produtos de terceiros');

-- Portal P com a flag: todas as lojas ativas de P (A2 e M1 sem opt-in incluídas); nada de E.
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021f0';
SELECT pg_temp.expect_count('SELECT (SELECT app_is_national_portal())::int', 1, 'portal P: modo portal ativo');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM portal_stores
       WHERE id IN ('00000000-0000-7000-8000-00000021a001', '00000000-0000-7000-8000-00000021a002',
                    '00000000-0000-7000-8000-00000021b001', '00000000-0000-7000-8000-00000021c001')$q$,
    4, 'portal P: portal_stores mostra as 4 lojas ativas de P');
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 4,
    'portal P: sem loja inativa nem de outro país');
-- Tenant da loja inativo (0035: um só national_portal por país): o P é desativado só dentro deste savepoint.
SAVEPOINT h21_ni;
RESET ROLE;
UPDATE tenants SET is_active = false WHERE id = '00000000-0000-7000-8000-0000000021f0';
SET ROLE ptmarket_app;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal P inativo: portal_stores vazia');
SET app.current_tenant_id = '00000000-0000-7000-8000-0000000021a0';
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0,
    'canal A: lojas patrocinadas por EA num tenant inativo não aparecem');
ROLLBACK TO SAVEPOINT h21_ni;
RESET app.portal_national;
SELECT pg_temp.expect_count('SELECT count(*) FROM portal_stores', 0, 'portal P sem flag: portal_stores vazia');
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000021f9', true);
RESET ROLE;

-- Catálogo.
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_roles
       WHERE rolname = 'ptmarket_portal' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
         AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication$q$,
    1, 'ptmarket_portal: NOLOGIN, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class
       WHERE oid = 'portal_stores'::regclass AND relkind = 'v' AND relowner = 'ptmarket_portal'::regrole
         AND reloptions @> ARRAY['security_barrier=true']$q$,
    1, 'portal_stores: view security_barrier, dona ptmarket_portal');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (
         SELECT array_agg(attname::text ORDER BY attnum) AS cols FROM pg_attribute
         WHERE attrelid = 'portal_stores'::regclass AND attnum > 0 AND NOT attisdropped) a
       WHERE a.cols = ARRAY['id', 'tenant_id', 'name', 'slug', 'legal_name', 'nif', 'email', 'phone', 'address_json',
                            'geo_lat', 'geo_lng', 'business_hours', 'is_vacation_mode', 'vacation_message',
                            'supports_click_collect', 'supports_local_courier', 'supports_national_shipping',
                            'vat_exempt_art53', 'shipping_scope', 'storefront_address', 'storefront_dicofre']$q$,
    1, 'portal_stores: exatamente as 21 colunas de exibição (as 18 da 0021 + 3 da 0033 no fim)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['iban', 'eupago_split_key', 'invoicing_credentials_enc', 'stripe_account_id',
                                         'custom_commission_bps', 'kyc_verified', 'invoicing_provider',
                                         'shipping_config', 'created_at', 'publish_to_national_portal']) AS c(col)
       WHERE has_column_privilege('ptmarket_portal', 'stores', c.col, 'SELECT')$q$,
    0, 'ptmarket_portal não lê nenhuma coluna sensível de stores');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['stores', 'tenants']) AS t(tab),
                            unnest(ARRAY['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) AS p(priv)
       WHERE has_table_privilege('ptmarket_portal', t.tab, p.priv)
          OR (p.priv IN ('INSERT', 'UPDATE') AND has_any_column_privilege('ptmarket_portal', t.tab, p.priv))$q$,
    0, 'ptmarket_portal sem escrita em stores e tenants');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['slug', 'custom_domain', 'name', 'theme_config', 'legal_config',
                                         'default_commission_bps', 'tenant_type']) AS c(col)
       WHERE has_column_privilege('ptmarket_portal', 'tenants', c.col, 'SELECT')$q$,
    0, 'ptmarket_portal em tenants só lê id, is_active, country_code');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_class c, aclexplode(c.relacl) a
       WHERE c.oid = 'portal_stores'::regclass AND a.grantee <> c.relowner
         AND NOT (a.grantee = 'ptmarket_app'::regrole AND a.privilege_type = 'SELECT')$q$,
    0, 'portal_stores: só SELECT para ptmarket_app (nada para PUBLIC, worker ou price_writer)');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'stores'::regclass AND polname = 'portal_read'$q$,
    0, 'stores: policy portal_read de ptmarket_app removida');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'stores'::regclass AND polname = 'portal_view' AND polcmd = 'r'
         AND polroles = ARRAY['ptmarket_portal'::regrole::oid]$q$,
    1, 'stores: policy portal_view FOR SELECT TO ptmarket_portal');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_policy
       WHERE polrelid = 'stores'::regclass AND polname = 'tenant_isolation'$q$,
    1, 'stores: tenant_isolation intacta');

-- ---------------------------------------------------------------------------
-- D. search_path das 4 DEFINER de identidade.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('identity_customer_credentials(text)'::regprocedure,
                       'identity_user_credentials(text)'::regprocedure,
                       'identity_session_lookup(bytea)'::regprocedure,
                       'identity_passkey_lookup(bytea)'::regprocedure)
         AND p.prosecdef AND p.provolatile = 's' AND p.proowner = 'ptmarket_identity'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']$q$,
    4, 'as 4 funções: DEFINER, STABLE, dono ptmarket_identity, search_path = pg_catalog, pg_temp');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM (VALUES
         ('identity_customer_credentials(text)', 'TABLE(id uuid, password_hash text)'),
         ('identity_user_credentials(text)', 'TABLE(id uuid, password_hash text, totp_enabled boolean)'),
         ('identity_session_lookup(bytea)',
          'TABLE(id uuid, subject_type character varying, subject_id uuid, tenant_id uuid, mfa_verified_at timestamp with time zone, impersonator_user_id uuid, created_at timestamp with time zone, expires_at timestamp with time zone)'),
         ('identity_passkey_lookup(bytea)', 'TABLE(id uuid, user_id uuid, credential jsonb, sign_count bigint)')
       ) AS f(fn, res)
       WHERE pg_get_function_result(f.fn::regprocedure) = f.res$q$,
    4, 'as 4 funções: mesmo retorno');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM unnest(ARRAY['identity_customer_credentials(text)', 'identity_user_credentials(text)',
                                         'identity_session_lookup(bytea)', 'identity_passkey_lookup(bytea)']) AS f(fn)
       WHERE has_function_privilege('ptmarket_app', f.fn, 'EXECUTE')
         AND NOT has_function_privilege('ptmarket_worker', f.fn, 'EXECUTE')
         AND NOT has_function_privilege('ptmarket_price_writer', f.fn, 'EXECUTE')$q$,
    4, 'as 4 funções: EXECUTE para ptmarket_app, não para worker nem price_writer');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_proc p, aclexplode(p.proacl) a
       WHERE p.oid IN ('identity_customer_credentials(text)'::regprocedure,
                       'identity_user_credentials(text)'::regprocedure,
                       'identity_session_lookup(bytea)'::regprocedure,
                       'identity_passkey_lookup(bytea)'::regprocedure)
         AND a.grantee = 0$q$,
    0, 'as 4 funções: sem EXECUTE para PUBLIC');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM pg_namespace
       WHERE nspname = 'public' AND has_schema_privilege('ptmarket_identity', oid, 'CREATE')$q$,
    0, 'ptmarket_identity sem CREATE no schema public');

-- Mesmo resultado que antes (dados criados pela app).
SET ROLE ptmarket_app;
SELECT pg_temp.as_actor('merchant', '00000000-0000-7000-8000-0000000021e1');
INSERT INTO sessions (id, subject_type, subject_id, token_hash, tenant_id, expires_at) VALUES
    ('00000000-0000-7000-8000-0000000021d1', 'user', '00000000-0000-7000-8000-0000000021e1', sha256('h21-tok'::bytea),
     '00000000-0000-7000-8000-0000000021a0', now() + interval '1 hour');
INSERT INTO user_passkeys (id, user_id, credential_id, credential, label) VALUES
    ('00000000-0000-7000-8000-0000000021f1', '00000000-0000-7000-8000-0000000021e1', '\xbeef21'::bytea,
     '{"alg": -7}', 'Chave UX');
SELECT pg_temp.as_actor('anonymous', '');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_customer_credentials('H21.C1.NOVO@teste.invalid')
       WHERE id = '00000000-0000-7000-8000-0000000021c1' AND password_hash = '$argon2id$v=19$m=19456,t=2,p=1$QzE$QzI'$q$,
    1, 'identity_customer_credentials devolve id + hash');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_user_credentials('h21.ux@teste.invalid')
       WHERE id = '00000000-0000-7000-8000-0000000021e1' AND password_hash LIKE '$argon2id$%' AND NOT totp_enabled$q$,
    1, 'identity_user_credentials devolve id + hash + totp_enabled');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_session_lookup(sha256('h21-tok'::bytea))
       WHERE id = '00000000-0000-7000-8000-0000000021d1' AND subject_type = 'user'
         AND subject_id = '00000000-0000-7000-8000-0000000021e1'
         AND tenant_id = '00000000-0000-7000-8000-0000000021a0'$q$,
    1, 'identity_session_lookup devolve a sessão válida');
SELECT pg_temp.expect_count(
    $q$SELECT count(*) FROM identity_passkey_lookup('\xbeef21'::bytea)
       WHERE id = '00000000-0000-7000-8000-0000000021f1' AND user_id = '00000000-0000-7000-8000-0000000021e1'
         AND credential = '{"alg": -7}'::jsonb AND sign_count = 0$q$,
    1, 'identity_passkey_lookup devolve a passkey');
RESET ROLE;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$SELECT * FROM identity_session_lookup(sha256('h21-tok'::bytea))$q$, '42501', 'worker não executa o lookup');
RESET ROLE;

ROLLBACK;
