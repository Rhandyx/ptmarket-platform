-- Teste da caixa negra L1 (0010): trigger genérico em todas as tabelas, ator obrigatório, máscara.
-- Corre como ptmarket_migrator (LOGIN, não superuser): o session_user é o migrator, como nas migrations.
-- Leituras de eventos sempre com SET ROLE ptmarket_app + contexto do tenant (política tenant_read).
-- Tudo numa transação com ROLLBACK (os eventos gravados aqui desaparecem com ela).

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

-- Tabelas de public sem os dois triggers L1 ativos (ENABLE ALWAYS) a apontar para audit.audit_row_trigger.
-- Allowlist FIXA (spec 13 §0): audit_events, audit_chain_heads, outbox_events.
-- tgtype: zz_audit_row = ROW|INSERT|DELETE|UPDATE (AFTER) = 29; zz_audit_truncate = BEFORE|TRUNCATE = 34.
CREATE FUNCTION pg_temp.l1_uncovered()
RETURNS SETOF text LANGUAGE sql AS $$
    SELECT c.relname::text
    FROM pg_class c
    WHERE c.relnamespace = 'public'::regnamespace
      AND c.relkind IN ('r', 'p')
      AND NOT c.relispartition
      AND c.relname NOT IN ('audit_events', 'audit_chain_heads', 'outbox_events')
      AND NOT (
          EXISTS (SELECT 1 FROM pg_trigger t
                  WHERE t.tgrelid = c.oid AND t.tgname = 'zz_audit_row' AND t.tgenabled = 'A'
                    AND t.tgtype = 29 AND t.tgfoid = 'audit.audit_row_trigger()'::regprocedure)
          AND EXISTS (SELECT 1 FROM pg_trigger t
                      WHERE t.tgrelid = c.oid AND t.tgname = 'zz_audit_truncate' AND t.tgenabled = 'A'
                        AND t.tgtype = 34 AND t.tgfoid = 'audit.audit_row_trigger()'::regprocedure))
$$;

-- Eventos visíveis ao papel corrente: marca e diferença (para provar "nada gravado").
CREATE FUNCTION pg_temp.l1_mark()
RETURNS void LANGUAGE sql AS $$
    SELECT set_config('ptm.l1_n', (SELECT count(*) FROM audit.audit_events)::text, true);
$$;
CREATE FUNCTION pg_temp.l1_delta()
RETURNS bigint LANGUAGE sql AS $$
    SELECT (SELECT count(*) FROM audit.audit_events) - current_setting('ptm.l1_n')::bigint;
$$;

-- Colunas de nome sensível em claro nos eventos legíveis pelo papel corrente (regra do §3.5).
CREATE FUNCTION pg_temp.l1_leaks()
RETURNS bigint LANGUAGE sql AS $$
    SELECT count(*)
    FROM audit.audit_events e
    CROSS JOIN LATERAL (VALUES (e.changes->'before'), (e.changes->'after')) AS s(obj)
    CROSS JOIN LATERAL jsonb_each(CASE WHEN jsonb_typeof(s.obj) = 'object' THEN s.obj ELSE '{}' END) AS c
    WHERE c.value <> 'null'::jsonb
      AND (   (c.key ~* '(password|secret|token|credential|passkey|split_key|_enc$|_hash$)'
               AND c.value <> '"[redacted]"'::jsonb)
           OR (c.key ~* 'iban' AND NOT (c.value #>> '{}') ~ '^\*{4}.{0,4}$')
           OR (c.key ~* '(^|_)ip(_|$)' AND c.value <> '"[pii]"'::jsonb))
$$;
-- Sem ator e sem tenant no início (a sessão é do migrator).
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.actor_label', '', true);
SELECT set_config('app.actor_id', '', true);
SELECT set_config('app.current_tenant_id', '', true);

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_roles WHERE rolname = session_user AND rolname = 'ptmarket_migrator'
       AND rolcanlogin AND NOT rolsuper$q$,
    1, 'sessão = ptmarket_migrator (LOGIN, não superuser)');

-- ---------------------------------------------------------------------------
-- 1. Cobertura: nenhuma tabela fora da allowlist sem L1; o teste apanha tabelas novas.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.l1_uncovered()$q$, 0, 'todas as tabelas de public têm zz_audit_row + zz_audit_truncate (ALWAYS)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_class c
       WHERE c.relnamespace = 'public'::regnamespace
         AND c.relname IN ('tenants', 'categories', 'stores', 'products', 'product_variants', 'customers',
                           'product_price_history', '_sqlx_migrations')
         AND c.relname NOT IN (SELECT * FROM pg_temp.l1_uncovered())$q$,
    8, 'retrofit: as 8 tabelas de 0002–0007 e _sqlx_migrations cobertas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_trigger t
       WHERE t.tgrelid = 'public.outbox_events'::regclass AND t.tgname LIKE 'zz_audit%'$q$,
    0, 'outbox_events fica de fora (allowlist)');

-- L2 (0013): uma tabela nova de public recebe sozinha os dois triggers (event trigger, ENABLE ALWAYS).
CREATE TABLE public.ptm_l1_bare (id int);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.l1_uncovered() u WHERE u = 'ptm_l1_bare'$q$, 0, 'tabela nova coberta sem CREATE TRIGGER manual');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_trigger t
       WHERE t.tgrelid = 'public.ptm_l1_bare'::regclass AND t.tgenabled = 'A'
         AND t.tgfoid = 'audit.audit_row_trigger()'::regprocedure
         AND ((t.tgname = 'zz_audit_row' AND t.tgtype = 29) OR (t.tgname = 'zz_audit_truncate' AND t.tgtype = 34))$q$,
    2, 'tabela nova: zz_audit_row + zz_audit_truncate com tgenabled A');
DROP TABLE public.ptm_l1_bare;

-- ---------------------------------------------------------------------------
-- 2. Selagem: o migrator não substitui a função de trigger, mas põe L1 numa tabela nova.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.pronamespace = 'audit'::regnamespace AND has_function_privilege(p.oid, 'EXECUTE')
         AND p.oid NOT IN ('audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'::regprocedure,
                           'audit.audit_row_trigger()'::regprocedure)$q$,
    0, 'migrator só tem EXECUTE em audit_append_db e audit_row_trigger (allowlist de grants)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE (p.oid = 'audit.audit_row_trigger()'::regprocedure AND NOT p.prosecdef
              AND r.rolname = 'ptmarket_audit_owner')
          OR (p.oid = 'audit.audit_redact(text,jsonb)'::regprocedure AND NOT p.prosecdef
              AND r.rolname = 'ptmarket_audit_owner')
          OR (p.oid = 'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'::regprocedure AND p.prosecdef
              AND r.rolname = 'ptmarket_audit_writer')$q$,
    3, 'donos: row_trigger/redact INVOKER de ptmarket_audit_owner; append_db DEFINER de ptmarket_audit_writer');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer']) r(n)
       WHERE has_function_privilege(r.n, 'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE')$q$,
    0, 'app, worker e price_writer sem EXECUTE em audit_append_db');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.audit_row_trigger() RETURNS trigger LANGUAGE plpgsql
       AS 'BEGIN RETURN NULL; END'$q$,
    '42501', 'migrator não faz CREATE OR REPLACE de audit.audit_row_trigger');
SELECT pg_temp.expect_error(
    $q$CREATE OR REPLACE FUNCTION audit.audit_redact(p_table text, p_changes jsonb) RETURNS jsonb
       LANGUAGE sql AS 'SELECT p_changes'$q$,
    '42501', 'migrator não faz CREATE OR REPLACE de audit.audit_redact');
SELECT pg_temp.expect_error(
    $q$ALTER FUNCTION audit.audit_row_trigger() SECURITY DEFINER$q$, '42501', 'migrator não altera audit_row_trigger');

CREATE TABLE public.ptm_l1_probe (
    id        UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id UUID,
    note      TEXT
);
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE ON public.ptm_l1_probe TO ptmarket_app, ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_temp.l1_uncovered()$q$, 0, 'tabela nova do migrator coberta sozinha (L2)');

-- ---------------------------------------------------------------------------
-- 3. Dono sem ator: grava 'db' com o session_user; o label não se muda pelo contexto.
-- ---------------------------------------------------------------------------
INSERT INTO tenants (id, slug, custom_domain, name) VALUES
    ('00000000-0000-7000-8000-00000000c00a', 'l1-teste-a', 'l1-a.teste.invalid', 'L1 A'),
    ('00000000-0000-7000-8000-00000000c00b', 'l1-teste-b', 'l1-b.teste.invalid', 'L1 B');

-- Contexto forjado pelo dono: ignorado (quem não é a app não escolhe o ator).
SELECT set_config('app.actor_type', 'admin', true);
SELECT set_config('app.actor_label', 'forjado', true);
SELECT set_config('app.actor_id', '00000000-0000-7000-8000-00000000c0ff', true);
UPDATE tenants SET name = 'L1 A2' WHERE id = '00000000-0000-7000-8000-00000000c00a';
SELECT audit.audit_append_db('manual.fix', 'tenants', '00000000-0000-7000-8000-00000000c00a', '{}'::jsonb,
                             '00000000-0000-7000-8000-00000000c00a', NULL);
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.actor_label', '', true);
SELECT set_config('app.actor_id', '', true);

SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000c00a';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'tenants.insert' AND target_type = 'tenants'
         AND target_id = '00000000-0000-7000-8000-00000000c00a'
         AND actor_type = 'db' AND actor_label = 'ptmarket_migrator' AND outcome = 'success'
         AND changes->'after'->>'slug' = 'l1-teste-a'$q$,
    1, 'dono sem ator: tenants.insert como db/ptmarket_migrator, tenant = id');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'tenants.update' AND actor_type = 'db' AND actor_label = 'ptmarket_migrator'
         AND actor_id IS NULL
         AND changes = '{"before": {"name": "L1 A"}, "after": {"name": "L1 A2"}}'::jsonb$q$,
    1, 'dono com app.actor_type/label forjados: continua db/ptmarket_migrator (UPDATE só com o campo alterado)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'manual.fix' AND actor_type = 'db' AND actor_label = 'ptmarket_migrator'$q$,
    1, 'audit_append_db chamado pelo migrator: label = session_user (sem parâmetro para o mudar)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE actor_label = 'forjado' OR actor_type = 'admin'$q$,
    0, 'nenhum evento com o ator forjado');

-- ---------------------------------------------------------------------------
-- 4. App e worker sem ator: PTA01 em qualquer mutação e nada gravado; nunca chamam audit_append_db.
-- ---------------------------------------------------------------------------
SELECT pg_temp.l1_mark();

SELECT pg_temp.expect_error(
    $q$INSERT INTO stores (tenant_id, name, slug, legal_name, nif, iban, email)
       VALUES ('00000000-0000-7000-8000-00000000c00a', 'S', 's', 'S Lda', '1', 'PT50', 's@teste.invalid')$q$,
    'PTA01', 'app sem ator: INSERT em stores ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$INSERT INTO ptm_l1_probe (tenant_id, note) VALUES ('00000000-0000-7000-8000-00000000c00a', 'x')$q$,
    'PTA01', 'app sem ator: INSERT ⇒ PTA01');
SELECT pg_temp.expect_error($q$TRUNCATE ptm_l1_probe$q$, 'PTA01', 'app sem ator: TRUNCATE ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_db('x.y', 't', '1', '{}'::jsonb, NULL, NULL)$q$,
    '42501', 'app não chama audit_append_db (42501)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM stores$q$, 0, 'app sem ator: a loja não ficou');
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_delta()$q$, 0, 'app sem ator: nada gravado');
RESET ROLE;

-- Linha existente (gravada pelo dono) para UPDATE/DELETE sem ator.
INSERT INTO ptm_l1_probe (id, tenant_id, note)
    VALUES ('00000000-0000-7000-8000-00000000c0e1', '00000000-0000-7000-8000-00000000c00a', 'dono');
SET ROLE ptmarket_app;
SELECT pg_temp.l1_mark();
SELECT pg_temp.expect_error(
    $q$UPDATE ptm_l1_probe SET note = 'y' WHERE id = '00000000-0000-7000-8000-00000000c0e1'$q$,
    'PTA01', 'app sem ator: UPDATE ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$DELETE FROM ptm_l1_probe WHERE id = '00000000-0000-7000-8000-00000000c0e1'$q$,
    'PTA01', 'app sem ator: DELETE ⇒ PTA01');
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$INSERT INTO ptm_l1_probe (tenant_id, note) VALUES ('00000000-0000-7000-8000-00000000c00a', 'w')$q$,
    'PTA01', 'worker sem ator: INSERT ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$UPDATE ptm_l1_probe SET note = 'w' WHERE id = '00000000-0000-7000-8000-00000000c0e1'$q$,
    'PTA01', 'worker sem ator: UPDATE ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$DELETE FROM ptm_l1_probe WHERE id = '00000000-0000-7000-8000-00000000c0e1'$q$,
    'PTA01', 'worker sem ator: DELETE ⇒ PTA01');
SELECT pg_temp.expect_error($q$TRUNCATE ptm_l1_probe$q$, 'PTA01', 'worker sem ator: TRUNCATE ⇒ PTA01');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_db('x.y', 't', '1', '{}'::jsonb, NULL, NULL)$q$,
    '42501', 'worker não chama audit_append_db (42501)');
RESET ROLE;
SET ROLE ptmarket_price_writer;
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_db('x.y', 't', '1', '{}'::jsonb, NULL, NULL)$q$,
    '42501', 'price_writer não chama audit_append_db (42501)');
RESET ROLE;

SET ROLE ptmarket_app;
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_delta()$q$, 0,
    'app/worker sem ator: nada gravado');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM ptm_l1_probe WHERE id = '00000000-0000-7000-8000-00000000c0e1' AND note = 'dono'$q$,
    1, 'app/worker sem ator: a linha ficou como estava');

-- ---------------------------------------------------------------------------
-- 5. App com ator: INSERT/UPDATE/DELETE/TRUNCATE gravam; UPDATE só com o que mudou; ROLLBACK sem evento.
-- ---------------------------------------------------------------------------
SET app.actor_type = 'system';
SET app.actor_label = 'test';
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email, invoicing_credentials_enc,
                    eupago_split_key) VALUES
    ('00000000-0000-7000-8000-00000000c0a1', '00000000-0000-7000-8000-00000000c00a', 'Loja L1', 'loja-l1',
     'Loja L1 Lda', '500000009', 'PT50000000000000000001234', 'loja@teste.invalid', 'cifra-ultra-secreta',
     'split-ultra-secreto');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-00000000c0a2', '00000000-0000-7000-8000-00000000c00a',
     '00000000-0000-7000-8000-00000000c0a1', '{"pt":"Produto L1"}', 2300),
    ('00000000-0000-7000-8000-00000000c0a4', '00000000-0000-7000-8000-00000000c00a',
     '00000000-0000-7000-8000-00000000c0a1', '{"pt":"Produto a apagar"}', 2300);
INSERT INTO product_variants (id, tenant_id, product_id, price_cents, stock_qty) VALUES
    ('00000000-0000-7000-8000-00000000c0a3', '00000000-0000-7000-8000-00000000c00a',
     '00000000-0000-7000-8000-00000000c0a2', 250, 3);
UPDATE product_variants SET price_cents = 300 WHERE id = '00000000-0000-7000-8000-00000000c0a3';
-- 2.ª mudança: lowest_price_30d já não muda (250), por isso só price_cents muda.
UPDATE product_variants SET price_cents = 350 WHERE id = '00000000-0000-7000-8000-00000000c0a3';

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'stores.insert' AND target_id = '00000000-0000-7000-8000-00000000c0a1'
         AND store_id = '00000000-0000-7000-8000-00000000c0a1'
         AND actor_type = 'system' AND actor_label = 'test' AND retention_class = 'standard'$q$,
    1, 'app com ator: stores.insert gravado (ator do contexto, store_id = id)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.insert' AND store_id = '00000000-0000-7000-8000-00000000c0a1'$q$,
    2, 'app com ator: products.insert gravado (store_id da coluna)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'product_variants.update' AND target_id = '00000000-0000-7000-8000-00000000c0a3'
         AND retention_class = 'fiscal'
         AND changes = '{"before": {"price_cents": 300}, "after": {"price_cents": 350}}'::jsonb$q$,
    1, 'UPDATE de price_cents: product_variants.update (fiscal) só com esse campo');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'product_price_history.insert' AND retention_class = 'fiscal'
         AND actor_type = 'system' AND changes->'after'->>'price_cents' = '350'
         AND changes->'after'->>'variant_id' = '00000000-0000-7000-8000-00000000c0a3'$q$,
    1, 'UPDATE de price_cents: product_price_history.insert (fiscal, via price_writer, com o ator)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE action = 'product_price_history.insert'
       AND changes->'after'->>'variant_id' = '00000000-0000-7000-8000-00000000c0a3'$q$,
    3, 'histórico: um evento por preço (250, 300, 350)');

-- UPDATE sem diferenças: sem evento.
SELECT pg_temp.l1_mark();
UPDATE product_variants SET stock_qty = stock_qty WHERE id = '00000000-0000-7000-8000-00000000c0a3';
SELECT pg_temp.expect_value(
    $q$SELECT pg_temp.l1_delta()$q$, 0, 'UPDATE sem diferenças não grava');

-- DELETE grava a linha antes.
DELETE FROM products WHERE id = '00000000-0000-7000-8000-00000000c0a4';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.delete' AND target_id = '00000000-0000-7000-8000-00000000c0a4'
         AND changes->'before'->>'id' = '00000000-0000-7000-8000-00000000c0a4' AND NOT changes ? 'after'$q$,
    1, 'DELETE grava products.delete com before');

-- TRUNCATE grava '<tabela>.truncate' (tenant do contexto).
TRUNCATE ptm_l1_probe;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'ptm_l1_probe.truncate' AND tenant_id = '00000000-0000-7000-8000-00000000c00a'
         AND target_id IS NULL AND changes IS NULL$q$,
    1, 'TRUNCATE grava ptm_l1_probe.truncate');

-- ROLLBACK não deixa evento.
SAVEPOINT l1_sp;
UPDATE product_variants SET price_cents = 999 WHERE id = '00000000-0000-7000-8000-00000000c0a3';
ROLLBACK TO SAVEPOINT l1_sp;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE changes->'after'->>'price_cents' = '999'$q$, 0, 'ROLLBACK não deixa evento');
RESET ROLE;

-- Worker com ator 'system', sem contexto: o evento vai para o tenant da linha.
SET ROLE ptmarket_worker;
SET app.actor_type = 'system';
SET app.actor_label = 'job:l1';
SET app.current_tenant_id = '';
INSERT INTO ptm_l1_probe (id, tenant_id, note)
    VALUES ('00000000-0000-7000-8000-00000000c0e2', '00000000-0000-7000-8000-00000000c00b', 'worker');
RESET ROLE;

-- Anti-IDOR: cada tenant só lê os seus eventos.
SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000c00b';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'ptm_l1_probe.insert' AND actor_label = 'job:l1'
         AND target_id = '00000000-0000-7000-8000-00000000c0e2'$q$,
    1, 'worker system sem contexto: evento no tenant da linha (B)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id IS DISTINCT FROM '00000000-0000-7000-8000-00000000c00b'$q$,
    0, 'tenant B só lê eventos do B');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000c00a';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE tenant_id = '00000000-0000-7000-8000-00000000c00b'$q$,
    0, 'tenant A não lê os eventos do B (anti-IDOR)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE target_id = '00000000-0000-7000-8000-00000000c0e2'$q$,
    0, 'tenant A não vê o evento do worker no B');
RESET ROLE;

-- _sqlx_migrations também é auditada (o INSERT/UPDATE do sqlx da 0010 gravou na cadeia da plataforma).
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains()
       WHERE chain_key = '00000000-0000-0000-0000-000000000000' AND retention_class = 'standard'
         AND last_seq >= 1$q$,
    1, '_sqlx_migrations: a cadeia da plataforma tem eventos do sqlx');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. Máscara (§3.5): segredos, IBAN e PII nunca em claro.
-- ---------------------------------------------------------------------------
-- customers (sem política: com FORCE RLS nem o dono escreve; só nesta transação).
ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-00000000c00a', true);
INSERT INTO customers (id, email, name, phone, nif, password_hash, passkeys) VALUES
    ('00000000-0000-7000-8000-00000000c0c1', 'cliente.l1@teste.invalid', 'Maria Confidencial', '+351919876543',
     '287654321', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', '[{"credential_id":"abc"}]');
UPDATE customers SET email = 'novo.l1@teste.invalid' WHERE id = '00000000-0000-7000-8000-00000000c0c1';

SET ROLE ptmarket_app;
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000c00a';
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.insert' AND target_id = '00000000-0000-7000-8000-00000000c0c1'
         AND changes->'after'->>'email' = '[pii]' AND changes->'after'->>'name' = '[pii]'
         AND changes->'after'->>'phone' = '[pii]' AND changes->'after'->>'nif' = '[pii]'
         AND changes->'after'->>'password_hash' = '[redacted]'
         AND changes->'after'->>'passkeys' = '[redacted]'$q$,
    1, 'customers.insert: email/nome/telefone/NIF = [pii], password_hash e passkeys = [redacted]');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'customers.update'
         AND changes = '{"before": {"email": "[pii]"}, "after": {"email": "[pii]"}}'::jsonb$q$,
    1, 'customers.update: diz QUE o email mudou, não o valor');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE changes::text ~* '(cliente\.l1|novo\.l1|Confidencial|919876543|287654321|argon2id|credential_id)'$q$,
    0, 'customers: nenhum valor pessoal ou segredo em claro');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'stores.insert' AND target_id = '00000000-0000-7000-8000-00000000c0a1'
         AND changes->'after'->>'iban' = '****1234'
         AND changes->'after'->>'invoicing_credentials_enc' = '[redacted]'
         AND changes->'after'->>'eupago_split_key' = '[redacted]'$q$,
    1, 'stores: IBAN só com os 4 últimos; credenciais e split_key = [redacted]');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE changes::text ~* '(PT5000000000000000000|ultra-secret)'$q$,
    0, 'stores: IBAN completo e segredos nunca em claro');

-- Regra geral, em todos os eventos legíveis (tenants A e B): coluna de nome sensível nunca em claro.
SELECT pg_temp.expect_value($q$SELECT pg_temp.l1_leaks()$q$, 0, 'tenant A: nenhuma coluna sensível em claro');
SET app.current_tenant_id = '00000000-0000-7000-8000-00000000c00b';
SELECT pg_temp.expect_value($q$SELECT pg_temp.l1_leaks()$q$, 0, 'tenant B: nenhuma coluna sensível em claro');

-- A função de máscara: users e colunas ip (tabelas que ainda não existem).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT audit.audit_redact('users',
           '{"before": {"email": "a@b.c", "full_name": "Ana", "last_ip": "10.0.0.1", "api_token": "t0k",
                        "iban": "PT50123456789", "role": "x"},
             "after": {"email": "d@e.f", "full_name": "Ana B", "ip": "10.0.0.2", "api_token": null}}'::jsonb) r) x
       WHERE r = '{"before": {"email": "[pii]", "full_name": "[pii]", "last_ip": "[pii]", "api_token": "[redacted]",
                              "iban": "****6789", "role": "x"},
                   "after": {"email": "[pii]", "full_name": "[pii]", "ip": "[pii]", "api_token": null}}'::jsonb$q$,
    1, 'audit_redact: users(email, full_name), ip, token e IBAN mascarados; resto intacto');
RESET ROLE;

ROLLBACK;
