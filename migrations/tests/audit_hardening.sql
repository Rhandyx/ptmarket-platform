-- run.sh: superuser
-- Teste do endurecimento da caixa negra (0012, cartão 02/03c): máscara recursiva em todos os caminhos, dedupe
-- com PTA03, mensagens sem valores, verify (bad_genesis, gap_before, head_mismatch) e defaults de app.*.
-- Corre como superuser só para assumir papéis NOLOGIN, adulterar a cadeia (session_replication_role, só em
-- savepoints) e pôr defaults na BD/papel; cada asserção é feita com SET ROLE do papel em causa.
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

-- Erro esperado com SQLSTATE p_state; a mensagem (e o detalhe/dica) não pode conter p_secret e tem de
-- conter p_must.
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
        RAISE EXCEPTION 'FALHOU: % (esperado % sem o valor e com "%", obtido %)', p_label, p_state, p_must, v_state;
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

-- Evento do contrato do Redis Stream (occurred_at RFC 3339, UTC, há 1 minuto; now() é fixo na transação).
CREATE FUNCTION pg_temp.ev(p_id uuid, p_tenant uuid, p_changes jsonb DEFAULT NULL, p_reason text DEFAULT NULL)
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'id', p_id, 'tenant_id', p_tenant, 'store_id', NULL, 'actor_type', 'merchant',
        'actor_id', '00000000-0000-7000-8000-0000000012a1', 'actor_label', NULL, 'impersonator_id', NULL,
        'action', 'stores.update', 'target_type', 'stores', 'target_id', 's1', 'outcome', 'success',
        'reason', p_reason, 'changes', p_changes,
        'request_id', '00000000-0000-7000-8000-0000000012f1', 'ip', '198.51.100.9',
        'user_agent_hash', 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
        'occurred_at', to_char((now() - interval '1 minute') AT TIME ZONE 'UTC',
                               'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'));
$$;
GRANT EXECUTE ON FUNCTION pg_temp.ev(uuid, uuid, jsonb, text) TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- 1. Alteração aprovada, donos e privilégios dos objetos novos.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes c JOIN audit_admin.sealed_changes_applied a USING (name)
       WHERE c.name = '0012_hardening'
         AND c.sha256 = encode(sha256(convert_to(c.sql, 'UTF8')), 'hex')
         AND c.sha256 = '23503d703c8adfa47cc309442078840d90b095fa88b1221caeed469d021ded95'$q$,
    1, '0012_hardening aprovada com o sha256 que a 0012 dispara, aplicada uma vez');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'audit.audit_guc_defaults()'::regprocedure
         AND p.prosecdef AND p.proowner = 'ptmarket_audit_writer'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                         WHERE a.grantee NOT IN (p.proowner, 'ptmarket_worker'::regrole))$q$,
    1, 'audit_guc_defaults: DEFINER, dono writer, search_path fixo, EXECUTE só worker');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('audit._redact_walk(text,jsonb,text)'::regprocedure,
                       'audit._event_content_hash(audit.audit_events)'::regprocedure,
                       'audit.audit_redact(text,jsonb)'::regprocedure)
         AND NOT p.prosecdef AND p.proowner = 'ptmarket_audit_owner'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND NOT has_function_privilege('ptmarket_migrator', p.oid, 'EXECUTE')$q$,
    3, '_redact_walk, _event_content_hash, audit_redact: INVOKER, dono ptmarket_audit_owner, migrator sem EXECUTE');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid = 'audit._event_content_hash(audit.audit_events)'::regprocedure
         AND NOT EXISTS (SELECT 1 FROM aclexplode(p.proacl) a
                         WHERE a.grantee NOT IN (p.proowner, 'ptmarket_audit_writer'::regrole))$q$,
    1, '_event_content_hash: EXECUTE só do escritor');
-- O que _chain_insert chama (corpos plpgsql não ficam em pg_depend): nenhum dono com LOGIN.
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid IN ('audit.audit_redact(text,jsonb)'::regprocedure,
                       'audit._redact_walk(text,jsonb,text)'::regprocedure,
                       'audit._event_content_hash(audit.audit_events)'::regprocedure)
         AND r.rolcanlogin$q$,
    0, '_chain_insert: funções novas que chama sem dono com LOGIN');

-- ---------------------------------------------------------------------------
-- 2. Tabela de casos da máscara (como app: a função é INVOKER).
-- ---------------------------------------------------------------------------
-- Criada como superuser: desde a 0020 a app não tem TEMPORARY (não cria tabelas temporárias).
CREATE TEMP TABLE redact_cases (label text, tbl text, input jsonb, expected jsonb);
INSERT INTO redact_cases VALUES
    ('stores.email (e name de stores) → [pii]', 'stores',
     '{"after": {"email": "loja@ex.pt", "name": "Loja da Ana"}}',
     '{"after": {"email": "[pii]", "name": "[pii]"}}'),
    ('tenants.settings.{api_key, smtp.password} → [redacted]; name/legal_name de tenants em claro', 'tenants',
     '{"before": {"settings": {"theme": "x"}},
       "after": {"name": "Câmara X", "legal_name": "Município X",
                 "settings": {"theme": "y", "api_key": "k-123", "smtp": {"host": "h", "password": "p-456"}}}}',
     '{"before": {"settings": {"theme": "x"}},
       "after": {"name": "Câmara X", "legal_name": "Município X",
                 "settings": {"theme": "y", "api_key": "[redacted]", "smtp": {"host": "h", "password": "[redacted]"}}}}'),
    ('users.totp_secret → [redacted]', 'users',
     '{"after": {"totp_secret": "JBSWY3DP", "role": "x"}}',
     '{"after": {"totp_secret": "[redacted]", "role": "x"}}'),
    ('x.authorization → [redacted]', 'x',
     '{"after": {"authorization": "Bearer abc"}}',
     '{"after": {"authorization": "[redacted]"}}'),
    ('customers.address.street → address inteiro [pii]', 'customers',
     '{"after": {"address": {"street": "Rua A 1", "city": "Porto"}}}',
     '{"after": {"address": "[pii]"}}'),
    ('street aninhado noutro objeto → [pii] (recursivo)', 'customers',
     '{"after": {"shipping": {"street": "Rua A 1", "city": "Porto"}}}',
     '{"after": {"shipping": {"street": "[pii]", "city": "Porto"}}}'),
    ('products.title, products.name, categories via *_id → em claro', 'products',
     '{"after": {"title": "Queijo", "name": "Queijo da Serra", "category_id": "00000000-0000-7000-8000-0000000012c1",
                 "store_id": "00000000-0000-7000-8000-0000000012c2", "company_id": "c1", "api_key_id": "k1"}}',
     -- 03d: segredos antes da exceção *_id (api_key_id → "[redacted]")
     '{"after": {"title": "Queijo", "name": "Queijo da Serra", "category_id": "00000000-0000-7000-8000-0000000012c1",
                 "store_id": "00000000-0000-7000-8000-0000000012c2", "company_id": "c1", "api_key_id": "[redacted]"}}'),
    ('categories.name → em claro', 'categories',
     '{"before": {"name": "Queijos"}, "after": {"name": "Queijos e enchidos"}}',
     '{"before": {"name": "Queijos"}, "after": {"name": "Queijos e enchidos"}}'),
    ('name aninhado em products (não é coluna) → [pii]', 'products',
     '{"after": {"supplier": {"name": "Ana Silva", "nif": "123456789"}}}',
     '{"after": {"supplier": {"name": "[pii]", "nif": "[pii]"}}}'),
    ('arrays: objetos dentro de arrays mascarados', 'stores',
     '{"after": {"contacts": [{"email": "a@ex.pt", "role": "x"}, {"phone": "912345678"}], "tags": ["a", "b"]}}',
     '{"after": {"contacts": [{"email": "[pii]", "role": "x"}, {"phone": "[pii]"}], "tags": ["a", "b"]}}'),
    ('changes sem before/after (produtor): raiz mascarada; nulls ficam', 'products',
     '{"email": "x@ex.pt", "password": "pw", "name": "Produto", "ip": "10.0.0.1", "cvv": "123", "otp": null}',
     '{"email": "[pii]", "password": "[redacted]", "name": "Produto", "ip": "[pii]", "cvv": "[redacted]", "otp": null}'),
    ('iban → 4 últimos; pan/private_key/_enc/_hash → [redacted]; birth/postal → [pii]', 'stores',
     '{"after": {"iban": "PT50000201231234567890154", "card_pan": "4111", "private_key": "k",
                 "x_enc": "e", "x_hash": "h", "birth_date": "2000-01-01", "postal_code": "4000-001"}}',
     '{"after": {"iban": "****0154", "card_pan": "[redacted]", "private_key": "[redacted]",
                 "x_enc": "[redacted]", "x_hash": "[redacted]", "birth_date": "[pii]", "postal_code": "[pii]"}}');
GRANT SELECT ON redact_cases TO ptmarket_app;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM redact_cases WHERE label = %L
              AND audit.audit_redact(tbl, input) = expected$q$, c.label),
    1, 'máscara: ' || c.label)
FROM redact_cases c ORDER BY c.label;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM redact_cases
       WHERE audit.audit_redact(tbl, audit.audit_redact(tbl, input)) IS DISTINCT FROM audit.audit_redact(tbl, input)$q$,
    0, 'máscara idempotente em todos os casos');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES (audit.audit_redact('x', NULL)), (audit.audit_redact('x', '"s"')),
                                   (audit.audit_redact('x', '[{"email": "a"}]'))) v(r)
       WHERE r IS NOT DISTINCT FROM NULL OR r = '"s"' OR r = '[{"email": "[pii]"}]'$q$,
    3, 'máscara: NULL, escalar e array na raiz');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. audit_append e audit_append_event com changes em claro → gravado mascarado (_chain_insert).
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000012aa', true);
SELECT set_config('app.actor_type', 'merchant', true);
SELECT audit.audit_append('stores.update'::text, 'stores'::text, 's1'::text, 'success'::text, NULL::text,
    '{"email": "dono@loja.pt", "password": "Segredo#1", "settings": {"api_key": "ak-777"}}'::jsonb,
    NULL::uuid) AS app_ev \gset
SELECT set_config('app.current_tenant_id', '', true);
SELECT set_config('app.actor_type', '', true);
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT uuidv7() AS wk_ev \gset
SELECT audit.audit_append_event(pg_temp.ev(:'wk_ev', '00000000-0000-7000-8000-0000000012aa',
    '{"after": {"email": "cli@ex.pt", "password": "Segredo#2", "phone": "919999999"}}'::jsonb));
RESET ROLE;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L
              AND changes = '{"email": "[pii]", "password": "[redacted]", "settings": {"api_key": "[redacted]"}}'::jsonb$q$,
           :'app_ev'),
    1, 'audit_append com email/password/api_key em claro → gravado mascarado');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L
              AND changes = '{"after": {"email": "[pii]", "password": "[redacted]", "phone": "[pii]"}}'::jsonb$q$,
           :'wk_ev'),
    1, 'audit_append_event com email/password/phone em claro → gravado mascarado');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id IN (%L, %L)
              AND changes::text ~ '(dono@loja|Segredo#|ak-777|cli@ex|919999999)'$q$, :'app_ev', :'wk_ev'),
    0, 'nenhum valor em claro nos eventos gravados');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. Dedupe: mesmo id e mesmo conteúdo → 1 evento; conteúdo diferente → PTA03 e nada gravado.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT uuidv7() AS dup \gset
SELECT pg_temp.expect_value(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-0000000012bb',
              '{"after": {"email": "a@ex.pt", "status": "on"}}'::jsonb))::int$q$, :'dup'),
    1, 'dedupe: 1.ª entrega grava');
SELECT pg_temp.expect_value(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-0000000012bb',
              '{"after": {"email": "a@ex.pt", "status": "on"}}'::jsonb))::int$q$, :'dup'),
    0, 'dedupe: reentrega igual (antes da máscara) ⇒ false');
SELECT pg_temp.expect_error(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-0000000012bb',
              '{"after": {"email": "a@ex.pt", "status": "off"}}'::jsonb))$q$, :'dup'),
    'PTA03', 'dedupe: mesmo id, changes diferente ⇒ PTA03');
SELECT pg_temp.expect_error(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-0000000012bb',
              '{"after": {"email": "a@ex.pt", "status": "on"}}'::jsonb, 'outra razão'))$q$, :'dup'),
    'PTA03', 'dedupe: mesmo id, reason diferente ⇒ PTA03');
SELECT pg_temp.expect_error(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L, '00000000-0000-7000-8000-0000000012cc',
              '{"after": {"email": "a@ex.pt", "status": "on"}}'::jsonb))$q$, :'dup'),
    'PTA03', 'dedupe: mesmo id noutro tenant ⇒ PTA03');
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L$q$, :'dup'), 1, 'dedupe: 1 só evento com esse id');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chain_heads
       WHERE chain_key IN ('00000000-0000-7000-8000-0000000012bb', '00000000-0000-7000-8000-0000000012cc')
         AND last_seq > 0$q$,
    1, 'dedupe: PTA03 não avançou nenhuma cabeça (cadeia bb seq 1; cc sem eventos)');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. audit_append_event: erro de conversão sem o valor (chave + SQLSTATE); lock_timeout reposto.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error_msg(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL) || '{"tenant_id": "nao-uuid-Ana.Silva@ex.pt"}')$q$,
    'PTA02', 'Ana.Silva', 'tenant_id', 'uuid inválido ⇒ PTA02 com a chave, sem o valor');
SELECT pg_temp.expect_error_msg(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL) || '{"actor_id": "ZZ-919999999"}')$q$,
    'PTA02', '919999999', '22P02', 'uuid inválido ⇒ PTA02 com o SQLSTATE, sem o valor');
SELECT pg_temp.expect_error_msg(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL) || '{"ip": "ip-de-Joao-Sousa"}')$q$,
    'PTA02', 'Joao-Sousa', 'ip', 'ip inválido ⇒ PTA02 sem o valor');
SELECT pg_temp.expect_error_msg(
    $q$SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), NULL) || '{"actor_type": "merchant-com-mais-de-16-Maria"}')$q$,
    'PTA02', 'Maria', 'actor_type', 'actor_type demasiado longo ⇒ PTA02 sem o valor');
SELECT set_config('lock_timeout', '1234ms', true);
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-0000000012bb'));
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE current_setting('lock_timeout') = '1234ms'$q$,
    1, 'audit_append_event repõe o lock_timeout de quem chama');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc WHERE oid = 'audit.audit_append_event(jsonb)'::regprocedure
       AND prosrc ~ 'set_config\(''lock_timeout'', ''2s'', true\)' AND prosrc !~ ',\s*SQLERRM'$q$,
    1, 'audit_append_event: lock_timeout 2s na escrita; SQLERRM nunca é argumento do RAISE');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. audit_verify_chain: íntegra → 0; génese adulterada, buraco antes da janela, cabeça divergente.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_worker;
SELECT audit.audit_append_event(pg_temp.ev(uuidv7(), '00000000-0000-7000-8000-0000000012dd'))
FROM generate_series(1, 4);
RESET ROLE;
SET ROLE ptmarket_audit_writer;
SELECT created_at AS g3_at FROM audit.audit_events
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND chain_seq = 3 \gset
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', 'infinity')$q$,
    0, 'verify: cadeia íntegra (toda, até ao presente) → 0 linhas');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                                      %L::timestamptz, 'infinity')$q$, :'g3_at'),
    0, 'verify: janela a começar no seq 3 continua o seq 2 → 0 linhas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_chains() c,
            audit.audit_verify_chain(c.chain_key, c.retention_class, '-infinity', 'infinity')$q$,
    0, 'verify: todas as cadeias íntegras, cabeças coerentes');
RESET ROLE;

-- 6a. Génese adulterada: seq 1 com prev_hash ≠ zeros (hash recalculado para isolar o problema).
SAVEPOINT tamper;
SET LOCAL session_replication_role = replica;
UPDATE audit.audit_events SET prev_hash = sha256('forjado'::bytea)
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard' AND chain_seq = 1;
UPDATE audit.audit_events e SET hash = audit._event_hash(e)
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard' AND chain_seq = 1;
RESET session_replication_role;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', 'infinity') v
       WHERE v.problem = 'bad_genesis' AND v.broken_seq = 1 AND v.broken_id IS NOT NULL$q$,
    1, 'verify: génese adulterada → bad_genesis no seq 1');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', 'infinity') v WHERE v.problem = 'hash'$q$,
    0, 'verify: (hash recalculado: só a génese denuncia)');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

-- 6b. Buraco antes da janela: apagar o seq 2; janela a começar no seq 3 → gap_before.
SAVEPOINT tamper;
SET LOCAL session_replication_role = replica;
DELETE FROM audit.audit_events
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard' AND chain_seq = 2;
RESET session_replication_role;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                                      %L::timestamptz, 'infinity') v
              WHERE v.problem = 'gap_before' AND v.broken_seq = 3$q$, :'g3_at'),
    1, 'verify: seq 2 apagado, janela no seq 3 → gap_before');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                                      %L::timestamptz, 'infinity')$q$, :'g3_at'),
    1, 'verify: só essa linha (cabeça coerente)');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

-- 6b'. Mesmo seq, elo trocado: hash do seq 2 adulterado; janela no seq 3 → gap_before.
SAVEPOINT tamper;
SET LOCAL session_replication_role = replica;
UPDATE audit.audit_events SET hash = sha256('x'::bytea)
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard' AND chain_seq = 2;
RESET session_replication_role;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                                      %L::timestamptz, 'infinity') v
              WHERE v.problem = 'gap_before' AND v.broken_seq = 3$q$, :'g3_at'),
    1, 'verify: hash do seq 2 ≠ prev_hash do seq 3 (fora da janela) → gap_before');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

-- 6c. Cabeça divergente: corte no fim (último evento apagado) e cabeça adulterada.
SAVEPOINT tamper;
SET LOCAL session_replication_role = replica;
DELETE FROM audit.audit_events
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard' AND chain_seq = 4;
RESET session_replication_role;
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', 'infinity') v
       WHERE v.problem = 'head_mismatch' AND v.broken_seq = 3$q$,
    1, 'verify: último evento apagado → head_mismatch (última linha seq 3 ≠ cabeça seq 4)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', 'infinity')$q$,
    1, 'verify: corte no fim → só head_mismatch');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               '-infinity', now())$q$,
    0, 'verify: janela que acaba antes de agora não compara a cabeça');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

SAVEPOINT tamper;
UPDATE audit.audit_chain_heads SET last_hash = sha256('y'::bytea)
WHERE chain_key = '00000000-0000-7000-8000-0000000012dd' AND retention_class = 'standard';
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_verify_chain('00000000-0000-7000-8000-0000000012dd', 'standard',
                                               now() - interval '1 day', now() + interval '1 day') v
       WHERE v.problem = 'head_mismatch' AND v.broken_seq = 4 AND v.broken_id IS NOT NULL$q$,
    1, 'verify: cabeça com last_hash adulterado → head_mismatch');
RESET ROLE;
ROLLBACK TO SAVEPOINT tamper;

-- ---------------------------------------------------------------------------
-- 7. Passo 0 e defaults de app.* fora da transação.
-- ---------------------------------------------------------------------------
-- Passo 0: pg_settings não expõe GUCs personalizados (nem da sessão nem da BD) → caminho audit_guc_defaults.
SELECT set_config('app.actor_type', 'customer', true);
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_settings WHERE name LIKE 'app.%'$q$,
    0, 'passo 0: pg_settings não mostra app.actor_type (nem posto na sessão)');
SELECT set_config('app.actor_type', '', true);

SET ROLE ptmarket_worker;
SELECT count(*) AS guc_base FROM audit.audit_guc_defaults() \gset
RESET ROLE;
SELECT pg_temp.expect_value($q$SELECT 1$q$, 1, 'base de defaults app.* lida');

SAVEPOINT gucs;
DO $$
BEGIN
    EXECUTE format('ALTER DATABASE %I SET app.actor_type = %L', current_database(), 'customer');
END
$$;
ALTER ROLE ptmarket_app SET app.actor_label = 'forjado';
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_guc_defaults() g
       WHERE g.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
         AND g.setrole = 0 AND g.setting = 'app.actor_type=customer'$q$,
    1, 'default de BD em app.actor_type → linha devolvida (BD, todos os papéis)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_guc_defaults() g
       WHERE g.setdatabase = 0 AND g.setrole = 'ptmarket_app'::regrole AND g.setting = 'app.actor_label=forjado'$q$,
    1, 'default de papel em app.actor_label → linha devolvida (papel, todas as BDs)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) - %s FROM audit.audit_guc_defaults()$q$, :'guc_base'),
    2, 'só os dois defaults novos');
RESET ROLE;
ROLLBACK TO SAVEPOINT gucs;

SET ROLE ptmarket_app;
SELECT pg_temp.expect_error($q$SELECT * FROM audit.audit_guc_defaults()$q$, '42501', 'app: audit_guc_defaults ⇒ 42501');
RESET ROLE;
SET ROLE ptmarket_migrator;
SELECT pg_temp.expect_error($q$SELECT * FROM audit.audit_guc_defaults()$q$, '42501', 'migrator: audit_guc_defaults ⇒ 42501');
RESET ROLE;

ROLLBACK;
