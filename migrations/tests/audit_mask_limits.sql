-- run.sh: superuser
-- Teste da 0014 (cartão 02/03d): máscara PT/EN por chave e por valor, limites de tamanho (PTA02 nos eventos da
-- aplicação; cortar e marcar na L1/L2), NUL recusado pelo PostgreSQL e alterações seladas encadeadas.
-- Corre como superuser só para assumir papéis NOLOGIN, criar tenants e mexer em audit_admin.sealed_changes (em
-- savepoint); cada asserção é feita com SET ROLE do papel em causa. Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- L2 ligada só na secção 6

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

-- Erro com SQLSTATE p_state; mensagem/detalhe/dica sem p_secret e mensagem com p_must.
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

-- JSON aninhado: p_n objetos {"a": …} com p_leaf no fundo.
CREATE FUNCTION pg_temp.nest(p_n int, p_leaf text DEFAULT '1')
RETURNS jsonb LANGUAGE sql AS $$
    SELECT (repeat('{"a": ', p_n) || p_leaf || repeat('}', p_n))::jsonb
$$;

-- Texto não compressível com p_chars caracteres.
CREATE FUNCTION pg_temp.blob(p_chars int)
RETURNS text LANGUAGE sql AS $$
    SELECT left(string_agg(md5(i::text), '' ORDER BY i), p_chars) FROM generate_series(1, p_chars / 32 + 1) AS i
$$;

-- Evento do contrato do Redis Stream (occurred_at RFC 3339, UTC, há 1 minuto).
CREATE FUNCTION pg_temp.ev(p_changes jsonb, p_reason text DEFAULT NULL)
RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object(
        'id', uuidv7(), 'tenant_id', '00000000-0000-7000-8000-0000000014aa', 'store_id', NULL,
        'actor_type', 'merchant', 'actor_id', '00000000-0000-7000-8000-0000000014a1', 'actor_label', NULL,
        'impersonator_id', NULL, 'action', 'test.limits', 'target_type', 'stores', 'target_id', 's1',
        'outcome', 'success', 'reason', p_reason, 'changes', p_changes,
        'request_id', '00000000-0000-7000-8000-0000000014f1', 'ip', NULL, 'user_agent_hash', NULL,
        'occurred_at', to_char((now() - interval '1 minute') AT TIME ZONE 'UTC',
                               'YYYY-MM-DD"T"HH24:MI:SS.US"+00:00"'));
$$;
GRANT EXECUTE ON FUNCTION pg_temp.ev(jsonb, text) TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- 1. Alterações seladas encadeadas (cadeia linear) e selagem.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes c JOIN audit_admin.sealed_changes_applied a USING (name)
       WHERE (c.name, c.requires) IN (('0012_hardening', '0011_db_user'),
                                       ('0013_ddl_owner_exec', '0012_hardening'),
                                       ('0014_mask_limits', '0013_ddl_owner_exec'))
          OR (c.name = '0011_db_user' AND c.requires IS NULL)$q$,
    4, 'requires: 0011 → NULL, 0012 → 0011, 0013 → 0012, 0014 → 0013 (todas aplicadas)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes c
       WHERE c.name = '0014_mask_limits' AND c.sha256 = encode(sha256(convert_to(c.sql, 'UTF8')), 'hex')
         AND c.sha256 = '4a8bb31a0d2b10ded579373f9c15d5b8ded161f34e3e6f7416557e48e9f44efc'$q$,
    1, '0014_mask_limits aprovada com o sha256 que a 0014 dispara');

SAVEPOINT chain;
INSERT INTO audit_admin.sealed_changes (name, requires, sql, sha256) VALUES
    ('zz_03d_a', '0014_mask_limits', 'SELECT 1', encode(sha256(convert_to('SELECT 1', 'UTF8')), 'hex')),
    ('zz_03d_b', 'zz_03d_a',         'SELECT 2', encode(sha256(convert_to('SELECT 2', 'UTF8')), 'hex'));
SELECT encode(sha256(convert_to('SELECT 1', 'UTF8')), 'hex') AS sha_a,
       encode(sha256(convert_to('SELECT 2', 'UTF8')), 'hex') AS sha_b \gset
SET ROLE ptmarket_migrator;
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit_admin.audit_upgrade('zz_03d_b'::text, %L::text)$q$, :'sha_b'),
    'P0001', '__nada__', 'exige zz_03d_a', 'audit_upgrade fora de ordem (anterior não aplicada) → erro');
SELECT audit_admin.audit_upgrade('zz_03d_a'::text, :'sha_a'::text);
SELECT audit_admin.audit_upgrade('zz_03d_b'::text, :'sha_b'::text);
SELECT audit_admin.audit_seal();
RESET ROLE;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes_applied WHERE name IN ('zz_03d_a', 'zz_03d_b')$q$,
    2, 'audit_upgrade pela ordem certa passa; audit_seal() passa');
ROLLBACK TO SAVEPOINT chain;

-- ---------------------------------------------------------------------------
-- 2. Tabela de casos da máscara (como app: audit_redact é INVOKER).
-- ---------------------------------------------------------------------------
-- Criada como superuser: desde a 0020 a app não tem TEMPORARY (não cria tabelas temporárias).
CREATE TEMP TABLE mask_cases (label text, tbl text, input jsonb, expected jsonb);
INSERT INTO mask_cases VALUES
    ('senha', 'stores', '{"senha": "x"}', '{"senha": "[redacted]"}'),
    ('palavra-passe (hífen e caixa)', 'stores',
     '{"palavra-passe": "x", "Palavra_Passe": "y"}', '{"palavra-passe": "[redacted]", "Palavra_Passe": "[redacted]"}'),
    ('segredos antes de *_id: reset_token_id, secret_id, api_key_id', 'stores',
     '{"reset_token_id": "x", "secret_id": "y", "api_key_id": "z"}',
     '{"reset_token_id": "[redacted]", "secret_id": "[redacted]", "api_key_id": "[redacted]"}'),
    ('segredos PT/EN novos', 'stores',
     '{"pwd": "x", "api-key": "x", "access_key": "x", "session": "x", "cookie": "x", "signature": "x",
       "hmac": "x", "pin": "1", "card_number": "x", "cartão": "x", "passaporte": "x", "passport": "x",
       "jwt": "x", "bearer": "x", "chave": "x", "segredo": "x", "card_pan": "4111"}',
     '{"pwd": "[redacted]", "api-key": "[redacted]", "access_key": "[redacted]", "session": "[redacted]",
       "cookie": "[redacted]", "signature": "[redacted]", "hmac": "[redacted]", "pin": "[redacted]",
       "card_number": "[redacted]", "cartão": "[redacted]", "passaporte": "[redacted]", "passport": "[redacted]",
       "jwt": "[redacted]", "bearer": "[redacted]", "chave": "[redacted]", "segredo": "[redacted]",
       "card_pan": "[redacted]"}'),
    ('PII PT com e sem acentos, qualquer caixa', 'stores',
     '{"telemóvel": "9", "TELEMÓVEL": "9", "telemovel": "9", "nome": "Ana", "apelido": "S",
       "data_nascimento": "x", "contribuinte": "1", "morada": "r"}',
     '{"telemóvel": "[pii]", "TELEMÓVEL": "[pii]", "telemovel": "[pii]", "nome": "[pii]", "apelido": "[pii]",
       "data_nascimento": "[pii]", "contribuinte": "[pii]", "morada": "[pii]"}'),
    ('par {key, value}', 'stores',
     '{"key": "password", "value": "x"}', '{"key": "password", "value": "[redacted]"}'),
    ('par {field, value} com etiqueta PT acentuada → [pii]', 'stores',
     '{"field": "Telemóvel", "value": "912"}', '{"field": "Telemóvel", "value": "[pii]"}'),
    ('pares {name, value} dentro de arrays', 'stores',
     '{"attrs": [{"name": "chave_api", "value": "k"}, {"name": "cor", "value": "azul"}]}',
     '{"attrs": [{"name": "[pii]", "value": "[redacted]"}, {"name": "[pii]", "value": "azul"}]}'),
    ('JWT sob chave neutra', 'stores', '{"note": "eyJhbGciOi...x.y"}', '{"note": "[redacted]"}'),
    ('JWT completo com Bearer', 'stores',
     '{"note": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"}', '{"note": "[redacted]"}'),
    ('e-mail dentro de array', 'stores', '{"notes": ["joao@x.pt", "ok"]}', '{"notes": ["[pii]", "ok"]}'),
    ('prefixos de chave de API', 'stores',
     '{"comment": "sk_live_abc", "a": "AKIAIOSFODNN7EXAMPLE", "b": "ghp_abc", "c": "xoxb-1", "d": "pk_live_x",
       "e": "rk_live_x"}',
     '{"comment": "[redacted]", "a": "[redacted]", "b": "[redacted]", "c": "[redacted]", "d": "[redacted]",
       "e": "[redacted]"}'),
    ('IBAN por valor (no meio do texto, em grupos, ISO) → 4 últimos', 'stores',
     '{"note": "pagar a PT50000201231234567890154 hoje", "g": "PT50 0002 0123 1234 5678 9015 4",
       "de": "DE89370400440532013000"}',
     '{"note": "pagar a ****0154 hoje", "g": "****0154", "de": "****3000"}'),
    ('em claro: store_id, title, name de products, company_id, expand_id, japan, textos neutros', 'products',
     '{"store_id": "00000000-0000-7000-8000-0000000014c2", "title": "Bolo", "name": "Bolo", "company_id": "c1",
       "expand_id": "e1", "japan": "jp", "note": "loja.ptmarket.pt", "sku": "task_sk_1", "n": 12}',
     '{"store_id": "00000000-0000-7000-8000-0000000014c2", "title": "Bolo", "name": "Bolo", "company_id": "c1",
       "expand_id": "e1", "japan": "jp", "note": "loja.ptmarket.pt", "sku": "task_sk_1", "n": 12}'),
    ('profundidade 16 intacta', 'stores', pg_temp.nest(16), pg_temp.nest(16)),
    ('profundidade 17: o 17.º contentor → "[depth]"', 'stores', pg_temp.nest(17), pg_temp.nest(16, '"[depth]"'));
GRANT SELECT ON mask_cases TO ptmarket_app;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM mask_cases WHERE label = %L
              AND audit.audit_redact(tbl, input) = expected$q$, c.label),
    1, 'máscara: ' || c.label)
FROM mask_cases c ORDER BY c.label;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM mask_cases
       WHERE audit.audit_redact(tbl, audit.audit_redact(tbl, input)) IS DISTINCT FROM audit.audit_redact(tbl, input)$q$,
    0, 'máscara idempotente em todos os casos');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 3. Eventos da aplicação: limites → PTA02 com mensagem fixa (sem o valor), nada gravado.
-- ---------------------------------------------------------------------------
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000014aa', true);
SELECT set_config('app.actor_type', 'merchant', true);
SELECT pg_temp.blob(70000) AS big \gset
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
              NULL::text, jsonb_build_object('blob', %L::text), NULL::uuid)$q$, :'big'),
    'PTA02', left(:'big', 40), '64 KiB', 'app: changes > 64 KiB → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
              NULL::text, %L::jsonb, NULL::uuid)$q$, pg_temp.nest(17, '"segredo-fundo"')),
    'PTA02', 'segredo-fundo', 'profundidade', 'app: profundidade 17 → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
              %L::text, NULL::jsonb, NULL::uuid)$q$, 'Rz' || repeat('r', 1023)),
    'PTA02', 'Rzrrr', 'reason', 'app: reason > 1 KiB → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, %L::text, 'success'::text,
              NULL::text, NULL::jsonb, NULL::uuid)$q$, 'Tz' || repeat('t', 255)),
    'PTA02', 'Tzttt', 'target_id', 'app: target_id > 256 → PTA02');
SELECT set_config('app.actor_label', 'Lz' || repeat('l', 127), true);
SELECT pg_temp.expect_error_msg(
    $q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
       NULL::text, NULL::jsonb, NULL::uuid)$q$,
    'PTA02', 'Lzlll', 'actor_label', 'app: actor_label > 128 → PTA02');
SELECT set_config('app.actor_label', '', true);
-- NUL: o PostgreSQL recusa antes de a função correr (desvio do cartão: não há PTA02 possível).
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
       'a' || chr(0), NULL::jsonb, NULL::uuid)$q$, '54000', 'NUL em reason → recusado pelo PostgreSQL');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 'a' || chr(0), 'success'::text,
       NULL::text, NULL::jsonb, NULL::uuid)$q$, '54000', 'NUL em target_id → recusado pelo PostgreSQL');
SELECT pg_temp.expect_error(
    $q$SELECT set_config('app.actor_label', 'a' || chr(0), true)$q$, '54000',
    'NUL em actor_label → recusado pelo PostgreSQL');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
       NULL::text, '{"a": "x\u0000"}'::jsonb, NULL::uuid)$q$, '22P05', 'NUL em changes → recusado pelo PostgreSQL');
-- Limites exatos passam (2 eventos).
SELECT audit.audit_append('test.limits'::text, 'stores'::text, repeat('t', 256), 'success'::text,
    repeat('r', 1024), pg_temp.nest(16), NULL::uuid);
SELECT set_config('app.actor_label', repeat('l', 128), true);
SELECT audit.audit_append('test.limits'::text, 'stores'::text, 's1'::text, 'success'::text,
    NULL::text, jsonb_build_object('blob', left(:'big', 65000)), NULL::uuid);
-- reason e actor_label passam pela máscara por valor; target_id não.
SELECT set_config('app.actor_label', 'ana@loja.pt', true);
SELECT audit.audit_append('test.mask'::text, 'stores'::text, 'joao@x.pt'::text, 'success'::text,
    'pedido de joao@x.pt'::text, NULL::jsonb, NULL::uuid) AS masked_ev \gset
SELECT set_config('app.actor_label', '', true);
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;

SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(%L::jsonb))$q$, pg_temp.nest(17, '"segredo-fundo"')),
    'PTA02', 'segredo-fundo', 'profundidade', 'worker: profundidade 17 → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(NULL::jsonb, %L::text))$q$, 'Rz' || repeat('r', 1023)),
    'PTA02', 'Rzrrr', 'reason', 'worker: reason > 1 KiB → PTA02');
SELECT pg_temp.expect_error_msg(
    format($q$SELECT audit.audit_append_event(pg_temp.ev(jsonb_build_object('blob', %L::text)))$q$, :'big'),
    'PTA02', left(:'big', 40), '64 KiB', 'worker: changes > 64 KiB → PTA02');
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_event(pg_temp.ev(NULL::jsonb, 'a' || chr(0)))$q$, '54000',
    'worker: NUL em reason → recusado pelo PostgreSQL');
RESET ROLE;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events WHERE action = 'test.limits'$q$,
    2, 'nada gravado pelas recusas (só os 2 eventos nos limites exatos)');
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L
              AND reason = '[pii]' AND actor_label = '[pii]' AND target_id = 'joao@x.pt'$q$, :'masked_ev'),
    1, 'reason e actor_label mascarados por valor; target_id em claro');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 4. L1 (trigger de linhas): uma escrita de negócio nunca falha por causa da auditoria.
-- ---------------------------------------------------------------------------
-- Desde a 0033 as lojas só vivem em tenants national_portal.
INSERT INTO tenants (id, slug, custom_domain, name, tenant_type) VALUES
    ('00000000-0000-7000-8000-0000000014aa', 'mask-03d', 'mask-03d.teste.invalid', 'Mask 03d', 'national_portal');
SET ROLE ptmarket_app;
SELECT set_config('app.current_tenant_id', '00000000-0000-7000-8000-0000000014aa', true);
SELECT set_config('app.actor_type', 'merchant', true);
INSERT INTO stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000014c1', '00000000-0000-7000-8000-0000000014aa',
     'Loja 03d', 'loja-03d', 'Loja 03d Lda', '500000014', 'PT50000000000000000000014', 'l@teste.invalid');
INSERT INTO products (id, tenant_id, store_id, title, vat_rate_bps) VALUES
    ('00000000-0000-7000-8000-0000000014c2', '00000000-0000-7000-8000-0000000014aa',
     '00000000-0000-7000-8000-0000000014c1', '{"pt":"Bolo"}', 2300);
-- (1) Profundidade 20 numa coluna jsonb: passa; a máscara corta com "[depth]".
UPDATE products SET description = pg_temp.nest(20)
 WHERE id = '00000000-0000-7000-8000-0000000014c2';
-- (2) ~100 KiB numa folha: o UPDATE passa; a folha fica com o marcador truncated.
UPDATE products SET description = jsonb_build_object('pt', pg_temp.blob(100000))
 WHERE id = '00000000-0000-7000-8000-0000000014c2';
RESET ROLE;
-- (3) O dono (caminho 'db') também nunca falha.
UPDATE products SET description = jsonb_build_object('pt', 'x' || pg_temp.blob(99999))
 WHERE id = '00000000-0000-7000-8000-0000000014c2';
SET ROLE ptmarket_app;
-- (4) 20 folhas de 4000 (> 64 KiB no total, nenhuma > 4096): changes inteiro → marcador.
UPDATE products SET description = (SELECT jsonb_object_agg('k' || i, pg_temp.blob(4000)) FROM generate_series(1, 20) i)
 WHERE id = '00000000-0000-7000-8000-0000000014c2';
SELECT set_config('app.actor_type', '', true);
SELECT set_config('app.current_tenant_id', '', true);
RESET ROLE;

SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.update' AND target_id = '00000000-0000-7000-8000-0000000014c2'
         AND changes #>> '{after,description,pt,truncated}' = 'true'
         AND (changes #>> '{after,description,pt,bytes}')::int = 100000
         AND changes #>> '{after,description,pt,sha256}' ~ '^[0-9a-f]{64}$'
         AND octet_length(changes::text) <= 65536$q$,
    2, 'L1 (app e db): linha de ~100 KiB → UPDATE passa, folha com marcador truncated');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.update' AND target_id = '00000000-0000-7000-8000-0000000014c2'
         AND actor_type = 'merchant'
         AND changes ->> 'truncated' = 'true' AND (changes ->> 'bytes')::int > 65536
         AND changes ->> 'sha256' ~ '^[0-9a-f]{64}$'$q$,
    1, 'L1: ainda > 64 KiB depois de cortar folhas → changes inteiro com marcador truncated');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action = 'products.update' AND target_id = '00000000-0000-7000-8000-0000000014c2'
         AND (changes -> 'after')::text LIKE '%"[depth]"%'
         AND NOT jsonb_path_exists(changes, 'strict $.**{16} ? (@.type() == "object" || @.type() == "array")')$q$,
    1, 'L1: profundidade 20 → UPDATE passa, cortada com "[depth]"');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 5. Caminho 'db' direto: reason/actor_label não chegam aqui; target_id longo cortado com sha256.
-- ---------------------------------------------------------------------------
SELECT audit.audit_append_db('test.db_long'::text, 'x'::text, repeat('t', 300), pg_temp.nest(18),
    NULL::uuid, NULL::uuid) AS db_ev \gset
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    format($q$SELECT count(*) FROM audit.audit_events WHERE id = %L
              AND target_id = repeat('t', 180) || '…sha256:' || encode(sha256(convert_to(repeat('t', 300), 'UTF8')), 'hex')
              AND char_length(target_id) <= 256 AND changes::text LIKE '%%"[depth]"%%'$q$, :'db_ev'),
    1, 'db: target_id > 256 → 180 + …sha256:<hex>; profundidade 18 → "[depth]"');
RESET ROLE;

-- ---------------------------------------------------------------------------
-- 6. L2 (DDL): identidade de objeto > 256 → a migration não falha; target_id cortado.
-- ---------------------------------------------------------------------------
SET LOCAL event_triggers = on;
CREATE FUNCTION public.zz_03d_long_signature(
    a1 timestamp with time zone, a2 timestamp with time zone, a3 timestamp with time zone,
    a4 timestamp with time zone, a5 timestamp with time zone, a6 timestamp with time zone,
    a7 timestamp with time zone, a8 timestamp with time zone, a9 timestamp with time zone,
    a10 timestamp with time zone, a11 timestamp with time zone, a12 timestamp with time zone)
RETURNS int LANGUAGE sql AS 'SELECT 1';
DROP FUNCTION public.zz_03d_long_signature(timestamptz, timestamptz, timestamptz, timestamptz, timestamptz,
    timestamptz, timestamptz, timestamptz, timestamptz, timestamptz, timestamptz, timestamptz);
SET LOCAL event_triggers = off;
SET ROLE ptmarket_audit_writer;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit.audit_events
       WHERE action IN ('ddl.create_function', 'ddl.drop_function')
         AND target_id LIKE 'public.zz_03d_long_signature(%'
         AND char_length(target_id) <= 256 AND target_id ~ '…sha256:[0-9a-f]{64}$'$q$,
    2, 'L2: CREATE/DROP FUNCTION com identidade > 256 passam; target_id cortado com sha256');
RESET ROLE;

ROLLBACK;
