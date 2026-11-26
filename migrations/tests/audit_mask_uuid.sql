-- run.sh: superuser
-- Teste da 0023 (cartão 02/03f): audit._redact_text não altera UUIDs (sozinhos ou dentro de texto) e continua a
-- mascarar o resto à volta deles. Os vetores partilhados (docs/testdata/redaction-vectors.json) correm no
-- audit_mask_v2.sql; aqui: alteração selada, atributos da função, os UUIDs do relatório, 13 600 UUIDs gerados e o
-- UUID intacto no vetor de controlo (o formato dos vetores não tem must_contain).
-- Corre como superuser só para ler audit_admin.sealed_changes; as asserções da máscara são feitas com SET ROLE
-- ptmarket_app (_redact_text e audit_redact são INVOKER). Tudo numa transação com ROLLBACK.

BEGIN;
SET LOCAL event_triggers = off; -- só funções em pg_temp; nada a auditar

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

-- Lista vazia = passou; senão falha com o que veio (só UUIDs e textos de teste, nunca dados reais).
CREATE FUNCTION pg_temp.expect_none(p_sql text, p_label text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_bad text;
BEGIN
    EXECUTE p_sql INTO v_bad;
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION 'FALHOU: % (%)', p_label, left(v_bad, 500);
    END IF;
    RAISE NOTICE 'OK: %', p_label;
END
$$;

-- ---------------------------------------------------------------------------
-- 1. Alteração selada 0023_mask_uuid: aprovada, aplicada, só _redact_text; atributos iguais aos da 0020.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes c JOIN audit_admin.sealed_changes_applied a USING (name)
       WHERE c.name = '0023_mask_uuid' AND c.requires = '0020_mask_v2'
         AND c.sha256 = encode(sha256(convert_to(c.sql, 'UTF8')), 'hex')
         AND c.sha256 = '643d2b792d24eb5009d8ca6110d3a759bf139abf6daf4db7d318bf6458d64bf1'$q$,
    1, '0023_mask_uuid aprovada (requires 0020_mask_v2), aplicada, com o sha256 que a 0023 dispara');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM audit_admin.sealed_changes
       WHERE name = '0023_mask_uuid'
         AND (SELECT count(*) FROM regexp_matches(sql, '\m(CREATE|ALTER|DROP|GRANT|REVOKE)\M', 'g')) = 1
         AND sql ~ 'CREATE OR REPLACE FUNCTION audit\._redact_text\(p_value text\)'$q$,
    1, '0023_mask_uuid: um só comando, CREATE OR REPLACE de audit._redact_text(text)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
       WHERE p.oid = 'audit._redact_text(text)'::regprocedure
         AND p.provolatile = 'i' AND p.proparallel = 's' AND NOT p.prosecdef
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND r.rolname = 'ptmarket_audit_owner'
         AND strpos(p.prosrc, 'v_scan') > 0$q$,
    1, '_redact_text: corpo novo, IMMUTABLE PARALLEL SAFE, INVOKER, search_path fixo, dono ptmarket_audit_owner');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc WHERE pronamespace = 'audit'::regnamespace AND proname = '_redact_text'$q$,
    1, '_redact_text: uma só assinatura');
SELECT pg_temp.expect_none(
    $q$WITH g AS (
           SELECT a.grantee, a.privilege_type
           FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
           WHERE p.oid = 'audit._redact_text(text)'::regprocedure AND a.grantee <> p.proowner)
       SELECT string_agg(x, ', ') FROM (
           SELECT 'a mais: ' || CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE g.grantee::regrole::text END AS x FROM g
           WHERE g.grantee NOT IN ('ptmarket_app'::regrole, 'ptmarket_worker'::regrole,
                                   'ptmarket_price_writer'::regrole, 'ptmarket_audit_writer'::regrole)
              OR g.privilege_type <> 'EXECUTE'
           UNION ALL
           SELECT 'em falta: ' || r FROM unnest(ARRAY['ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer',
                                                     'ptmarket_audit_writer']) AS r
           WHERE NOT EXISTS (SELECT 1 FROM g WHERE g.grantee = r::regrole AND g.privilege_type = 'EXECUTE')) s$q$,
    '_redact_text: EXECUTE só para app, worker, price_writer e audit_writer (grants da 0014 mantidos)');

-- ---------------------------------------------------------------------------
-- 2. UUIDs intactos: os do relatório (meio com forma de IBAN) e 13 600 gerados.
-- ---------------------------------------------------------------------------
CREATE TEMP TABLE report_uuids (u text NOT NULL);
INSERT INTO report_uuids VALUES
    ('01a2185a-ac77-73f5-8fa6-b4840a004eeb'),
    ('01a2185a-bd21-7437-b788-4e359b080843'),
    ('01a2185a-dd68-71a1-9c3e-5f1a2b3c4d5e'),
    ('01a2185a-ee44-73f2-a1b2-c3d4e5f60718');
-- 5 000 UUIDv7 espalhados no tempo (±30 anos: o segmento do meio varia), 5 000 v4 e 3 600 com o 2.º grupo
-- "2 letras hex + 2 dígitos" (todas as combinações; a forma exata do bug).
CREATE TEMP TABLE gen_uuids AS
    SELECT uuidv7(make_interval(secs => (random() * 2e9 - 1e9)::double precision))::text AS u
    FROM generate_series(1, 5000)
    UNION ALL
    SELECT gen_random_uuid()::text FROM generate_series(1, 5000)
    UNION ALL
    SELECT format('01a2185a-%s%s%s-7%s-8fa6-b4840a004eeb', l1, l2, lpad(n::text, 2, '0'), lpad(n::text, 3, '0'))
    FROM unnest(ARRAY['a', 'b', 'c', 'd', 'e', 'f']) AS l1, unnest(ARRAY['a', 'b', 'c', 'd', 'e', 'f']) AS l2,
         generate_series(0, 99) AS n;
GRANT SELECT ON report_uuids, gen_uuids TO ptmarket_app;

SET ROLE ptmarket_app;
SELECT pg_temp.expect_value($q$SELECT count(*) FROM gen_uuids$q$, 13600, '13 600 UUIDs gerados');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(t.x, ' | ') FROM report_uuids r
       CROSS JOIN LATERAL (VALUES (r.u), (upper(r.u)), ('pedido ' || r.u || ' falhou'), ('id=' || r.u || ';'),
                                  ('(' || r.u || ')'), ('ref:' || r.u || ',' || upper(r.u)),
                                  (r.u || ' ' || r.u), (r.u || E'\n' || r.u)) AS t(x)
       WHERE audit._redact_text(t.x) IS DISTINCT FROM t.x$q$,
    'UUIDs do relatório (ac77-73f5, bd21-7437, dd68-71a1, ee44-73f2) intactos, sozinhos e dentro de texto');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(g.u, ', ') FROM gen_uuids g
       WHERE audit._redact_text(g.u) IS DISTINCT FROM g.u
          OR audit._redact_text('pedido ' || g.u || ' falhou') IS DISTINCT FROM 'pedido ' || g.u || ' falhou'
          OR audit._redact_text(upper(g.u) || ' ' || g.u) IS DISTINCT FROM upper(g.u) || ' ' || g.u$q$,
    '13 600 UUIDs (v7, v4, forma do bug) intactos, sozinhos, em texto, em maiúsculas e aos pares');
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(r.u, ', ') FROM report_uuids r
       WHERE audit.audit_redact('vectors'::text, jsonb_build_object('note', 'pedido ' || r.u || ' falhou',
                                                                'list', jsonb_build_array(r.u)))
             IS DISTINCT FROM jsonb_build_object('note', 'pedido ' || r.u || ' falhou', 'list', jsonb_build_array(r.u))$q$,
    'audit_redact (JSON): UUIDs do relatório intactos em valores e listas');

-- ---------------------------------------------------------------------------
-- 3. O que era mascarado continua a sê-lo ao lado de um UUID (e o UUID fica intacto quando o texto fica).
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_none(
    $q$SELECT string_agg(t.label || ' → ' || COALESCE(audit._redact_text(t.x), 'NULL'), ' | ')
       FROM (VALUES
           ('controlo IBAN + UUID', 'PT50 0002 0123 1234 5678 9015 4 ref 01a2185a-ac77-73f5-8fa6-b4840a004eeb',
            '****0154 ref 01a2185a-ac77-73f5-8fa6-b4840a004eeb'),
           ('UUID + IBAN', '01a2185a-ac77-73f5-8fa6-b4840a004eeb PT50-0002-0123-1234-5678-9015-4',
            '01a2185a-ac77-73f5-8fa6-b4840a004eeb ****0154'),
           ('IBAN colado a UUID', 'ref:01a2185a-ac77-73f5-8fa6-b4840a004eeb,PT50000201231234567890154',
            'ref:01a2185a-ac77-73f5-8fa6-b4840a004eeb,****0154'),
           ('NIB entre UUIDs', '01a2185a-ac77-73f5-8fa6-b4840a004eeb 0002 0123 1234 5678 9015 4 '
                               || '01a2185a-bd21-7437-b788-4e359b080843',
            '01a2185a-ac77-73f5-8fa6-b4840a004eeb ****0154 01a2185a-bd21-7437-b788-4e359b080843'),
           ('NIF + UUID', 'nif 123456789 ref 01a2185a-ac77-73f5-8fa6-b4840a004eeb', '[pii]'),
           ('UUID + DNI', '01a2185a-ac77-73f5-8fa6-b4840a004eeb 12345678Z', '[pii]'),
           ('UUID + telefone', '01a2185a-ac77-73f5-8fa6-b4840a004eeb +351 912 345 678', '[pii]'),
           ('UUID + telefone PT', '01a2185a-ac77-73f5-8fa6-b4840a004eeb 912345678', '[pii]'),
           ('UUID + telefone 00', '01a2185a-ac77-73f5-8fa6-b4840a004eeb 00351912345678', '[pii]'),
           ('PAN + UUID', '4111 1111 1111 1111 01a2185a-ac77-73f5-8fa6-b4840a004eeb', '[redacted]'),
           ('UUID + e-mail', '01a2185a-ac77-73f5-8fa6-b4840a004eeb ana@exemplo.pt', '[pii]'),
           ('UUID + JWT', '01a2185a-ac77-73f5-8fa6-b4840a004eeb eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln',
            '[redacted]'),
           ('só dígitos em texto', '12345678-1234-1234-1234-123456789012 falhou',
            '12345678-1234-1234-1234-123456789012 falhou'),
           ('texto vazio', '', ''),
           ('ISO sozinha', '2026-11-26T10:00:00Z', '2026-11-26T10:00:00Z')
       ) AS t(label, x, expected)
       WHERE audit._redact_text(t.x) IS DISTINCT FROM t.expected$q$,
    'IBAN/NIB/NIF/DNI/telefone/PAN/e-mail/JWT ao lado de UUIDs continuam mascarados; os UUIDs ficam');
-- Não é UUID (sem fronteira de palavra): sem proteção, como no Rust e no Go (\b … \b).
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (VALUES ('x_01a2185a-ac77-73f5-8fa6-b4840a004eeb'),
                                     ('01a2185a-ac77-73f5-8fa6-b4840a004eeb4')) AS t(x)
       WHERE strpos(audit._redact_text(t.x), 'ac77-73f5') = 0$q$,
    2, 'sem fronteira de palavra não é UUID: as regras numéricas aplicam-se');
RESET ROLE;

ROLLBACK;
