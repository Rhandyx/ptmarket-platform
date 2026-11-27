-- run.sh: superuser
-- Teste da 0037 (cartão 03/10): revisão das verificações de loja pelo super_admin com 2FA.
--   Lista com cursor (3 páginas, sem repetidos, empate em created_at), segredo, decisão (aprova, rejeita, 30 dias,
--   0 linhas à 2.ª), L1 do UPDATE (ator 'db', session_user ptmarket_app), porta (merchant, municipal, sponsor_admin,
--   sem TOTP, sessão sem 2FA, revogada, de tenant, sem sessão, session_user ≠ ptmarket_app) → 42501, validação →
--   22023, catálogo (proacl, prosecdef, proconfig, dono), grants e policies mínimos de ptmarket_identity, EXECUTE em
--   audit_append_db só para quem está na allowlist (e mantido pela audit_seal).
-- Superuser só para semear (ignora RLS) e ler catálogos/audit.*; as chamadas fazem SET SESSION AUTHORIZATION
-- ptmarket_app (session_user real). Tudo numa transação com ROLLBACK. now() é constante na transação.
--   T1 = nacional PT, lojas L1 e L2 (mesmo país).

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

-- Contexto do pedido (como o TenantTx/AuditCtx: local à transação).
CREATE FUNCTION pg_temp.ctx(p_type text, p_actor text, p_session text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.actor_type', COALESCE(p_type, ''), true);
    PERFORM set_config('app.actor_id', COALESCE(p_actor, ''), true);
    PERFORM set_config('app.session_id', COALESCE(p_session, ''), true);
END
$$;

-- As três funções recusadas (42501) no contexto atual; a decisão usa uma linha pending válida.
CREATE FUNCTION pg_temp.expect_denied(p_label text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_temp.expect_error(
        $q$SELECT * FROM public.identity_admin_verifications_list('pending', NULL, NULL, 10)$q$,
        '42501', p_label || ': list → 42501');
    PERFORM pg_temp.expect_error(
        $q$SELECT * FROM public.identity_admin_verification_secret('00000000-0000-7000-8000-000000003705')$q$,
        '42501', p_label || ': secret → 42501');
    PERFORM pg_temp.expect_error(
        $q$SELECT * FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003705', true, NULL)$q$,
        '42501', p_label || ': decide → 42501');
END
$$;

CREATE TEMP TABLE pages (page int, ord bigint, id uuid, created_at timestamptz);
CREATE TEMP TABLE res (label text, id uuid, tenant_id uuid, store_id uuid, store_name text, store_legal_name text,
    store_nif text, kind text, status text, has_file boolean, has_access_code boolean, sha256 bytea,
    created_at timestamptz, reviewed_at timestamptz, delete_after timestamptz);
CREATE TEMP TABLE sec (label text, tenant_id uuid, store_id uuid, storage_key text, sha256 bytea, access_code_enc text);
CREATE TEMP TABLE dcs (label text, tenant_id uuid, store_id uuid, status text, delete_after timestamptz);
GRANT SELECT, INSERT ON pages, res, sec, dcs TO ptmarket_app;

-- ---------------------------------------------------------------------------
-- 0. Sementes (superuser).
--    Utilizadores: SA super_admin com TOTP · SN super_admin sem TOTP · M merchant_owner de L1 · SP sponsor_admin.
--    Sessões da plataforma: 5101 SA com 2FA · 5102 SA sem 2FA · 5103 SA revogada · 5104 SA de tenant (com 2FA)
--      · 5105 SN com 2FA · 5106 M com 2FA · 5107 SP com 2FA.
--    Verificações (T1): pending 3701 L1 pdf (-5h) · 3702 L1 código (-4h) · 3703 L2 declaração (-4h, mesmo instante
--      que 3702: desempate por id) · 3704 L2 manual (-3h) · 3705 L1 comprovativo (-1h); 3706 L2 pdf approved.
-- ---------------------------------------------------------------------------
SELECT set_config('app.actor_type', 'system', true), set_config('app.actor_label', 'test', true);

INSERT INTO public.tenants (id, slug, custom_domain, name, tenant_type, country_code) VALUES
    ('00000000-0000-7000-8000-0000000037a1', 'iav-npt', 'iav-npt.teste.invalid', 'Nacional PT 37',
     'national_portal', 'PT');
INSERT INTO public.stores (id, tenant_id, name, slug, legal_name, nif, iban, email) VALUES
    ('00000000-0000-7000-8000-0000000037b1', '00000000-0000-7000-8000-0000000037a1',
     'Loja V1', 'iav-l1', 'V1 Lda', '500003701', 'PT50000000000000000003701', 'v1@teste.invalid'),
    ('00000000-0000-7000-8000-0000000037b2', '00000000-0000-7000-8000-0000000037a1',
     'Loja V2', 'iav-l2', 'V2 Unipessoal', '200003702', 'PT50000000000000000003702', 'v2@teste.invalid');
INSERT INTO public.sponsor_entities (id, kind, country_code, name, slug) VALUES
    ('00000000-0000-7000-8000-0000000037e1', 'association', 'PT', 'Associação 37', 'iav-assoc');

INSERT INTO public.users (id, email, full_name, totp_secret_enc, totp_enabled) VALUES
    ('00000000-0000-7000-8000-000000370001', 'sa@ptm37.test', 'SA', 'v1:a', true),
    ('00000000-0000-7000-8000-000000370002', 'sn@ptm37.test', 'SN', NULL, false),
    ('00000000-0000-7000-8000-000000370003', 'm@ptm37.test', 'M', 'v1:m', true),
    ('00000000-0000-7000-8000-000000370004', 'sp@ptm37.test', 'SP', 'v1:p', true);
INSERT INTO public.user_roles (user_id, role, tenant_id, store_id, sponsor_entity_id) VALUES
    ('00000000-0000-7000-8000-000000370001', 'super_admin', NULL, NULL, NULL),
    ('00000000-0000-7000-8000-000000370002', 'super_admin', NULL, NULL, NULL),
    ('00000000-0000-7000-8000-000000370003', 'merchant_owner', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b1', NULL),
    ('00000000-0000-7000-8000-000000370004', 'sponsor_admin', NULL, NULL, '00000000-0000-7000-8000-0000000037e1');
INSERT INTO public.sessions (id, subject_type, subject_id, token_hash, tenant_id, mfa_verified_at, expires_at,
                             revoked_at) VALUES
    ('00000000-0000-7000-8000-000000375101', 'user', '00000000-0000-7000-8000-000000370001', sha256('37a'::bytea),
     NULL, now(), now() + interval '8 hours', NULL),
    ('00000000-0000-7000-8000-000000375102', 'user', '00000000-0000-7000-8000-000000370001', sha256('37b'::bytea),
     NULL, NULL, now() + interval '8 hours', NULL),
    ('00000000-0000-7000-8000-000000375103', 'user', '00000000-0000-7000-8000-000000370001', sha256('37c'::bytea),
     NULL, now(), now() + interval '8 hours', now()),
    ('00000000-0000-7000-8000-000000375104', 'user', '00000000-0000-7000-8000-000000370001', sha256('37d'::bytea),
     '00000000-0000-7000-8000-0000000037a1', now(), now() + interval '8 hours', NULL),
    ('00000000-0000-7000-8000-000000375105', 'user', '00000000-0000-7000-8000-000000370002', sha256('37e'::bytea),
     NULL, now(), now() + interval '8 hours', NULL),
    ('00000000-0000-7000-8000-000000375106', 'user', '00000000-0000-7000-8000-000000370003', sha256('37f'::bytea),
     NULL, now(), now() + interval '8 hours', NULL),
    ('00000000-0000-7000-8000-000000375107', 'user', '00000000-0000-7000-8000-000000370004', sha256('37g'::bytea),
     NULL, now(), now() + interval '8 hours', NULL);

INSERT INTO public.store_verifications (id, tenant_id, store_id, kind, sha256, storage_key, access_code_enc,
                                        created_at) VALUES
    ('00000000-0000-7000-8000-000000003701', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b1', 'certidao_permanente_pdf', sha256('3701'::bytea), 'verif/3701.pdf',
     NULL, now() - interval '5 hours'),
    ('00000000-0000-7000-8000-000000003702', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b1', 'certidao_permanente_code', NULL, NULL,
     'v1:0a1b2c3d:ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/u', now() - interval '4 hours'),
    ('00000000-0000-7000-8000-000000003703', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b2', 'declaracao_inicio_atividade', sha256('3703'::bytea), 'verif/3703.pdf',
     NULL, now() - interval '4 hours'),
    ('00000000-0000-7000-8000-000000003704', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b2', 'manual_other', sha256('3704'::bytea), 'verif/3704.pdf',
     NULL, now() - interval '3 hours'),
    ('00000000-0000-7000-8000-000000003705', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b1', 'comprovativo_domicilio_fiscal', sha256('3705'::bytea),
     'verif/3705.pdf', NULL, now() - interval '1 hour');
INSERT INTO public.store_verifications (id, tenant_id, store_id, kind, sha256, storage_key, status, reviewed_at,
                                        delete_after, created_at) VALUES
    ('00000000-0000-7000-8000-000000003706', '00000000-0000-7000-8000-0000000037a1',
     '00000000-0000-7000-8000-0000000037b2', 'certidao_permanente_pdf', sha256('3706'::bytea), 'verif/3706.pdf',
     'approved', now() - interval '1 hour', now() + interval '29 days', now() - interval '10 hours');

CREATE TEMP TABLE l1_before AS
SELECT count(*) AS n FROM audit.audit_events WHERE action = 'store_verifications.update';

-- ---------------------------------------------------------------------------
-- 1. Porta: session_user ≠ ptmarket_app (superuser ou migrator com SET ROLE ptmarket_app) → 42501.
-- ---------------------------------------------------------------------------
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375101');
SET ROLE ptmarket_app;
SELECT pg_temp.expect_denied('SET ROLE ptmarket_app com session_user postgres');
RESET ROLE;
SET SESSION AUTHORIZATION ptmarket_migrator;
SET ROLE ptmarket_app;
SELECT pg_temp.expect_denied('migrator com SET ROLE ptmarket_app');
RESET ROLE;
RESET SESSION AUTHORIZATION;

-- ---------------------------------------------------------------------------
-- 2. Porta como ptmarket_app (session_user): cada contexto inválido → 42501 nas três.
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_app;
SELECT pg_temp.ctx('merchant', '00000000-0000-7000-8000-000000370003', '00000000-0000-7000-8000-000000375106');
SELECT pg_temp.expect_denied('contexto merchant');
SELECT pg_temp.ctx('municipal', '00000000-0000-7000-8000-000000370004', '00000000-0000-7000-8000-000000375107');
SELECT pg_temp.expect_denied('contexto municipal (sponsor_admin)');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370004', '00000000-0000-7000-8000-000000375107');
SELECT pg_temp.expect_denied('ator admin mas papel sponsor_admin');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370003', '00000000-0000-7000-8000-000000375106');
SELECT pg_temp.expect_denied('ator admin mas papel merchant_owner');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370002', '00000000-0000-7000-8000-000000375105');
SELECT pg_temp.expect_denied('super_admin sem TOTP');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375102');
SELECT pg_temp.expect_denied('sessão sem mfa_verified_at');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375103');
SELECT pg_temp.expect_denied('sessão revogada');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375104');
SELECT pg_temp.expect_denied('sessão de tenant (não da plataforma)');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375106');
SELECT pg_temp.expect_denied('sessão de outro utilizador');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', NULL);
SELECT pg_temp.expect_denied('sem sessão no contexto');
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375101');
SELECT set_config('app.impersonator_id', '00000000-0000-7000-8000-000000370003', true);
SELECT pg_temp.expect_denied('com app.impersonator_id');
SELECT set_config('app.impersonator_id', '', true);

-- ---------------------------------------------------------------------------
-- 3. Validação (super_admin com 2FA) → 22023.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verifications_list('pending', NULL, NULL, 0)$q$, '22023', 'limit 0 → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verifications_list('pending', NULL, NULL, 101)$q$, '22023',
    'limit 101 → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verifications_list(NULL, NULL, NULL, NULL)$q$, '22023',
    'limit NULL → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verifications_list('canceled', NULL, NULL, 10)$q$, '22023',
    'estado inválido → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verifications_list('pending', now(), NULL, 10)$q$, '22023',
    'cursor só com a data → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003705', false, NULL)$q$,
    '22023', 'rejeição sem motivo → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003705', false, '   ')$q$,
    '22023', 'rejeição com motivo só de espaços → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003705', true,
                                                               repeat('x', 501))$q$,
    '22023', 'motivo com 501 caracteres → 22023');
SELECT pg_temp.expect_error(
    $q$SELECT * FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003705', NULL, 'x')$q$,
    '22023', 'decisão NULL → 22023');

-- ---------------------------------------------------------------------------
-- 4. Lista: pendentes de L1 e L2 em 3 páginas de 2 (cursor do último de cada página).
-- ---------------------------------------------------------------------------
INSERT INTO pages
SELECT 1, f.ord, f.id, f.created_at
FROM public.identity_admin_verifications_list('pending', NULL, NULL, 2)
     WITH ORDINALITY AS f(id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file,
                          has_access_code, sha256, created_at, reviewed_at, delete_after, ord);
INSERT INTO pages
SELECT 2, f.ord, f.id, f.created_at
FROM (SELECT p.created_at, p.id FROM pages p WHERE p.page = 1 ORDER BY p.ord DESC LIMIT 1) c,
     LATERAL public.identity_admin_verifications_list('pending', c.created_at, c.id, 2)
     WITH ORDINALITY AS f(id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file,
                          has_access_code, sha256, created_at, reviewed_at, delete_after, ord);
INSERT INTO pages
SELECT 3, f.ord, f.id, f.created_at
FROM (SELECT p.created_at, p.id FROM pages p WHERE p.page = 2 ORDER BY p.ord DESC LIMIT 1) c,
     LATERAL public.identity_admin_verifications_list('pending', c.created_at, c.id, 2)
     WITH ORDINALITY AS f(id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file,
                          has_access_code, sha256, created_at, reviewed_at, delete_after, ord);
INSERT INTO pages
SELECT 4, f.ord, f.id, f.created_at
FROM (SELECT p.created_at, p.id FROM pages p WHERE p.page = 3 ORDER BY p.ord DESC LIMIT 1) c,
     LATERAL public.identity_admin_verifications_list('pending', c.created_at, c.id, 2)
     WITH ORDINALITY AS f(id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file,
                          has_access_code, sha256, created_at, reviewed_at, delete_after, ord);

INSERT INTO res SELECT 'all', f.* FROM public.identity_admin_verifications_list(NULL, NULL, NULL, 100) f;
INSERT INTO res SELECT 'approved', f.* FROM public.identity_admin_verifications_list('approved', NULL, NULL, 100) f;
RESET SESSION AUTHORIZATION;

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT array_agg(id ORDER BY page, ord) AS ids FROM pages) s
       WHERE s.ids = ARRAY['00000000-0000-7000-8000-000000003701', '00000000-0000-7000-8000-000000003702',
                           '00000000-0000-7000-8000-000000003703', '00000000-0000-7000-8000-000000003704',
                           '00000000-0000-7000-8000-000000003705']::uuid[]$q$,
    1, 'pendentes de L1 e L2: 3701, 3702, 3703 (empate em created_at, por id), 3704, 3705 por (created_at, id) ASC');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM (SELECT array_agg(n ORDER BY page) AS ns
                             FROM (SELECT page, count(*) AS n FROM pages GROUP BY page) g) s
       WHERE s.ns = ARRAY[2, 2, 1]::bigint[]$q$,
    1, '3 páginas (2, 2, 1) e a 4.ª vazia');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) - count(DISTINCT id) FROM pages$q$, 0, 'cursor: sem repetidos entre páginas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res
       WHERE label = 'all' AND tenant_id = '00000000-0000-7000-8000-0000000037a1'$q$,
    6, 'estado NULL: as 6 (pending e approved)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res
       WHERE label = 'approved' AND id = '00000000-0000-7000-8000-000000003706' AND status = 'approved'
         AND reviewed_at IS NOT NULL AND delete_after IS NOT NULL$q$,
    1, 'filtro approved: 3706 com reviewed_at e delete_after');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res WHERE label = 'approved' AND status <> 'approved'$q$, 0, 'filtro approved: só approved');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM res
       WHERE label = 'all'
         AND ((id = '00000000-0000-7000-8000-000000003701' AND store_id = '00000000-0000-7000-8000-0000000037b1'
               AND store_name = 'Loja V1' AND store_legal_name = 'V1 Lda' AND store_nif = '500003701'
               AND kind = 'certidao_permanente_pdf' AND status = 'pending' AND has_file AND NOT has_access_code
               AND sha256 = sha256('3701'::bytea) AND reviewed_at IS NULL AND delete_after IS NULL)
           OR (id = '00000000-0000-7000-8000-000000003702' AND store_nif = '500003701' AND NOT has_file
               AND has_access_code AND sha256 IS NULL)
           OR (id = '00000000-0000-7000-8000-000000003703' AND store_name = 'Loja V2'
               AND store_legal_name = 'V2 Unipessoal' AND store_nif = '200003702' AND has_file))$q$,
    3, 'lista: dados da loja (nome, nome legal, NIF), has_file / has_access_code e sha256 certos');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE pg_get_function_result(
           'public.identity_admin_verifications_list(text, timestamptz, uuid, integer)'::regprocedure)
           ~ '(storage_key|access_code_enc|iban|email|phone|kyc)'$q$,
    0, 'lista: o retorno não tem storage_key, access_code_enc, iban nem outras colunas da loja');

-- ---------------------------------------------------------------------------
-- 5. Segredo e decisão (super_admin com 2FA).
-- ---------------------------------------------------------------------------
SET SESSION AUTHORIZATION ptmarket_app;
SELECT pg_temp.ctx('admin', '00000000-0000-7000-8000-000000370001', '00000000-0000-7000-8000-000000375101');
INSERT INTO sec SELECT 'pdf', f.* FROM public.identity_admin_verification_secret('00000000-0000-7000-8000-000000003701') f;
INSERT INTO sec SELECT 'code', f.* FROM public.identity_admin_verification_secret('00000000-0000-7000-8000-000000003702') f;
INSERT INTO sec SELECT 'none', f.* FROM public.identity_admin_verification_secret('00000000-0000-7000-8000-0000000037ff') f;

INSERT INTO dcs SELECT 'approve_file', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003701', true, NULL) f;
INSERT INTO dcs SELECT 'reject_file', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003703', false, '  Documento ilegível  ') f;
INSERT INTO dcs SELECT 'approve_code', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003702', true, repeat('y', 500)) f;
INSERT INTO dcs SELECT 'again', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003701', false, 'outra vez') f;
INSERT INTO dcs SELECT 'again_approved', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-000000003706', true, NULL) f;
INSERT INTO dcs SELECT 'missing', f.*
FROM public.identity_admin_verification_decide('00000000-0000-7000-8000-0000000037ff', true, NULL) f;
RESET SESSION AUTHORIZATION;

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM sec
       WHERE (label = 'pdf' AND tenant_id = '00000000-0000-7000-8000-0000000037a1'
              AND store_id = '00000000-0000-7000-8000-0000000037b1' AND storage_key = 'verif/3701.pdf'
              AND sha256 = sha256('3701'::bytea) AND access_code_enc IS NULL)
          OR (label = 'code' AND storage_key IS NULL AND sha256 IS NULL AND access_code_enc = 'v1:0a1b2c3d:ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/u')$q$,
    2, 'secret: chave do ficheiro + hash; código só cifrado (v1:), NULL onde não há');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM sec WHERE label = 'none'$q$, 0, 'secret: id inexistente → 0 linhas');

SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM dcs
       WHERE (label = 'approve_file' AND status = 'approved' AND tenant_id = '00000000-0000-7000-8000-0000000037a1'
              AND store_id = '00000000-0000-7000-8000-0000000037b1' AND delete_after = now() + interval '30 days')
          OR (label = 'reject_file' AND status = 'rejected' AND store_id = '00000000-0000-7000-8000-0000000037b2'
              AND delete_after = now() + interval '30 days')
          OR (label = 'approve_code' AND status = 'approved' AND delete_after = now() + interval '30 days')$q$,
    3, 'decide: aprova e rejeita; delete_after = decisão + 30 dias com ficheiro e também só com código');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM dcs WHERE label IN ('again', 'again_approved', 'missing')$q$,
    0, 'decide: já decidida (2.ª vez ou approved de origem) ou inexistente → 0 linhas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.store_verifications v
       WHERE (v.id = '00000000-0000-7000-8000-000000003701' AND v.status = 'approved' AND v.review_reason IS NULL)
          OR (v.id = '00000000-0000-7000-8000-000000003703' AND v.status = 'rejected'
              AND v.review_reason = 'Documento ilegível')
          OR (v.id = '00000000-0000-7000-8000-000000003702' AND v.review_reason = repeat('y', 500))$q$,
    3, 'decide: motivo gravado (btrim; 500 aceite); a 2.ª decisão não mudou 3701');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.store_verifications v
       WHERE v.id IN ('00000000-0000-7000-8000-000000003701', '00000000-0000-7000-8000-000000003702',
                      '00000000-0000-7000-8000-000000003703')
         AND v.reviewed_by = '00000000-0000-7000-8000-000000370001' AND v.reviewed_at = now()
         AND v.delete_after = v.reviewed_at + interval '30 days'
         AND v.file_deleted_at IS NULL$q$,
    3, 'decide: reviewed_by = app.actor_id, reviewed_at = now(), delete_after = reviewed_at + 30 dias');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.store_verifications v
       WHERE v.id IN ('00000000-0000-7000-8000-000000003704', '00000000-0000-7000-8000-000000003705')
         AND v.status = 'pending' AND v.reviewed_at IS NULL$q$,
    2, 'recusas e erros de validação não decidiram nada (3704, 3705 continuam pending)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM public.stores
       WHERE tenant_id = '00000000-0000-7000-8000-0000000037a1' AND kyc_verified$q$,
    0, 'decide não mexe em stores.kyc_verified');

-- L1: cada decisão gravou store_verifications.update com ator 'db' e session_user ptmarket_app.
SELECT pg_temp.expect_value(
    $q$SELECT count(*) - (SELECT n FROM l1_before) FROM audit.audit_events WHERE action = 'store_verifications.update'$q$,
    3, 'L1: 3 decisões → 3 eventos store_verifications.update (0 linhas, recusas e 22023 → nenhum)');
SELECT pg_temp.expect_value(
    $q$SELECT count(DISTINCT e.target_id) FROM audit.audit_events e
       WHERE e.action = 'store_verifications.update'
         AND e.target_id IN ('00000000-0000-7000-8000-000000003701', '00000000-0000-7000-8000-000000003702',
                             '00000000-0000-7000-8000-000000003703')
         AND e.actor_type = 'db' AND e.actor_label = 'ptmarket_app' AND e.db_user = 'ptmarket_app'
         AND e.tenant_id = '00000000-0000-7000-8000-0000000037a1' AND e.store_id IS NOT NULL
         AND e.changes -> 'after' ->> 'status' IN ('approved', 'rejected')$q$,
    3, 'L1: ator db, actor_label e db_user = ptmarket_app (session_user), tenant e loja, status no after');

-- ---------------------------------------------------------------------------
-- 6. Catálogo das três funções: DEFINER, dono ptmarket_identity, search_path fixo, EXECUTE só ptmarket_app.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.oid IN ('public.identity_admin_verifications_list(text, timestamptz, uuid, integer)'::regprocedure,
                       'public.identity_admin_verification_secret(uuid)'::regprocedure,
                       'public.identity_admin_verification_decide(uuid, boolean, text)'::regprocedure)
         AND p.prosecdef AND p.proowner = 'ptmarket_identity'::regrole
         AND p.proconfig = ARRAY['search_path=pg_catalog, pg_temp']
         AND p.provolatile = CASE WHEN p.proname = 'identity_admin_verification_decide' THEN 'v' ELSE 's' END$q$,
    3, 'as três: DEFINER, dono ptmarket_identity, search_path = pg_catalog, pg_temp (decide VOLATILE)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
       WHERE p.oid IN ('public.identity_admin_verifications_list(text, timestamptz, uuid, integer)'::regprocedure,
                       'public.identity_admin_verification_secret(uuid)'::regprocedure,
                       'public.identity_admin_verification_decide(uuid, boolean, text)'::regprocedure)
         AND a.grantee <> p.proowner
         AND NOT (a.grantee = 'ptmarket_app'::regrole AND a.privilege_type = 'EXECUTE')$q$,
    0, 'proacl: além do dono, só EXECUTE de ptmarket_app (nem PUBLIC)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       CROSS JOIN LATERAL aclexplode(p.proacl) a
       WHERE p.oid IN ('public.identity_admin_verifications_list(text, timestamptz, uuid, integer)'::regprocedure,
                       'public.identity_admin_verification_secret(uuid)'::regprocedure,
                       'public.identity_admin_verification_decide(uuid, boolean, text)'::regprocedure)
         AND a.grantee = 'ptmarket_app'::regrole AND a.privilege_type = 'EXECUTE'$q$,
    3, 'proacl: ptmarket_app executa as três');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_migrator', 'ptmarket_worker', 'ptmarket_price_writer',
                                         'ptmarket_portal']) AS r(rol),
                            unnest(ARRAY['public.identity_admin_verifications_list(text, timestamptz, uuid, integer)',
                                         'public.identity_admin_verification_secret(uuid)',
                                         'public.identity_admin_verification_decide(uuid, boolean, text)']) AS f(fn)
       WHERE has_function_privilege(r.rol, f.fn, 'EXECUTE')$q$,
    0, 'migrator, worker, price_writer e portal não executam nenhuma');

-- ---------------------------------------------------------------------------
-- 7. Grants e policies mínimos de ptmarket_identity.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'store_verifications' AND grantee = 'ptmarket_identity'
         AND ((privilege_type = 'SELECT'
               AND column_name IN ('id', 'tenant_id', 'store_id', 'kind', 'status', 'sha256', 'storage_key',
                                   'access_code_enc', 'created_at', 'reviewed_at', 'delete_after'))
              OR (privilege_type = 'UPDATE'
                  AND column_name IN ('status', 'reviewed_by', 'reviewed_at', 'review_reason', 'delete_after')))$q$,
    16, 'identity: SELECT nas 11 colunas lidas e UPDATE das 5 da decisão em store_verifications');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'store_verifications' AND grantee = 'ptmarket_identity'$q$,
    16, 'identity: mais nenhum privilégio de coluna em store_verifications');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'stores' AND grantee = 'ptmarket_identity'
         AND privilege_type = 'SELECT' AND column_name IN ('id', 'tenant_id', 'name', 'legal_name', 'nif')$q$,
    5, 'identity: SELECT (id, tenant_id, name, legal_name, nif) em stores');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM information_schema.column_privileges
       WHERE table_schema = 'public' AND table_name = 'stores' AND grantee = 'ptmarket_identity'$q$,
    5, 'identity: mais nada em stores (nem iban)');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['store_verifications', 'stores']) AS t(tab),
                            unnest(ARRAY['INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']) AS p(priv)
       WHERE has_table_privilege('ptmarket_identity', t.tab, p.priv)
          OR (p.priv = 'INSERT' AND has_any_column_privilege('ptmarket_identity', t.tab, 'INSERT'))
          OR (t.tab = 'stores' AND has_any_column_privilege('ptmarket_identity', t.tab, 'UPDATE'))$q$,
    0, 'identity: sem INSERT/DELETE/TRUNCATE/REFERENCES/TRIGGER; sem UPDATE em stores');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy p
       WHERE p.polroles = ARRAY['ptmarket_identity'::regrole::oid] AND p.polpermissive
         AND ((p.polrelid = 'public.stores'::regclass AND p.polname = 'identity_lookup' AND p.polcmd = 'r')
           OR (p.polrelid = 'public.store_verifications'::regclass AND p.polname = 'identity_lookup' AND p.polcmd = 'r')
           OR (p.polrelid = 'public.store_verifications'::regclass AND p.polname = 'identity_decide'
               AND p.polcmd = 'w'))$q$,
    3, 'policies: identity_lookup FOR SELECT (stores, store_verifications), identity_decide FOR UPDATE');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_policy p
       WHERE p.polrelid IN ('public.stores'::regclass, 'public.store_verifications'::regclass)
         AND 'ptmarket_identity'::regrole::oid = ANY (p.polroles)$q$,
    3, 'policies: mais nenhuma para ptmarket_identity nestas tabelas');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_namespace
       WHERE nspname = 'public' AND has_schema_privilege('ptmarket_identity', oid, 'CREATE')$q$,
    0, 'ptmarket_identity sem CREATE no schema public');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE pg_has_role('ptmarket_migrator', 'ptmarket_identity', 'USAGE')$q$,
    0, 'migrator sem INHERIT em ptmarket_identity');

-- ---------------------------------------------------------------------------
-- 8. audit_append_db: só os papéis da allowlist; um papel sem o grant continua a falhar; a selagem mantém-no.
-- ---------------------------------------------------------------------------
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM unnest(ARRAY['ptmarket_app', 'ptmarket_worker', 'ptmarket_price_writer',
                                         'ptmarket_portal', 'ptmarket_operator']) AS r(rol)
       WHERE has_function_privilege(r.rol, 'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE')$q$,
    0, 'audit_append_db: app, worker, price_writer, portal e operator sem EXECUTE');
SET ROLE ptmarket_worker;
SELECT pg_temp.expect_error(
    $q$SELECT audit.audit_append_db('x.update', 'x', 'x', NULL, NULL, NULL)$q$,
    '42501', 'papel sem o grant (worker) chama audit_append_db → 42501');
RESET ROLE;
SET ROLE ptmarket_migrator;
SELECT audit_admin.audit_seal();
RESET ROLE;
SELECT pg_temp.expect_value(
    $q$SELECT count(*) FROM pg_proc p
       WHERE p.pronamespace = 'audit'::regnamespace AND has_function_privilege('ptmarket_identity', p.oid, 'EXECUTE')
         AND p.oid NOT IN ('audit.audit_append_db(text,text,text,jsonb,uuid,uuid)'::regprocedure,
                           'audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text, timestamptz, uuid, integer)'::regprocedure)$q$,
    0, 'depois da audit_seal: identity só executa audit_append_db e admin_read_events em audit.*');
SELECT pg_temp.expect_value(
    $q$SELECT count(*) WHERE has_function_privilege('ptmarket_identity',
                                                    'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE')$q$,
    1, 'depois da audit_seal: identity continua com EXECUTE em audit_append_db (allowlist de grants)');

ROLLBACK;
