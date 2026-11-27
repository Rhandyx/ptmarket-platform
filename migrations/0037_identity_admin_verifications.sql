-- 0037 — Revisão das verificações de loja pelo super_admin (cartão 03/10; spec 14 §6; ASVS L3).
-- Rollback mental (só em dev):
--   DROP FUNCTION public.identity_admin_verifications_list(text, timestamptz, uuid, integer);
--   DROP FUNCTION public.identity_admin_verification_secret(uuid);
--   DROP FUNCTION public.identity_admin_verification_decide(uuid, boolean, text);
--   DROP POLICY identity_lookup ON public.store_verifications; DROP POLICY identity_decide ON public.store_verifications;
--   DROP POLICY identity_lookup ON public.stores;
--   REVOKE ALL ON public.store_verifications, public.stores FROM ptmarket_identity;
--   C. (correções da auditoria; tabela da 0036 vazia em dev) repor o texto da 0036:
--      ALTER TABLE public.store_verifications DROP CONSTRAINT store_verifications_access_code_format,
--        DROP CONSTRAINT store_verifications_code_by_kind, DROP CONSTRAINT store_verifications_deleted_has_no_code,
--        DROP CONSTRAINT store_verifications_file_deleted_after_review, DROP CONSTRAINT store_verifications_delete_within_30d,
--        ADD CONSTRAINT store_verifications_access_code_enc_check CHECK (access_code_enc LIKE 'v1:%'),
--        ADD CONSTRAINT store_verifications_code_only_in_code_kind
--            CHECK ((kind = 'certidao_permanente_code') = (access_code_enc IS NOT NULL)),
--        ADD CONSTRAINT store_verifications_delete_within_30d CHECK (status = 'pending' OR storage_key IS NULL
--            OR (delete_after IS NOT NULL AND delete_after <= reviewed_at + interval '30 days'));
--      CREATE OR REPLACE store_verifications_guard() com o corpo da 0036;
--      ALTER POLICY worker_select / worker_update com o texto da 0036; REVOKE UPDATE (access_code_enc) ON
--      store_verifications FROM ptmarket_worker; DROP INDEX store_verifications_delete_after_idx e recriá-lo com
--      WHERE storage_key IS NOT NULL.
--   (superuser; opcional) tirar o par (audit.audit_append_db, ptmarket_identity) da allowlist de grants da audit_seal
--   em infra/postgres/init/03-audit-bootstrap.sh e reaplicar o bootstrap.
--   (Os eventos store_verifications.update gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * O super_admin trabalha em admin.ptmarket.pt sem tenant nem loja no contexto; a ptmarket_app só vê
--     store_verifications do tenant e da loja do contexto (0036). A leitura e a decisão globais passam por três
--     DEFINER de identidade (padrão da 0025/0026): dono ptmarket_identity, search_path = pg_catalog, pg_temp,
--     relações com public., REVOKE ALL FROM PUBLIC, EXECUTE só para ptmarket_app. Não chamam audit.*.
--   * Porta (42501, mensagem fixa), antes de validar os argumentos: session_user = ptmarket_app (o SET ROLE não o
--     muda); app.actor_type = 'admin'; sem app.impersonator_id; app.actor_id com super_admin global (tenant e loja
--     NULL), conta ativa com totp_enabled; app.session_id = sessão desse utilizador, de subject_type 'user', da
--     plataforma (tenant_id NULL), com mfa_verified_at, não revogada, não expirada e sem impersonação.
--   * identity_admin_verifications_list: p_status NULL ou pending|approved|rejected; 1 ≤ p_limit ≤ 100; cursor
--     (created_at, id) ASC, os dois ou nenhum; nunca OFFSET. Validação = 22023. Nunca devolve storage_key,
--     access_code_enc, iban nem outras colunas da loja (só has_file / has_access_code).
--   * identity_admin_verification_secret: tenant, loja, storage_key, sha256 e access_code_enc da linha (NULL se não
--     houver). A BD nunca decifra (não tem a chave).
--   * identity_admin_verification_decide: só linha pending (senão 0 linhas). status, reviewed_by = app.actor_id,
--     reviewed_at = now(), review_reason (obrigatório na rejeição; ≤ 500; btrim), delete_after = o MESMO now() +
--     30 dias se houver ficheiro ou código (CHECK store_verifications_delete_within_30d). NÃO mexe em stores.kyc_verified.
--     O UPDATE passa pela L1 (INVOKER) como ptmarket_identity → audit.audit_append_db (ator 'db' + session_user):
--     EXECUTE dado pelo bootstrap (allowlist de grants da audit_seal, como ptmarket_bootstrap na 0024). O evento
--     nomeado é gravado pela app (cartão 23).
--   * ptmarket_identity, mínimo: SELECT nas colunas lidas de store_verifications e em stores (id, tenant_id, name,
--     legal_name, nif); UPDATE (status, reviewed_by, reviewed_at, review_reason, delete_after) em
--     store_verifications. Policies: identity_lookup FOR SELECT (true) nas duas; identity_decide FOR UPDATE só de
--     pending para decidido com revisor.
--   * C. Correções da auditoria do cartão 10 sobre a 0036 (imutável: só ALTER/CREATE OR REPLACE aqui):
--     - RGPD art. 5.º/1/e: o código cifrado da Certidão Permanente é apagado como o ficheiro, até 30 dias depois
--       da decisão. "Há segredo" = storage_key OU access_code_enc. delete_within_30d vale para os dois;
--       file_deleted_at marca a eliminação dos dois (deleted_has_no_key + deleted_has_no_code).
--     - code_by_kind (substitui code_only_in_code_kind): fora do tipo código → sem código; tipo código pending →
--       com código (decidida pode já não o ter).
--     - Formato (identity::crypto): 'v1:' + kid (8 hex minúsculos: 4 bytes do sha256 da chave) + ':' +
--       base64 padrão com padding de (nonce 12 B || ciphertext || tag 16 B). Mínimo 28 bytes = 40 caracteres
--       (10 grupos de 4). O LIKE 'v1:%' aceitava texto em claro ('v1:1234-5678').
--     - file_deleted_after_review: file_deleted_at só depois da decisão (sem datas inventadas).
--     - Trigger: access_code_enc só pode passar a NULL e só fora de pending; os outros imutáveis iguais à 0036.
--     - Worker (cartão 25): worker_select/worker_update com "há segredo"; a linha nova tem de ficar sem ficheiro,
--       sem código e com file_deleted_at (senão 42501). UPDATE (access_code_enc) sem SELECT dessa coluna. O
--       índice parcial do job cobre os dois.
--   * LIÇÃO L2: nada de SET ROLE. Dono por ALTER FUNCTION … OWNER TO (o migrator tem SET em ptmarket_identity);
--     CREATE no schema public só durante o ALTER. No fim, a guarda B da 0022.

DO $$
DECLARE
    v_oid oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'ptmarket_identity');
BEGIN
    IF to_regclass('public.store_verifications') IS NULL THEN
        RAISE EXCEPTION '0037: falta public.store_verifications (aplicar a 0036 primeiro)';
    END IF;
    IF v_oid IS NULL THEN
        RAISE EXCEPTION '0037: o papel ptmarket_identity não existe (aplicar a 0017 primeiro); recusado.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
               WHERE oid = v_oid AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION '0037: ptmarket_identity tem SUPERUSER, BYPASSRLS ou LOGIN; recusado.';
    END IF;
    IF NOT has_schema_privilege('ptmarket_identity', 'audit', 'USAGE')
       OR NOT has_function_privilege('ptmarket_identity',
                                     'audit.audit_append_db(text,text,text,jsonb,uuid,uuid)', 'EXECUTE') THEN
        RAISE EXCEPTION '0037: ptmarket_identity sem USAGE em audit/EXECUTE em audit_append_db: reaplicar infra/postgres/init/03-audit-bootstrap.sh (superuser) antes desta migration.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- C. Correções da auditoria sobre store_verifications (0036).
-- ---------------------------------------------------------------------------
ALTER TABLE public.store_verifications
    DROP CONSTRAINT store_verifications_access_code_enc_check,
    DROP CONSTRAINT store_verifications_code_only_in_code_kind,
    DROP CONSTRAINT store_verifications_delete_within_30d,
    -- 'v1:<kid 8 hex>:<base64(nonce 12 B || ct || tag 16 B)>'; ≥ 28 bytes = ≥ 10 grupos de 4 (≥ 40 caracteres).
    ADD CONSTRAINT store_verifications_access_code_format CHECK (
        access_code_enc ~ '^v1:[0-9a-f]{8}:([A-Za-z0-9+/]{4}){9,}([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$'
    ),
    ADD CONSTRAINT store_verifications_code_by_kind CHECK (
        (kind = 'certidao_permanente_code' OR access_code_enc IS NULL)
        AND (kind <> 'certidao_permanente_code' OR status <> 'pending' OR access_code_enc IS NOT NULL)
    ),
    ADD CONSTRAINT store_verifications_delete_within_30d CHECK (
        status = 'pending' OR (storage_key IS NULL AND access_code_enc IS NULL)
        OR (delete_after IS NOT NULL AND delete_after <= reviewed_at + interval '30 days')
    ),
    ADD CONSTRAINT store_verifications_deleted_has_no_code CHECK (file_deleted_at IS NULL OR access_code_enc IS NULL),
    ADD CONSTRAINT store_verifications_file_deleted_after_review CHECK (
        file_deleted_at IS NULL OR (reviewed_at IS NOT NULL AND file_deleted_at >= reviewed_at)
    );

COMMENT ON COLUMN public.store_verifications.access_code_enc IS
    'Código de acesso à Certidão Permanente cifrado pela app (AES-256-GCM, v1:<kid>:<base64>, VERIFICATION_ENC_KEY); '
    'nunca em claro; apagado (NULL) até 30 dias depois da decisão, como o ficheiro';
COMMENT ON COLUMN public.store_verifications.delete_after IS
    'Data-limite de eliminação do ficheiro e do código (<= reviewed_at + 30 dias quando há um deles e decisão)';
COMMENT ON COLUMN public.store_verifications.file_deleted_at IS
    'Quando o job apagou o ficheiro e/ou o código (>= reviewed_at)';

CREATE OR REPLACE FUNCTION public.store_verifications_guard() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
BEGIN
    IF NEW.sha256 IS DISTINCT FROM OLD.sha256
       OR NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.store_id IS DISTINCT FROM OLD.store_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'store_verifications: sha256, kind, store_id, tenant_id e created_at são imutáveis'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.access_code_enc IS DISTINCT FROM OLD.access_code_enc
       AND (NEW.access_code_enc IS NOT NULL OR OLD.status = 'pending') THEN
        RAISE EXCEPTION 'store_verifications: access_code_enc só pode passar a NULL, e só depois da decisão'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       AND NOT (OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected')) THEN
        RAISE EXCEPTION 'store_verifications: transição % → % proibida', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.storage_key IS DISTINCT FROM OLD.storage_key AND NEW.storage_key IS NOT NULL THEN
        RAISE EXCEPTION 'store_verifications: storage_key só pode passar a NULL'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

-- Job de eliminação (cartão 25): "há segredo" = ficheiro ou código. worker_select inclui o estado depois da
-- eliminação (file_deleted_at posto), como na 0036.
ALTER POLICY worker_select ON public.store_verifications
    USING (delete_after <= now()
           AND (storage_key IS NOT NULL OR access_code_enc IS NOT NULL OR file_deleted_at IS NOT NULL));
ALTER POLICY worker_update ON public.store_verifications
    USING ((storage_key IS NOT NULL OR access_code_enc IS NOT NULL) AND delete_after <= now())
    WITH CHECK (storage_key IS NULL AND access_code_enc IS NULL AND file_deleted_at IS NOT NULL);
GRANT UPDATE (access_code_enc) ON public.store_verifications TO ptmarket_worker;

DROP INDEX public.store_verifications_delete_after_idx;
CREATE INDEX store_verifications_delete_after_idx ON public.store_verifications (delete_after)
    WHERE storage_key IS NOT NULL OR access_code_enc IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Grants e policies mínimos para o dono das DEFINER.
-- ---------------------------------------------------------------------------
GRANT SELECT (id, tenant_id, name, legal_name, nif) ON public.stores TO ptmarket_identity;
CREATE POLICY identity_lookup ON public.stores
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

GRANT SELECT (id, tenant_id, store_id, kind, status, sha256, storage_key, access_code_enc, created_at, reviewed_at,
              delete_after)
    ON public.store_verifications TO ptmarket_identity;
GRANT UPDATE (status, reviewed_by, reviewed_at, review_reason, delete_after)
    ON public.store_verifications TO ptmarket_identity;
CREATE POLICY identity_lookup ON public.store_verifications
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);
CREATE POLICY identity_decide ON public.store_verifications
    AS PERMISSIVE
    FOR UPDATE TO ptmarket_identity
    USING (status = 'pending')
    WITH CHECK (status IN ('approved', 'rejected') AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL);

COMMENT ON POLICY identity_lookup ON public.stores IS
    'Leitura para o dono das DEFINER identity_admin_verification_* (0037; só id, tenant_id, name, legal_name, nif)';
COMMENT ON POLICY identity_lookup ON public.store_verifications IS
    'Leitura global para o dono das DEFINER identity_admin_verification_* (0037; a porta está nas funções)';
COMMENT ON POLICY identity_decide ON public.store_verifications IS
    'Decisão pela DEFINER identity_admin_verification_decide (0037): só pending → approved|rejected com revisor';

-- ---------------------------------------------------------------------------
-- Funções (criadas pelo migrator; dono muda no fim).
-- ---------------------------------------------------------------------------
CREATE FUNCTION public.identity_admin_verifications_list(p_status text, p_cursor_at timestamptz, p_cursor_id uuid,
    p_limit integer)
RETURNS TABLE (id uuid, tenant_id uuid, store_id uuid, store_name text, store_legal_name text, store_nif text,
    kind text, status text, has_file boolean, has_access_code boolean, sha256 bytea, created_at timestamptz,
    reviewed_at timestamptz, delete_after timestamptz)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
#variable_conflict use_column
DECLARE
    c_uuid    constant text := '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$';
    v_actor   text := NULLIF(current_setting('app.actor_id', true), '');
    v_session text := NULLIF(current_setting('app.session_id', true), '');
BEGIN
    IF session_user IS DISTINCT FROM 'ptmarket_app'
       OR current_setting('app.actor_type', true) IS DISTINCT FROM 'admin'
       OR NULLIF(current_setting('app.impersonator_id', true), '') IS NOT NULL
       OR v_actor IS NULL OR v_actor !~ c_uuid
       OR v_session IS NULL OR v_session !~ c_uuid
       OR NOT EXISTS (SELECT 1 FROM public.users u
                      WHERE u.id = v_actor::uuid AND u.is_active AND u.totp_enabled)
       OR NOT EXISTS (SELECT 1 FROM public.user_roles r
                      WHERE r.user_id = v_actor::uuid AND r.role = 'super_admin'
                        AND r.tenant_id IS NULL AND r.store_id IS NULL)
       OR NOT EXISTS (SELECT 1 FROM public.sessions s
                      WHERE s.id = v_session::uuid
                        AND s.subject_type = 'user' AND s.subject_id = v_actor::uuid
                        AND s.tenant_id IS NULL
                        AND s.mfa_verified_at IS NOT NULL
                        AND s.revoked_at IS NULL
                        AND s.expires_at > now()
                        AND s.impersonator_user_id IS NULL) THEN
        RAISE EXCEPTION 'identity_admin_verifications_list: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
        RAISE EXCEPTION 'identity_admin_verifications_list: limite fora de 1..100' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_status IS NOT NULL AND p_status NOT IN ('pending', 'approved', 'rejected') THEN
        RAISE EXCEPTION 'identity_admin_verifications_list: estado inválido' USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF (p_cursor_at IS NULL) <> (p_cursor_id IS NULL) THEN
        RAISE EXCEPTION 'identity_admin_verifications_list: cursor incompleto' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT v.id, v.tenant_id, v.store_id, s.name::text, s.legal_name::text, s.nif::text, v.kind::text, v.status::text,
           v.storage_key IS NOT NULL, v.access_code_enc IS NOT NULL, v.sha256, v.created_at, v.reviewed_at,
           v.delete_after
    FROM public.store_verifications v
    JOIN public.stores s ON s.tenant_id = v.tenant_id AND s.id = v.store_id
    WHERE (p_status IS NULL OR v.status = p_status)
      AND (p_cursor_at IS NULL OR (v.created_at, v.id) > (p_cursor_at, p_cursor_id))
    ORDER BY v.created_at, v.id
    LIMIT p_limit;
END
$body$;

CREATE FUNCTION public.identity_admin_verification_secret(p_id uuid)
RETURNS TABLE (tenant_id uuid, store_id uuid, storage_key text, sha256 bytea, access_code_enc text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
#variable_conflict use_column
DECLARE
    c_uuid    constant text := '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$';
    v_actor   text := NULLIF(current_setting('app.actor_id', true), '');
    v_session text := NULLIF(current_setting('app.session_id', true), '');
BEGIN
    IF session_user IS DISTINCT FROM 'ptmarket_app'
       OR current_setting('app.actor_type', true) IS DISTINCT FROM 'admin'
       OR NULLIF(current_setting('app.impersonator_id', true), '') IS NOT NULL
       OR v_actor IS NULL OR v_actor !~ c_uuid
       OR v_session IS NULL OR v_session !~ c_uuid
       OR NOT EXISTS (SELECT 1 FROM public.users u
                      WHERE u.id = v_actor::uuid AND u.is_active AND u.totp_enabled)
       OR NOT EXISTS (SELECT 1 FROM public.user_roles r
                      WHERE r.user_id = v_actor::uuid AND r.role = 'super_admin'
                        AND r.tenant_id IS NULL AND r.store_id IS NULL)
       OR NOT EXISTS (SELECT 1 FROM public.sessions s
                      WHERE s.id = v_session::uuid
                        AND s.subject_type = 'user' AND s.subject_id = v_actor::uuid
                        AND s.tenant_id IS NULL
                        AND s.mfa_verified_at IS NOT NULL
                        AND s.revoked_at IS NULL
                        AND s.expires_at > now()
                        AND s.impersonator_user_id IS NULL) THEN
        RAISE EXCEPTION 'identity_admin_verification_secret: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_id IS NULL THEN
        RAISE EXCEPTION 'identity_admin_verification_secret: id em falta' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT v.tenant_id, v.store_id, v.storage_key, v.sha256, v.access_code_enc
    FROM public.store_verifications v
    WHERE v.id = p_id;
END
$body$;

CREATE FUNCTION public.identity_admin_verification_decide(p_id uuid, p_approve boolean, p_reason text)
RETURNS TABLE (tenant_id uuid, store_id uuid, status text, delete_after timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $body$
#variable_conflict use_column
DECLARE
    c_uuid    constant text := '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$';
    v_actor   text := NULLIF(current_setting('app.actor_id', true), '');
    v_session text := NULLIF(current_setting('app.session_id', true), '');
    v_reason  text := NULLIF(btrim(p_reason), '');
    v_now     timestamptz := now(); -- o mesmo instante em reviewed_at e delete_after (CHECK dos 30 dias)
BEGIN
    IF session_user IS DISTINCT FROM 'ptmarket_app'
       OR current_setting('app.actor_type', true) IS DISTINCT FROM 'admin'
       OR NULLIF(current_setting('app.impersonator_id', true), '') IS NOT NULL
       OR v_actor IS NULL OR v_actor !~ c_uuid
       OR v_session IS NULL OR v_session !~ c_uuid
       OR NOT EXISTS (SELECT 1 FROM public.users u
                      WHERE u.id = v_actor::uuid AND u.is_active AND u.totp_enabled)
       OR NOT EXISTS (SELECT 1 FROM public.user_roles r
                      WHERE r.user_id = v_actor::uuid AND r.role = 'super_admin'
                        AND r.tenant_id IS NULL AND r.store_id IS NULL)
       OR NOT EXISTS (SELECT 1 FROM public.sessions s
                      WHERE s.id = v_session::uuid
                        AND s.subject_type = 'user' AND s.subject_id = v_actor::uuid
                        AND s.tenant_id IS NULL
                        AND s.mfa_verified_at IS NOT NULL
                        AND s.revoked_at IS NULL
                        AND s.expires_at > now()
                        AND s.impersonator_user_id IS NULL) THEN
        RAISE EXCEPTION 'identity_admin_verification_decide: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_id IS NULL OR p_approve IS NULL THEN
        RAISE EXCEPTION 'identity_admin_verification_decide: id ou decisão em falta'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF NOT p_approve AND v_reason IS NULL THEN
        RAISE EXCEPTION 'identity_admin_verification_decide: a rejeição exige motivo'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF char_length(v_reason) > 500 THEN
        RAISE EXCEPTION 'identity_admin_verification_decide: motivo acima de 500 caracteres'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    WITH u AS (
        UPDATE public.store_verifications v
        SET status        = CASE WHEN p_approve THEN 'approved' ELSE 'rejected' END,
            reviewed_by   = v_actor::uuid,
            reviewed_at   = v_now,
            review_reason = v_reason,
            delete_after  = CASE WHEN v.storage_key IS NOT NULL OR v.access_code_enc IS NOT NULL
                                 THEN v_now + interval '30 days' END
        WHERE v.id = p_id AND v.status = 'pending'
        RETURNING v.tenant_id, v.store_id, v.status, v.delete_after
    )
    SELECT u.tenant_id, u.store_id, u.status::text, u.delete_after FROM u;
END
$body$;

COMMENT ON FUNCTION public.identity_admin_verifications_list(text, timestamptz, uuid, integer) IS
    'Verificações de loja para o super_admin (TOTP + sessão de plataforma com 2FA): cursor (created_at, id) ASC; sem '
    'storage_key nem código';
COMMENT ON FUNCTION public.identity_admin_verification_secret(uuid) IS
    'Chave do ficheiro e código cifrado de uma verificação, só para o super_admin com 2FA; a BD nunca decifra';
COMMENT ON FUNCTION public.identity_admin_verification_decide(uuid, boolean, text) IS
    'Decisão do super_admin com 2FA sobre uma verificação pending (0 linhas se já decidida); ficheiro a apagar em '
    '30 dias; não mexe em stores.kyc_verified';

REVOKE ALL ON FUNCTION public.identity_admin_verifications_list(text, timestamptz, uuid, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.identity_admin_verification_secret(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.identity_admin_verification_decide(uuid, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.identity_admin_verifications_list(text, timestamptz, uuid, integer) TO ptmarket_app;
GRANT EXECUTE ON FUNCTION public.identity_admin_verification_secret(uuid) TO ptmarket_app;
GRANT EXECUTE ON FUNCTION public.identity_admin_verification_decide(uuid, boolean, text) TO ptmarket_app;

-- Dono = ptmarket_identity (depois dos GRANT: quem migra deixa de ter EXECUTE). CREATE no schema só durante o ALTER.
GRANT CREATE ON SCHEMA public TO ptmarket_identity;
ALTER FUNCTION public.identity_admin_verifications_list(text, timestamptz, uuid, integer) OWNER TO ptmarket_identity;
ALTER FUNCTION public.identity_admin_verification_secret(uuid) OWNER TO ptmarket_identity;
ALTER FUNCTION public.identity_admin_verification_decide(uuid, boolean, text) OWNER TO ptmarket_identity;
REVOKE CREATE ON SCHEMA public FROM ptmarket_identity;

-- Guarda B da 0022: ptmarket_identity sem memberships além das do migrator (sem INHERIT).
DO $$
DECLARE
    v_oid oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'ptmarket_identity');
    v_me  oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
        RAISE EXCEPTION '0037: ptmarket_identity é membro de outro papel (herdaria os privilégios dele); recusado.';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members m
        LEFT JOIN pg_catalog.pg_roles g ON g.oid = m.grantor
        WHERE m.roleid = v_oid
          AND NOT (m.member = v_me
                   AND NOT m.inherit_option
                   AND ((m.admin_option AND COALESCE(g.rolsuper, false))
                        OR (m.set_option AND NOT m.admin_option)))
    ) THEN
        RAISE EXCEPTION '0037: ptmarket_identity tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.';
    END IF;
END
$$;
