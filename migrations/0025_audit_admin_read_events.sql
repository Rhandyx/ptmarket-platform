-- 0025 — Caixa negra: leitura global da timeline para o Super-Admin (cartão 02/23a).
-- Rollback mental (só em dev; o lado audit é do superuser, objetos selados):
--   B. DROP FUNCTION public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
--        timestamptz, uuid, integer);
--      DROP POLICY identity_lookup ON public.user_roles; REVOKE SELECT ON public.user_roles FROM ptmarket_identity;
--   A. (superuser) DROP FUNCTION audit.admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
--        timestamptz, uuid, integer); DROP FUNCTION audit._admin_read_events_sql(boolean, boolean, boolean, boolean,
--        boolean, boolean, boolean); REVOKE USAGE ON SCHEMA audit FROM ptmarket_identity;
--      DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0025_admin_read_events';
--   (Nenhuma tabela nova; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * A REGRA da 0008 mantém-se: nenhuma DEFINER de audit.* lê objetos de papéis com LOGIN (users, user_roles e
--     sessions são do migrator). Por isso a leitura tem duas camadas:
--     A. audit.admin_read_events (alteração aprovada '0025_admin_read_events' em infra/postgres/init/
--        03-audit-bootstrap.sh; texto exato, o superuser aplica o bootstrap antes desta migration; exige
--        '0023_mask_uuid'): DEFINER dono ptmarket_audit_writer, só lê audit.*. Exige app.actor_type = 'admin'
--        (42501), valida os parâmetros (22023), página por (created_at, id) DESC com cursor, chain_ok por linha.
--        EXECUTE só para ptmarket_identity (allowlist de grants da audit_seal).
--     B. public.identity_admin_read_events (aqui): mesma assinatura e retorno; DEFINER dono ptmarket_identity
--        (NOLOGIN, sem acesso de escrita a audit). Porta (42501, mensagem fixa): app.actor_type = 'admin',
--        app.actor_id com super_admin global (tenant e loja NULL), conta ativa com totp_enabled, e a sessão
--        app.session_id (uuid) desse utilizador, de subject_type 'user', com mfa_verified_at, não revogada, não
--        expirada e sem impersonação (nem impersonator_user_id na sessão, nem app.impersonator_id no contexto).
--        Depois chama A. EXECUTE só para ptmarket_app.
--   * app.session_id: a app tem de o pôr no contexto da transação (cartão 23: TenantTx/AuditCtx). Sem ele → 42501.
--   * ptmarket_identity ganha SELECT em user_roles (colunas da porta) e a política identity_lookup (como em users e
--     sessions, 0018/0019). As políticas de user_roles são do migrator, mas correm como ptmarket_identity, que não
--     escreve na caixa negra.
--   * LIÇÃO L2: nada de SET ROLE. O dono muda com ALTER FUNCTION … OWNER TO (o migrator tem SET em
--     ptmarket_identity); CREATE no schema public só durante o ALTER (padrão da 0017).
--   * Guarda B da 0022 repetida para ptmarket_identity (nenhuma membership além das do migrator).

DO $$
DECLARE
    v_oid oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'ptmarket_identity');
    v_me  oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0025: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
    IF v_oid IS NULL THEN
        RAISE EXCEPTION '0025: o papel ptmarket_identity não existe (aplicar a 0017 primeiro); recusado.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
               WHERE oid = v_oid AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
        RAISE EXCEPTION '0025: ptmarket_identity tem SUPERUSER, BYPASSRLS ou LOGIN; recusado.';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
        RAISE EXCEPTION '0025: ptmarket_identity é membro de outro papel (herdaria os privilégios dele); recusado.';
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
        RAISE EXCEPTION '0025: ptmarket_identity tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- B. Porta em public: leitura de user_roles para o dono da DEFINER.
-- ---------------------------------------------------------------------------
GRANT SELECT (user_id, role, tenant_id, store_id) ON public.user_roles TO ptmarket_identity;

CREATE POLICY identity_lookup ON public.user_roles
    AS PERMISSIVE
    FOR SELECT TO ptmarket_identity
    USING (true);

CREATE FUNCTION public.identity_admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid,
    p_store_id uuid, p_actor_id uuid, p_order_id uuid, p_action_prefix text, p_outcome text,
    p_cursor_at timestamptz, p_cursor_id uuid, p_limit integer)
RETURNS TABLE (id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean)
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
    IF current_setting('app.actor_type', true) IS DISTINCT FROM 'admin'
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
                        AND s.mfa_verified_at IS NOT NULL
                        AND s.revoked_at IS NULL
                        AND s.expires_at > now()
                        AND s.impersonator_user_id IS NULL) THEN
        RAISE EXCEPTION 'identity_admin_read_events: acesso recusado' USING ERRCODE = 'insufficient_privilege';
    END IF;

    RETURN QUERY
    SELECT a.id, a.created_at, a.tenant_id, a.store_id, a.actor_type, a.actor_id, a.actor_label, a.impersonator_id,
           a.action, a.target_type, a.target_id, a.outcome, a.reason, a.changes, a.chain_seq, a.chain_ok
    FROM audit.admin_read_events(p_from, p_to, p_tenant_id, p_store_id, p_actor_id, p_order_id, p_action_prefix,
                                 p_outcome, p_cursor_at, p_cursor_id, p_limit) AS a;
END
$body$;

COMMENT ON FUNCTION public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
    timestamptz, uuid, integer) IS
    'Timeline global da caixa negra: só super_admin com TOTP e sessão (app.session_id) com 2FA; página por cursor';

REVOKE ALL ON FUNCTION public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text,
    text, timestamptz, uuid, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text,
    text, timestamptz, uuid, integer) TO ptmarket_app;

-- Dono = ptmarket_identity (depois dos GRANT: quem migra deixa de ter EXECUTE). CREATE no schema só durante o ALTER.
GRANT CREATE ON SCHEMA public TO ptmarket_identity;
ALTER FUNCTION public.identity_admin_read_events(timestamptz, timestamptz, uuid, uuid, uuid, uuid, text, text,
    timestamptz, uuid, integer) OWNER TO ptmarket_identity;
REVOKE CREATE ON SCHEMA public FROM ptmarket_identity;

-- ---------------------------------------------------------------------------
-- A. Alteração selada (cria audit._admin_read_events_sql e audit.admin_read_events, grants e USAGE em audit).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_upgrade(
    '0025_admin_read_events'::text,
    '569e94b39de8206d7741d2d2e962f1b598d087f3ff30d2e4f49c8244f92fa808'::text);

SELECT audit_admin.audit_seal();
