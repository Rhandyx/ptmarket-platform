-- 0026 — Timeline global do Super-Admin, v2: achados da auditoria do cartão 02/23a (a 0025 não se reescreve).
-- Rollback mental (só em dev):
--   B. CREATE OR REPLACE de public.identity_admin_read_events com o corpo da 0025 (STABLE, sem s.tenant_id IS NULL),
--      pelo mesmo caminho (INHERIT temporário do migrator em ptmarket_identity).
--   A. (superuser; objetos selados) CREATE OR REPLACE de audit._admin_read_events_sql e audit.admin_read_events com o
--      texto da alteração '0025_admin_read_events' (infra/postgres/init/03-audit-bootstrap.sh);
--      DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0026_admin_read_events_v2';
--   (Os eventos 'admin.audit_timeline.read' e ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   A. Alteração aprovada '0026_admin_read_events_v2' (texto exato no bootstrap; o superuser aplica-o antes desta
--      migration; exige '0025_admin_read_events'). Assinaturas, donos e grants iguais. audit.admin_read_events:
--      * session_user tem de ser ptmarket_app (42501): o SET ROLE não muda o session_user, por isso o migrator
--        (ou outro login com SET em ptmarket_app) não lê pela porta;
--      * sem filtro seletivo (tenant, loja, ator ou encomenda) a janela máxima é 24 h; com um deles, 31 dias (22023);
--      * VOLATILE: grava ela própria o evento 'admin.audit_timeline.read' por audit._chain_insert, na transação de
--        quem chama (ator do contexto; outcome success; changes = filtros, cursor como booleano, linhas devolvidas).
--        A app NÃO volta a gravar este evento no sucesso (cartão 23); as recusas continuam a ser gravadas pela app.
--      chain_ok: também a cauda (sem seq + 1 → só true se seq = audit_chain_heads.last_seq); sondagens limitadas
--      por created_at (poda de partições). O prefixo da cadeia fica para audit_verify_chain + raiz WORM.
--   B. public.identity_admin_read_events: só sessões da plataforma (s.tenant_id IS NULL, com o CHECK de 8 h da
--      0019) e VOLATILE (chama uma função que escreve). Resto igual à 0025.
--      LIÇÃO L2: nada de SET ROLE. CREATE OR REPLACE com INHERIT temporário do migrator em ptmarket_identity e
--      reposição de INHERIT FALSE, SET TRUE (padrão do ponto D da 0021), ANTES do audit_upgrade/audit_seal (com
--      INHERIT a selagem veria o EXECUTE de ptmarket_identity como do migrator). No fim, a guarda B da 0022.

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0026: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
    IF to_regprocedure('public.identity_admin_read_events(timestamptz,timestamptz,uuid,uuid,uuid,uuid,text,text,timestamptz,uuid,integer)') IS NULL THEN
        RAISE EXCEPTION '0026: falta public.identity_admin_read_events (aplicar a 0025 primeiro)';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- B. Porta: só sessões da plataforma; VOLATILE.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_identity TO %I WITH INHERIT TRUE', current_user);
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.identity_admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid,
    p_store_id uuid, p_actor_id uuid, p_order_id uuid, p_action_prefix text, p_outcome text,
    p_cursor_at timestamptz, p_cursor_id uuid, p_limit integer)
RETURNS TABLE (id uuid, created_at timestamptz, tenant_id uuid, store_id uuid, actor_type text, actor_id uuid,
    actor_label text, impersonator_id uuid, action text, target_type text, target_id text, outcome text,
    reason text, changes jsonb, chain_seq bigint, chain_ok boolean)
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
                        AND s.tenant_id IS NULL
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

DO $$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format('GRANT ptmarket_identity TO %I WITH INHERIT FALSE, SET TRUE', current_user);
    END IF;
    IF pg_has_role(current_user, 'ptmarket_identity', 'USAGE')
       AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0026: o migrator ficou com INHERIT em ptmarket_identity';
    END IF;
END
$$;

-- Guarda B da 0022: ptmarket_identity sem memberships além das do migrator (sem INHERIT).
DO $$
DECLARE
    v_oid oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'ptmarket_identity');
    v_me  oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
        RAISE EXCEPTION '0026: ptmarket_identity é membro de outro papel (herdaria os privilégios dele); recusado.';
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
        RAISE EXCEPTION '0026: ptmarket_identity tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- A. Alteração selada.
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_upgrade(
    '0026_admin_read_events_v2'::text,
    '07f1dab0d98663c41e8c457c932dcd3a7be57ccf469fd99c082c1a405a7bdcee'::text);

SELECT audit_admin.audit_seal();
