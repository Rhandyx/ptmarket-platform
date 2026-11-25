-- 0011 — Caixa negra: db_user (session_user) em cada evento, dentro do hash, e verificação do ator vs. LOGIN.
-- Rollback mental (só em dev, como superuser — objetos selados; em produção exportar e verificar a cadeia antes):
--   DROP FUNCTION audit.audit_verify_actors(uuid, text, timestamptz, timestamptz);
--   DROP FUNCTION audit._db_user_since_us();
--   CREATE OR REPLACE de audit._event_hash / audit._chain_insert / audit.audit_append com os corpos da 0008;
--   ALTER TABLE audit.audit_events DROP COLUMN db_user;  (parte a verificação dos eventos gravados depois da 0011)
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0011_db_user';
--
-- Porquê: o migrator tem SET em ptmarket_app/_worker/_price_writer (GRANT/OWNER da 0001/0007, testes) e, com
-- SET ROLE + app.actor_type, grava eventos que parecem da app. O session_user não muda com SET ROLE nem dentro de
-- DEFINER (só o superuser o muda): cada evento passa a gravá-lo (db_user, dentro do hash) e
-- audit_verify_actors assinala o ator incoerente com o papel LOGIN. A escrita não é recusada (fora de âmbito:
-- os testes de dev/CI ligam como migrator e fazem SET ROLE ptmarket_app; esses eventos SÃO assinalados).
--
-- Objetos selados (audit_events, _event_hash, _chain_insert, audit_append) só mudam pela alteração aprovada
-- '0011_db_user' em infra/postgres/init/03-audit-bootstrap.sh (texto exato; o superuser aplica o bootstrap antes
-- desta migration). Aqui só se dispara por nome + sha256: se o texto aprovado mudar, esta migration falha.
-- A mesma alteração faz audit_append recusar app.actor_type fora da lista fechada (incluindo 'db', PTA01).

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0011: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0011_db_user'::text,
    'def87fba170d6261f7f44697b915fc0dabc5bf3337e0578fadaf1e4950629e50'::text);

-- ---------------------------------------------------------------------------
-- audit_verify_actors: eventos da cadeia (chain_key, classe) com created_at em [p_from, p_to) cujo ator não bate
-- com o papel LOGIN que os gravou. Uma linha por problema; zero linhas = coerente. Nunca devolve changes nem
-- dados pessoais.
--   'actor_db_user_mismatch' — customer/merchant/municipal/admin/api_key/anonymous/system gravado por um LOGIN
--       que não é ptmarket_app nem ptmarket_worker (o worker grava os eventos do Redis Stream por
--       audit_append_event, com o ator do pedido; os jobs 'system' correm na app ou no worker).
--   'db_label_mismatch'      — 'db' cujo actor_label não é o db_user (audit_append_db grava session_user) nem
--       termina em '/' || db_user.
--   'db_user_missing'        — db_user NULL num evento criado depois da aplicação de 0011_db_user
--       (audit._db_user_since_us(), fixada pela alteração aprovada).
-- Eventos anteriores à 0011 (db_user NULL) não são avaliados.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_verify_actors(p_chain_key uuid, p_class text, p_from timestamptz, p_to timestamptz)
RETURNS TABLE (event_id uuid, chain_seq bigint, actor_type text, db_user text, problem text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_since_us bigint := audit._db_user_since_us();
BEGIN
    IF p_chain_key IS NULL OR p_from IS NULL OR p_to IS NULL OR p_from >= p_to THEN
        RAISE EXCEPTION 'audit_verify_actors: parâmetros obrigatórios e p_from < p_to'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    IF p_class IS NULL OR p_class NOT IN ('fiscal', 'standard', 'security') THEN
        RAISE EXCEPTION 'audit_verify_actors: classe inválida' USING ERRCODE = 'invalid_parameter_value';
    END IF;

    RETURN QUERY
    SELECT e.id, e.chain_seq, e.actor_type::text, e.db_user, q.problem
    FROM audit.audit_events e
    CROSS JOIN LATERAL (VALUES
        (1, 'db_user_missing'::text,
            e.db_user IS NULL AND (extract(epoch FROM e.created_at) * 1000000)::bigint >= v_since_us),
        (2, 'actor_db_user_mismatch'::text,
            e.db_user IS NOT NULL
            AND e.actor_type IN ('customer', 'merchant', 'municipal', 'admin', 'api_key', 'anonymous', 'system')
            AND e.db_user NOT IN ('ptmarket_app', 'ptmarket_worker')),
        (3, 'db_label_mismatch'::text,
            e.db_user IS NOT NULL AND e.actor_type = 'db'
            AND e.actor_label IS DISTINCT FROM e.db_user
            AND COALESCE(right(e.actor_label, char_length(e.db_user) + 1) <> '/' || e.db_user, true))
    ) AS q(ord, problem, flagged)
    WHERE e.chain_key = p_chain_key
      AND e.retention_class = p_class
      AND e.created_at >= p_from
      AND e.created_at < p_to
      AND q.flagged
    ORDER BY e.chain_seq, q.ord;
END
$$;

REVOKE ALL ON FUNCTION audit.audit_verify_actors(uuid, text, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_verify_actors(uuid, text, timestamptz, timestamptz) TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- Selagem (última instrução): audit_verify_actors está na allowlist do bootstrap (dono ptmarket_audit_writer).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
