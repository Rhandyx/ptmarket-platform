-- 0012 — Caixa negra: endurecimento (achados médios/baixos da auditoria ASVS; cartão 02/03c).
-- Rollback mental (só em dev, como superuser — objetos selados; em produção exportar e verificar a cadeia antes):
--   DROP FUNCTION audit.audit_guc_defaults();
--   CREATE OR REPLACE de audit.audit_redact (corpo da 0010), audit._chain_insert (corpo da 0011_db_user),
--   audit.audit_append_event e audit.audit_verify_chain (corpos da 0009);
--   DROP FUNCTION audit._event_content_hash(audit.audit_events); DROP FUNCTION audit._redact_walk(text, jsonb, text);
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0012_hardening';
--   (os eventos gravados ficam; a fórmula do hash não muda.)
--
-- PASSO 0 (provado em postgres:18.7, 25/11/2026; repetido em migrations/tests/audit_hardening.sql):
--   pg_settings NÃO expõe GUCs personalizados (app.actor_type) — nem com ALTER DATABASE/ROLE … SET, nem com
--   SET/set_config na sessão: SELECT … FROM pg_settings WHERE name LIKE 'app.%' devolve 0 linhas. Logo não dá
--   para saber, dentro de audit_append, se app.actor_type veio da transação ou de um default da BD/papel.
--   Caminho escolhido ("Não"): audit.audit_guc_defaults() (abaixo) lista os defaults app.% de
--   pg_db_role_setting; o verify do cartão 09 alerta se devolver linhas.
--
-- O resto é a alteração aprovada '0012_hardening' em infra/postgres/init/03-audit-bootstrap.sh (texto exato; o
-- superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256:
--   - máscara recursiva (audit_redact → audit._redact_walk), aplicada por _chain_insert a todos os caminhos;
--   - dedupe: id repetido com o mesmo conteúdo → NULL; com conteúdo diferente → PTA03 (nada gravado);
--   - audit_append_event: erros de conversão só com a chave e o SQLSTATE; lock_timeout 2s na escrita;
--   - audit_verify_chain: + 'bad_genesis', 'gap_before', 'head_mismatch' (mesma assinatura; hash igual).

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0012: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0012_hardening'::text,
    '23503d703c8adfa47cc309442078840d90b095fa88b1221caeed469d021ded95'::text);

-- ---------------------------------------------------------------------------
-- audit_guc_defaults: defaults de app.* postos fora da transação (ALTER DATABASE/ROLE … SET). Um default de
-- app.actor_type satisfaz o PTA01 em todas as sessões sem que a app escolha o ator. Uma linha por default
-- (setdatabase 0 = todas as BDs; setrole 0 = todos os papéis; setting = 'nome=valor'). Zero linhas = limpo.
-- DEFINER (allowlist do bootstrap), EXECUTE só para ptmarket_worker.
-- ---------------------------------------------------------------------------
CREATE FUNCTION audit.audit_guc_defaults()
RETURNS TABLE (setdatabase oid, setrole oid, setting text)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.setdatabase, s.setrole, c.setting
    FROM pg_catalog.pg_db_role_setting s
    CROSS JOIN LATERAL unnest(s.setconfig) AS c(setting)
    WHERE lower(c.setting) LIKE 'app.%'
    ORDER BY s.setdatabase, s.setrole, c.setting;
$$;

REVOKE ALL ON FUNCTION audit.audit_guc_defaults() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.audit_guc_defaults() TO ptmarket_worker;

-- ---------------------------------------------------------------------------
-- Selagem (última instrução): audit_guc_defaults está na allowlist do bootstrap (dono ptmarket_audit_writer).
-- ---------------------------------------------------------------------------
SELECT audit_admin.audit_seal();
