-- Caixa negra L2 (spec 13 §0; cartão 02/04): event triggers de DDL. Corre como SUPERUSER, DEPOIS das migrations
-- (precisa de audit.audit_ddl_end/audit_ddl_drop, criadas pela 0013), em cada BD com as migrations (não em
-- template1). Idempotente: cria o que falta, recria o que aponta para outra função/evento ou tem filtro de tags,
-- e põe ambos em ENABLE ALWAYS (session_replication_role não os salta).
-- PostgreSQL: CREATE EVENT TRIGGER exige superuser (passo 0 da 0013); o migrator (dono da BD) não os cria nem
-- desliga (ALTER/DROP EVENT TRIGGER exigem ser o dono, um superuser). O GUC event_triggers só o superuser muda.
-- Onde corre: migrations/tests/run.sh e infra/scripts/dev-check.sh; em produção é um passo do deploy.
--   dev: docker compose -f infra/docker-compose.dev.yml exec -T postgres psql -U postgres -d ptmarket \
--          -X -q -v ON_ERROR_STOP=1 -f - < infra/postgres/bootstrap/event-triggers.sql
DO $$
DECLARE
    v_end  oid := to_regprocedure('audit.audit_ddl_end()');
    v_drop oid := to_regprocedure('audit.audit_ddl_drop()');
BEGIN
    IF NOT COALESCE((SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user), false) THEN
        RAISE EXCEPTION 'event-triggers.sql: correr como superuser';
    END IF;
    IF v_end IS NULL OR v_drop IS NULL THEN
        RAISE EXCEPTION 'event-triggers.sql: audit.audit_ddl_end()/audit_ddl_drop() em falta nesta BD (aplicar as migrations até à 0013 primeiro)';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger
               WHERE evtname = 'audit_ddl_end'
                 AND (evtevent <> 'ddl_command_end' OR evtfoid <> v_end OR evttags IS NOT NULL)) THEN
        DROP EVENT TRIGGER audit_ddl_end;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtname = 'audit_ddl_end') THEN
        CREATE EVENT TRIGGER audit_ddl_end ON ddl_command_end EXECUTE FUNCTION audit.audit_ddl_end();
    END IF;
    ALTER EVENT TRIGGER audit_ddl_end ENABLE ALWAYS;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger
               WHERE evtname = 'audit_ddl_drop'
                 AND (evtevent <> 'sql_drop' OR evtfoid <> v_drop OR evttags IS NOT NULL)) THEN
        DROP EVENT TRIGGER audit_ddl_drop;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_event_trigger WHERE evtname = 'audit_ddl_drop') THEN
        CREATE EVENT TRIGGER audit_ddl_drop ON sql_drop EXECUTE FUNCTION audit.audit_ddl_drop();
    END IF;
    ALTER EVENT TRIGGER audit_ddl_drop ENABLE ALWAYS;
END
$$;
