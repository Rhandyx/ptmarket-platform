-- 0001 — Papéis da aplicação (ptmarket_app = API, ptmarket_worker = outbox).
-- Rollback mental: REVOKE USAGE ON SCHEMA public FROM ptmarket_app, ptmarket_worker;
--   DROP ROLE ptmarket_worker; DROP ROLE ptmarket_app;
--   (só depois de 0002..0006 revertidas; os papéis podem ser partilhados por outras BDs do cluster.)
-- Papéis NOLOGIN, sem password, nunca SUPERUSER/BYPASSRLS. Quem corre a migration
-- tem de conseguir SET ROLE para ambos (superuser já consegue; senão concede-se SET sem INHERIT).

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['ptmarket_app', 'ptmarket_worker'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                r
            );
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname = r AND (rolsuper OR rolbypassrls)
        ) THEN
            RAISE EXCEPTION 'O papel % já existe com SUPERUSER ou BYPASSRLS; recusado.', r;
        END IF;

        IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
           AND NOT pg_has_role(current_user, r, 'SET') THEN
            EXECUTE format('GRANT %I TO %I WITH INHERIT FALSE, SET TRUE', r, current_user);
        END IF;
    END LOOP;
END
$$;

GRANT USAGE ON SCHEMA public TO ptmarket_app, ptmarket_worker;
