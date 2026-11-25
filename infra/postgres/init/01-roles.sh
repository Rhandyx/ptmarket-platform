#!/bin/bash
# Corre no 1.º arranque. Passwords vêm do ambiente do contentor.
set -euo pipefail
psql -v ON_ERROR_STOP=1 -U postgres -d postgres \
  -v mig="$PTM_MIGRATOR_PASSWORD" -v app="$PTM_APP_PASSWORD" -v wrk="$PTM_WORKER_PASSWORD" <<'SQL'
CREATE ROLE ptmarket_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'app';
CREATE ROLE ptmarket_worker LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'wrk';
CREATE ROLE ptmarket_migrator LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD :'mig';
GRANT ptmarket_app, ptmarket_worker TO ptmarket_migrator WITH INHERIT FALSE, SET TRUE;
ALTER DATABASE ptmarket OWNER TO ptmarket_migrator;
SQL
psql -v ON_ERROR_STOP=1 -U postgres -d ptmarket <<'SQL'
ALTER SCHEMA public OWNER TO ptmarket_migrator;
SQL
