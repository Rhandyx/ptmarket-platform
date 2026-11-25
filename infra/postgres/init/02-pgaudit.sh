#!/bin/bash
# Corre no 1.º arranque (volume novo), como superuser, depois de 01-roles.sh.
# Spec 13 §0 L3: o superuser fica com auditoria total; o migrator com escrita/DDL/papéis/misc;
# ptmarket_app/ptmarket_worker ficam com o valor global 'ddl,role' (o resto é a L1, triggers).
set -euo pipefail
psql -v ON_ERROR_STOP=1 -U postgres -d ptmarket <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgaudit;
ALTER ROLE postgres SET pgaudit.log = 'all';
ALTER ROLE ptmarket_migrator SET pgaudit.log = 'write,ddl,role,misc';
SQL
