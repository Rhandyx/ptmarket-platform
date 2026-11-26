#!/usr/bin/env bash
# Verifica a infra de dev. DEV_CHECK_NO_UP=1 não sobe nada (útil para testar falhas, ex.: worm parado).
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f docker-compose.dev.yml)
fail() { echo "ERRO: $*" >&2; exit 1; }
docker info >/dev/null 2>&1 || fail "Docker não está a correr"
if [ "${DEV_CHECK_NO_UP:-0}" != 1 ]; then
  "${DC[@]}" up -d --wait >/dev/null 2>&1 || fail "os serviços não ficaram saudáveis (ver: docker compose -f infra/docker-compose.dev.yml ps -a / logs)"
fi
q() { "${DC[@]}" exec -T postgres psql -U postgres -d ptmarket -At -c "$1"; }
[ "$(q "SHOW server_version_num")" -ge 180000 ] || fail "Postgres < 18"
q "SELECT uuidv7()" >/dev/null || fail "uuidv7() indisponível"
for r in ptmarket_migrator ptmarket_app ptmarket_worker; do
  row=$(q "SELECT rolsuper||','||rolbypassrls FROM pg_roles WHERE rolname='$r'")
  [ -n "$row" ] || fail "papel $r não existe"
  [ "$row" = "false,false" ] || fail "papel $r tem SUPERUSER/BYPASSRLS ($row)"
done
[ "$(q "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='ptmarket'")" = ptmarket_migrator ] \
  || fail "ptmarket_migrator não é dono da BD ptmarket"
"${DC[@]}" exec -T postgres psql -U ptmarket_migrator -d ptmarket -At \
  -c "SET ROLE ptmarket_app" -c "SET ROLE ptmarket_worker" >/dev/null || fail "migrator não consegue SET ROLE"
# Caixa negra (init/03-audit-bootstrap.sh): papéis NOLOGIN sem membros, schemas em ptmarket e template1.
for r in ptmarket_audit_owner ptmarket_audit_writer ptmarket_audit_retention ptmarket_price_writer; do
  row=$(q "SELECT rolcanlogin||','||rolsuper||','||rolbypassrls||','||rolcreaterole FROM pg_roles WHERE rolname='$r'")
  [ "$row" = "false,false,false,false" ] || fail "papel $r em falta ou com LOGIN/SUPERUSER/BYPASSRLS/CREATEROLE ($row) — volume antigo? ver README: down -v"
done
[ "$(q "SELECT count(*) FROM pg_auth_members WHERE roleid IN ('ptmarket_audit_owner'::regrole, 'ptmarket_audit_writer'::regrole, 'ptmarket_audit_retention'::regrole)")" = 0 ] \
  || fail "há membros dos papéis de auditoria (ninguém pode ser)"
for db in ptmarket template1; do
  [ "$("${DC[@]}" exec -T postgres psql -U postgres -d "$db" -At -c \
      "SELECT pg_get_userbyid(n.nspowner)||','||pg_get_userbyid(p.proowner)||','||p.prosecdef
       FROM pg_namespace n, pg_proc p WHERE n.nspname='audit' AND p.oid=to_regprocedure('audit_admin.audit_seal()')")" \
      = "ptmarket_audit_owner,postgres,true" ] || fail "bootstrap da caixa negra em falta na BD $db (schema audit / audit_seal)"
done
if "${DC[@]}" exec -T postgres psql -U ptmarket_migrator -d ptmarket -At -c "SET ROLE ptmarket_audit_writer" >/dev/null 2>&1; then
  fail "migrator consegue SET ROLE ptmarket_audit_writer (devia ser recusado)"
fi
[ "$("${DC[@]}" exec -T redis redis-cli ping | tr -d '\r')" = PONG ] || fail "Redis não responde PONG"

# Caixa negra L2 (0013): event triggers de DDL, só o superuser os cria; aplicados DEPOIS das migrations
# (idempotente). Sem a 0013 aplicada, avisa e segue (BD nova antes do sqlx migrate run).
if [ "$(q "SELECT to_regprocedure('audit.audit_ddl_end()') IS NOT NULL AND to_regprocedure('audit.audit_ddl_drop()') IS NOT NULL")" = t ]; then
  "${DC[@]}" exec -T postgres psql -U postgres -d ptmarket -X -q -v ON_ERROR_STOP=1 -f - \
    < postgres/bootstrap/event-triggers.sql >/dev/null || fail "postgres/bootstrap/event-triggers.sql falhou"
  [ "$(q "SELECT count(*) FROM pg_event_trigger WHERE evtenabled = 'A' AND evttags IS NULL
          AND ((evtname = 'audit_ddl_end' AND evtevent = 'ddl_command_end' AND evtfoid = 'audit.audit_ddl_end()'::regprocedure)
            OR (evtname = 'audit_ddl_drop' AND evtevent = 'sql_drop' AND evtfoid = 'audit.audit_ddl_drop()'::regprocedure))")" = 2 ] \
    || fail "event triggers da L2 (audit_ddl_end/audit_ddl_drop) em falta ou sem ENABLE ALWAYS"
  [ "$(q "SHOW event_triggers")" = on ] || fail "event_triggers=off (a L2 não dispara)"
else
  echo "AVISO: migrations até à 0013 por aplicar: L2 (event triggers de DDL) inativa; correr sqlx migrate run e repetir" >&2
fi

# pgaudit (spec 13 §0 L3)
q "SHOW shared_preload_libraries" | grep -qw pgaudit || fail "pgaudit não está em shared_preload_libraries"
[ "$(q "SELECT count(*) FROM pg_extension WHERE extname='pgaudit'")" = 1 ] \
  || fail "extensão pgaudit não criada na BD ptmarket (volume antigo? ver README: down -v)"
[ "$(q "SELECT array_to_string(rolconfig, ';') FROM pg_roles WHERE rolname='postgres'")" = "pgaudit.log=all" ] \
  || fail "postgres sem pgaudit.log='all' (rolconfig)"
[ "$(q "SELECT array_to_string(rolconfig, ';') FROM pg_roles WHERE rolname='ptmarket_migrator'")" = "pgaudit.log=write,ddl,role,misc" ] \
  || fail "ptmarket_migrator sem pgaudit.log='write,ddl,role,misc' (rolconfig)"
logf=$(q "SELECT pg_current_logfile('jsonlog')")
[ -n "$logf" ] || fail "Postgres sem log jsonlog (logging_collector/log_destination)"
off=$(q "SELECT (pg_stat_file('$logf')).size")
q "CREATE TABLE _pgaudit_probe(); DROP TABLE _pgaudit_probe;" >/dev/null || fail "probe DDL falhou"
found=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  n=$(q "SELECT count(*) FROM regexp_split_to_table(pg_read_file('$logf', $off, 10485760), E'\\n') l
         WHERE l LIKE '%\"user\":\"postgres\"%' AND l LIKE '%AUDIT: SESSION,%,DDL,' || 'CREATE TABLE,TABLE,public._pgaudit_probe,%'")
  [ "$n" -ge 1 ] && { found=1; break; }
  sleep 0.5
done
[ "$found" = 1 ] || fail "linha AUDIT: do probe não encontrada no log jsonlog do Postgres"

# WORM (Object Lock COMPLIANCE): grava, e apagar a versão / encurtar a retenção tem de ser RECUSADO
worm_out=$("${DC[@]}" exec -T worm-init sh -c '
  B="$WORM_BUCKET"; K="dev-check/$(date +%s)-$$.txt"
  aws s3api head-bucket --bucket "$B" >/dev/null 2>&1 || { echo "UNREACHABLE"; exit 0; }
  [ "$(aws s3api get-object-lock-configuration --bucket "$B" --query ObjectLockConfiguration.Rule.DefaultRetention.Mode --output text)" = COMPLIANCE ] \
    || { echo "NOLOCK"; exit 0; }
  echo prova > /tmp/p
  V=$(aws s3api put-object --bucket "$B" --key "$K" --body /tmp/p --query VersionId --output text) || { echo "PUTFAIL"; exit 0; }
  [ -n "$V" ] && [ "$V" != None ] || { echo "NOVERSION"; exit 0; }
  if aws s3api delete-object --bucket "$B" --key "$K" --version-id "$V" --bypass-governance-retention >/dev/null 2>&1; then
    echo "DELETED"; exit 0; fi
  soon=$(date -u -d "@$(( $(date +%s) + 60 ))" +%Y-%m-%dT%H:%M:%SZ)
  if aws s3api put-object-retention --bucket "$B" --key "$K" --version-id "$V" --bypass-governance-retention \
       --retention "{\"Mode\":\"COMPLIANCE\",\"RetainUntilDate\":\"$soon\"}" >/dev/null 2>&1; then
    echo "SHORTENED"; exit 0; fi
  aws s3api head-object --bucket "$B" --key "$K" --version-id "$V" >/dev/null 2>&1 || { echo "GONE"; exit 0; }
  echo "WORM_OK"' 2>&1 | tr -d '\r' | tail -n1) || true
case "$worm_out" in
  WORM_OK) ;;
  UNREACHABLE) fail "WORM inacessível (serviço worm parado ou bucket em falta)" ;;
  NOLOCK) fail "WORM: bucket sem Object Lock COMPLIANCE por omissão" ;;
  DELETED) fail "WORM: apagar a versão protegida foi ACEITE (devia ser recusado)" ;;
  SHORTENED) fail "WORM: encurtar a retenção foi ACEITE (devia ser recusado)" ;;
  *) fail "WORM: prova falhou ($worm_out)" ;;
esac

if "${DC[@]}" ps --format '{{.Publishers}}' | grep -q '0\.0\.0\.0'; then fail "porta publicada em 0.0.0.0"; fi
echo "OK: pg18 uuidv7 papéis redis L2 pgaudit worm"
