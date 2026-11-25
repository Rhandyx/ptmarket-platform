#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
DC=(docker compose -f docker-compose.dev.yml)
fail() { echo "ERRO: $*" >&2; exit 1; }
docker info >/dev/null 2>&1 || fail "Docker não está a correr"
"${DC[@]}" up -d --wait >/dev/null || fail "os serviços não ficaram saudáveis"
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
[ "$("${DC[@]}" exec -T redis redis-cli ping | tr -d '\r')" = PONG ] || fail "Redis não responde PONG"
if "${DC[@]}" ps --format '{{.Publishers}}' | grep -q '0\.0\.0\.0'; then fail "porta publicada em 0.0.0.0"; fi
echo "OK: pg18 uuidv7 papéis redis"
