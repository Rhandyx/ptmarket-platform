#!/usr/bin/env bash
# Prova do seed DICOFRE (cartão 03/02): postgres:18 descartável + migrations + seed-dicofre.sh; removido no fim.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SEED="$ROOT/infra/scripts/seed-dicofre.sh"
FIX="$ROOT/infra/scripts/tests/fixtures"
SQLX="$(command -v sqlx || true)"; [ -n "$SQLX" ] || SQLX="$HOME/.cargo/bin/sqlx"
[ -x "$SQLX" ] || { echo "ERRO: sqlx-cli não encontrado." >&2; exit 1; }

CONTAINER="ptm-seedtest-$$-$RANDOM"
TMP="$(mktemp -d)"
cleanup() { docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

DB=ptm_seedtest; MIG_PASS="$(openssl rand -hex 16)"
docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" -e POSTGRES_DB="$DB" \
    -p 127.0.0.1::5432 postgres:18 >/dev/null
ready=0
for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 -U postgres -d "$DB" && { ready=1; break; }
    sleep 1
done
[ "$ready" -eq 1 ] || { echo "ERRO: postgres não ficou pronto." >&2; exit 1; }
docker exec -i "$CONTAINER" psql -U postgres -d "$DB" -X -q -o /dev/null -v ON_ERROR_STOP=1 -v mig="$MIG_PASS" -v db="$DB" -f - <<'SQL'
CREATE ROLE ptmarket_migrator LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD :'mig';
ALTER DATABASE :"db" OWNER TO ptmarket_migrator;
ALTER SCHEMA public OWNER TO ptmarket_migrator;
SQL
docker exec -i "$CONTAINER" bash -s <"$ROOT/infra/postgres/init/03-audit-bootstrap.sh" >/dev/null
PORT="$(docker port "$CONTAINER" 5432/tcp | head -n1 | sed 's/.*://')"
"$SQLX" migrate run --source "$ROOT/migrations" --database-url "postgres://ptmarket_migrator:${MIG_PASS}@127.0.0.1:${PORT}/${DB}" >/dev/null
docker exec -i "$CONTAINER" psql -U postgres -d "$DB" -X -q -o /dev/null -v ON_ERROR_STOP=1 \
    -f - <"$ROOT/infra/postgres/bootstrap/event-triggers.sql"

export SEED_DICOFRE_PSQL="docker exec -i $CONTAINER psql -U ptmarket_migrator -d $DB"
q() { docker exec -i "$CONTAINER" psql -U ptmarket_migrator -d "$DB" -X -q -At -c "$1"; }
fail() { echo "FALHOU: $1" >&2; exit 1; }
expect() { [ "$2" = "$3" ] || fail "$1: obtido '$2', esperado '$3'"; echo "OK  $1"; }
state() { q "SELECT md5(string_agg(g::text, '|' ORDER BY code)) FROM geo_dicofre g"; }

# 1. v1 carrega; 2.ª corrida igual
out="$("$SEED" "$FIX/dicofre_v1.csv" T1)"
expect "v1 inserido" "$out" "inseridos=10 atualizados=0 em_falta=0 (sem --retire-missing)"
expect "freguesia alfanumérica" "$(q "SELECT parent_code||level FROM geo_dicofre WHERE code='9902FA'")" "9902parish"
s1="$(state)"
out="$("$SEED" "$FIX/dicofre_v1.csv" T1)"
expect "v1 2.ª corrida" "$out" "inseridos=0 atualizados=0 em_falta=0 (sem --retire-missing)"
expect "v1 estado igual" "$(state)" "$s1"

# 2. v2 com --retire-missing
out="$("$SEED" "$FIX/dicofre_v2.csv" T2 --retire-missing)"
expect "v2 contagens" "$out" "inseridos=1 atualizados=9 retirados=1"
expect "extinta com valid_to e versão antiga" \
    "$(q "SELECT (valid_to IS NOT NULL)||caop_version FROM geo_dicofre WHERE code='990202'")" "trueT1"
expect "nome mudado com versão nova" "$(q "SELECT name||caop_version FROM geo_dicofre WHERE code='990101'")" \
    "Freguesia Ficticia A1a (nome novo)T2"
expect "nova em vigor" "$(q "SELECT (valid_to IS NULL)||caop_version FROM geo_dicofre WHERE code='990103'")" "trueT2"
# 3. código retirado que volta
out="$("$SEED" "$FIX/dicofre_v1.csv" T3)"
expect "regresso: contagens" "$out" "inseridos=0 atualizados=10 em_falta=1 (sem --retire-missing)"
expect "regresso: valid_to NULL" "$(q "SELECT (valid_to IS NULL)||caop_version FROM geo_dicofre WHERE code='990202'")" "trueT3"

# 4. erros: tabela igual
s2="$(state)"
printf 'code,name\n03,X\n0399,Y\n03AB,Z\n' >"$TMP/bad_code.csv"
printf 'code,name\n03,X\n0301,Y\n0301,Z\n' >"$TMP/dup.csv"
printf 'code,name\n03,X\n0401,Y\n' >"$TMP/orphan.csv"
printf 'code,name\n03,X\n0301,\n' >"$TMP/noname.csv"
printf 'code,name\n03,X\n\\.\nDROP TABLE geo_dicofre;\n' >"$TMP/inject.csv"
for c in "bad_code:linha 4" "dup:linha 4" "orphan:linha 3" "noname:linha 3" "inject:barra invertida"; do
    f="${c%%:*}"; want="${c#*:}"
    if err="$("$SEED" "$TMP/$f.csv" T9 --retire-missing 2>&1)"; then fail "$f devia falhar"; fi
    case "$err" in *"$want"*) ;; *) fail "$f: mensagem sem '$want': $err" ;; esac
    expect "$f aborta, tabela igual" "$(state)" "$s2"
done

# 5. CSV oficial real da CAOP 2025 (supervisor): 3596 linhas
real="$ROOT/infra/data/geo/dicofre_caop2025.csv"
out="$("$SEED" "$real" CAOP2025 --retire-missing)"
case "$out" in inseridos=3596\ *) echo "OK  CAOP2025 inseridos=3596" ;; *) fail "CAOP2025: $out" ;; esac
out="$("$SEED" "$real" CAOP2025)"
expect "CAOP2025 2.ª corrida" "$out" "inseridos=0 atualizados=0 em_falta=0 (sem --retire-missing)"
expect "0302FA pai 0302" "$(q "SELECT parent_code FROM geo_dicofre WHERE code='0302FA' AND caop_version='CAOP2025'")" "0302"

cleanup; trap - EXIT
docker ps -a --format '{{.Names}}' | grep -q "$CONTAINER" && fail "contentor não removido"
echo "OK  contentor removido"
echo "OK: seed-dicofre"
