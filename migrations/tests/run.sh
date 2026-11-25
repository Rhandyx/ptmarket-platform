#!/usr/bin/env bash
# Prova das migrations: BD PostgreSQL 18 limpa -> sqlx migrate run -> todos os tests/*.sql (ON_ERROR_STOP).
# Migrations e testes correm SEMPRE como papel não superuser (equivalente ao ptmarket_migrator de dev:
#   LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS, dono da BD e do schema public).
# Sem MIGRATIONS_TEST_URL: levanta um postgres:18 descartável numa porta livre (só 127.0.0.1); o superuser
#   do contentor só cria o ptmarket_migrator; psql corre dentro do contentor; removido no fim (trap).
# Com MIGRATIONS_TEST_URL: usa essa BD (tem de estar limpa, utilizador não superuser) e o psql do host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MIG_DIR="$ROOT/migrations"

SQLX="$(command -v sqlx || true)"
[ -n "$SQLX" ] || SQLX="$HOME/.cargo/bin/sqlx"
if [ ! -x "$SQLX" ]; then
    echo "ERRO: sqlx-cli não encontrado (PATH ou ~/.cargo/bin/sqlx)." >&2
    exit 1
fi

CONTAINER=""
cleanup() {
    if [ -n "$CONTAINER" ]; then
        docker rm -f -v "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

if [ -n "${MIGRATIONS_TEST_URL:-}" ]; then
    DB_URL="$MIGRATIONS_TEST_URL"
    if ! command -v psql >/dev/null 2>&1; then
        echo "ERRO: com MIGRATIONS_TEST_URL é preciso psql no PATH." >&2
        exit 1
    fi
    run_psql() { psql "$DB_URL" -X -q -o /dev/null -v ON_ERROR_STOP=1 -f - <"$1"; }
    if [ "$(psql "$DB_URL" -X -At -c "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")" != f ]; then
        echo "ERRO: MIGRATIONS_TEST_URL tem de usar um papel sem SUPERUSER/BYPASSRLS." >&2
        exit 1
    fi
else
    CONTAINER="ptm-migtest-$$-$RANDOM"
    DB_NAME="ptm_migtest"
    DB_PASS="$(openssl rand -hex 16)"
    docker run -d --name "$CONTAINER" \
        -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_DB="$DB_NAME" \
        -p 127.0.0.1::5432 postgres:18 >/dev/null

    ready=0
    for _ in $(seq 1 60); do
        if docker exec "$CONTAINER" pg_isready -q -h 127.0.0.1 -U postgres -d "$DB_NAME"; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" -ne 1 ]; then
        echo "ERRO: postgres:18 descartável não ficou pronto." >&2
        docker logs "$CONTAINER" >&2 || true
        exit 1
    fi

    # Único passo como superuser: criar o migrator (como infra/postgres/init/01-roles.sh, sem app/worker:
    # esses criam-se em 0001 pelo próprio migrator, NOLOGIN).
    MIG_PASS="$(openssl rand -hex 16)"
    docker exec -i "$CONTAINER" psql -U postgres -d "$DB_NAME" -X -q -o /dev/null -v ON_ERROR_STOP=1 \
        -v mig="$MIG_PASS" -v db="$DB_NAME" -f - <<'SQL'
CREATE ROLE ptmarket_migrator LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS PASSWORD :'mig';
ALTER DATABASE :"db" OWNER TO ptmarket_migrator;
ALTER SCHEMA public OWNER TO ptmarket_migrator;
SQL

    PORT="$(docker port "$CONTAINER" 5432/tcp | head -n1 | sed 's/.*://')"
    DB_URL="postgres://ptmarket_migrator:${MIG_PASS}@127.0.0.1:${PORT}/${DB_NAME}"
    run_psql() {
        docker exec -i "$CONTAINER" psql -U ptmarket_migrator -d "$DB_NAME" -X -q -o /dev/null -v ON_ERROR_STOP=1 -f - <"$1"
    }
fi

echo "== sqlx migrate run --source migrations"
"$SQLX" migrate run --source "$MIG_DIR" --database-url "$DB_URL"

shopt -s nullglob
tests=("$MIG_DIR"/tests/*.sql)
if [ "${#tests[@]}" -eq 0 ]; then
    echo "ERRO: nenhum teste em migrations/tests/*.sql" >&2
    exit 1
fi

for t in "${tests[@]}"; do
    echo "== $(basename "$t")"
    run_psql "$t"
done

echo "TODOS OS TESTES PASSARAM"
