#!/usr/bin/env bash
# Prova das migrations: BD PostgreSQL 18 limpa -> sqlx migrate run -> todos os tests/*.sql (ON_ERROR_STOP).
# Sem MIGRATIONS_TEST_URL: levanta um postgres:18 descartável numa porta livre (só 127.0.0.1),
#   corre o psql dentro do contentor e remove-o no fim (trap).
# Com MIGRATIONS_TEST_URL: usa essa BD (tem de estar limpa) e o psql do host.
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

    PORT="$(docker port "$CONTAINER" 5432/tcp | head -n1 | sed 's/.*://')"
    DB_URL="postgres://postgres:${DB_PASS}@127.0.0.1:${PORT}/${DB_NAME}"
    run_psql() {
        docker exec -i "$CONTAINER" psql -U postgres -d "$DB_NAME" -X -q -o /dev/null -v ON_ERROR_STOP=1 -f - <"$1"
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
