#!/usr/bin/env bash
# Seed idempotente de geo_dicofre (cartão 03/02): carrega o CSV intermédio code,name (contrato no infra/README.md).
# Uso: infra/scripts/seed-dicofre.sh <ficheiro.csv> <caop_version> [--retire-missing]
# Liga como migrator via DATABASE_URL (passada por quem corre; este script nunca lê .env). Tudo numa transação.
# SEED_DICOFRE_PSQL (opcional): comando psql alternativo, ex. "docker exec -i <ctr> psql -U ptmarket_migrator -d <bd>".
# O CSV segue inline no stdin do psql, dentro de um \copy ... FROM STDIN: nunca é executado como SQL (linhas com
# barra invertida são recusadas aqui) e o caminho nunca é interpolado em SQL.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "uso: $0 <ficheiro.csv> <caop_version> [--retire-missing]" >&2
    exit 2
fi
FILE="$1"
VERSION="$2"
RETIRE=0
if [ "${3:-}" = "--retire-missing" ]; then
    RETIRE=1
elif [ -n "${3:-}" ]; then
    echo "ERRO: opção desconhecida: $3" >&2
    exit 2
fi
[ -f "$FILE" ] || { echo "ERRO: ficheiro não encontrado: $FILE" >&2; exit 2; }
if ! [[ "$VERSION" =~ ^[A-Za-z0-9._-]{1,16}$ ]]; then
    echo "ERRO: caop_version inválida (1-16 de A-Za-z0-9._-): $VERSION" >&2
    exit 2
fi
if grep -q '\\' "$FILE"; then
    echo "ERRO: $FILE contém barra invertida (linha $(grep -n '\\' "$FILE" | head -n1 | cut -d: -f1)); recusado." >&2
    exit 1
fi

if [ -n "${SEED_DICOFRE_PSQL:-}" ]; then
    # shellcheck disable=SC2206
    PSQL=($SEED_DICOFRE_PSQL)
else
    [ -n "${DATABASE_URL:-}" ] || { echo "ERRO: DATABASE_URL em falta (ligação do migrator)." >&2; exit 2; }
    PSQL=(psql "$DATABASE_URL")
fi

{
    cat <<'SQL'
BEGIN;
CREATE TEMP TABLE seed_raw (ln serial, code text, name text) ON COMMIT DROP;
CREATE TEMP TABLE seed_stats (ins int, upd int) ON COMMIT DROP;
\copy seed_raw (code, name) FROM STDIN WITH (FORMAT csv, HEADER true)
SQL
    cat "$FILE"
    # Garante que o último registo termina em newline antes do terminador do COPY.
    [ -z "$(tail -c1 "$FILE")" ] || printf '\n'
    printf '\\.\n'
    cat <<'SQL'
DO $$
DECLARE r record;
BEGIN
    -- linha do ficheiro = ln + 1 (cabeçalho)
    SELECT ln + 1 AS l, code INTO r FROM seed_raw
        WHERE code IS NULL OR code !~ '^[0-9]{2}([0-9]{2}([0-9A-Z]{2})?)?$' ORDER BY ln LIMIT 1;
    IF FOUND THEN RAISE EXCEPTION 'linha %: código inválido (%)', r.l, r.code; END IF;
    SELECT ln + 1 AS l, code INTO r FROM seed_raw
        WHERE name IS NULL OR btrim(name) = '' OR length(btrim(name)) > 160 ORDER BY ln LIMIT 1;
    IF FOUND THEN RAISE EXCEPTION 'linha %: nome vazio ou com mais de 160 caracteres (código %)', r.l, r.code; END IF;
    SELECT s.ln + 1 AS l, s.code INTO r FROM seed_raw s
        WHERE EXISTS (SELECT 1 FROM seed_raw o WHERE o.code = s.code AND o.ln < s.ln) ORDER BY s.ln LIMIT 1;
    IF FOUND THEN RAISE EXCEPTION 'linha %: código duplicado (%)', r.l, r.code; END IF;
    SELECT s.ln + 1 AS l, s.code INTO r FROM seed_raw s
        WHERE length(s.code) > 2
          AND NOT EXISTS (SELECT 1 FROM seed_raw p WHERE p.code = left(s.code, length(s.code) - 2))
          AND NOT EXISTS (SELECT 1 FROM geo_dicofre g WHERE g.code = left(s.code, length(s.code) - 2))
        ORDER BY s.ln LIMIT 1;
    IF FOUND THEN RAISE EXCEPTION 'linha %: pai % ausente (código %)', r.l, left(r.code, length(r.code) - 2), r.code; END IF;
END
$$;
SQL
    for len in 2 4 6; do
        cat <<SQL
WITH up AS (
    INSERT INTO geo_dicofre AS g (code, level, parent_code, name, caop_version)
    SELECT code, CASE $len WHEN 2 THEN 'district' WHEN 4 THEN 'municipality' ELSE 'parish' END,
           CASE WHEN $len = 2 THEN NULL ELSE left(code, $len - 2) END, btrim(name), :'ver'
    FROM seed_raw WHERE length(code) = $len
    ON CONFLICT (code) DO UPDATE
        SET name = EXCLUDED.name, caop_version = EXCLUDED.caop_version, valid_to = NULL, updated_at = now()
        WHERE (g.name, g.caop_version) IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.caop_version) OR g.valid_to IS NOT NULL
    RETURNING (xmax = 0) AS ins)
INSERT INTO seed_stats SELECT count(*) FILTER (WHERE ins), count(*) FILTER (WHERE NOT ins) FROM up;
SQL
    done
    if [ "$RETIRE" -eq 1 ]; then
        cat <<'SQL'
WITH r AS (
    UPDATE geo_dicofre SET valid_to = now(), updated_at = now()
    WHERE valid_to IS NULL AND code NOT IN (SELECT code FROM seed_raw) RETURNING 1)
SELECT format('inseridos=%s atualizados=%s retirados=%s', (SELECT sum(ins) FROM seed_stats),
              (SELECT sum(upd) FROM seed_stats), (SELECT count(*) FROM r));
SQL
    else
        cat <<'SQL'
SELECT format('inseridos=%s atualizados=%s em_falta=%s (sem --retire-missing)', (SELECT sum(ins) FROM seed_stats),
              (SELECT sum(upd) FROM seed_stats),
              (SELECT count(*) FROM geo_dicofre WHERE valid_to IS NULL AND code NOT IN (SELECT code FROM seed_raw)));
SQL
    fi
    echo 'COMMIT;'
} | "${PSQL[@]}" -X -q -At -v ON_ERROR_STOP=1 -v ver="$VERSION" -f -
