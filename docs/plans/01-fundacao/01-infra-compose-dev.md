# 01 — docker-compose de desenvolvimento: Postgres 18 + Redis (épico: 01-fundacao)

**Agente:** db-architect · **Modelo:** sonnet · **Depende de:** — · **Paralelo com:** 02, 04, 07, 08

## Objetivo
Um comando levanta Postgres 18 e Redis locais, com os três papéis de BD de menor privilégio que os outros cartões usam.

## Pode alterar
- `infra/docker-compose.dev.yml`, `infra/.env.example`, `infra/postgres/init/01-roles.sh`, `infra/scripts/dev-check.sh`, `infra/README.md` (criar)

## Não tocar
- `migrations/`, `backend-rust/`, `workers-go/`, `frontend-web/` — pertencem a outros cartões em paralelo
- Qualquer `.env` real — nunca criar, ler nem imprimir (só `.env.example`)

## Contexto exato (colado da spec; não ler a spec)
```
Compose: projeto `ptmarket-dev`. Portas publicadas SÓ em 127.0.0.1. Imagens fixadas por tag menor (nunca `latest`). Só estes 2 serviços (MinIO/Mailpit entram com o cartão que os usar).
postgres: postgres:18.x · POSTGRES_DB=ptmarket · 127.0.0.1:5432 · healthcheck pg_isready · volume nomeado em /var/lib/postgresql (a imagem 18 mudou: NÃO usar /var/lib/postgresql/data)
redis: 7.x ou 8.x alpine · 127.0.0.1:6379 · `--appendonly yes` (a fila Asynq não se pode perder) · healthcheck `redis-cli ping`
Papéis (01-roles.sh, corre no 1.º arranque; passwords vêm de variáveis de ambiente, nunca escritas em ficheiros versionados):
  ptmarket_migrator  LOGIN CREATEDB CREATEROLE NOSUPERUSER NOBYPASSRLS — dono da BD `ptmarket`; corre migrations; membro de app e worker (consegue SET ROLE)
  ptmarket_app       LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE — API Rust
  ptmarket_worker    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE — publicador do outbox (Go)
Valores de dev por omissão no compose: ${POSTGRES_PASSWORD:-dev_postgres} ${PTM_MIGRATOR_PASSWORD:-dev_migrator} ${PTM_APP_PASSWORD:-dev_app} ${PTM_WORKER_PASSWORD:-dev_worker}; `.env.example` documenta-os e avisa "só desenvolvimento".
ASVS (spec 12 §3): "utilizador de BD da API sem SUPERUSER/BYPASSRLS". O superuser `postgres` serve só o init; nenhuma aplicação liga com ele.
```

## Feito quando
- [ ] `docker compose -f infra/docker-compose.dev.yml up -d --wait` fica saudável a partir de volumes vazios; `down -v` limpa tudo
- [ ] `dev-check.sh` verifica: `server_version_num` ≥ 180000 · `SELECT uuidv7()` funciona · os 3 papéis existem com `rolsuper = false` e `rolbypassrls = false` · `ptmarket_migrator` é dono de `ptmarket` e faz `SET ROLE ptmarket_app` · Redis responde `PONG` · nenhuma porta em 0.0.0.0
- [ ] Caso de erro: `dev-check.sh` sai ≠ 0 com mensagem clara se um papel tiver SUPERUSER/BYPASSRLS ou se o Docker não estiver a correr
- [ ] README ≤ 20 linhas: subir, verificar, apagar, URLs de ligação por papel

## Prova (um comando)
`infra/scripts/dev-check.sh` → esperado: sobe os serviços e termina com `OK: pg18 uuidv7 papéis redis` e código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- —
