# Infra de desenvolvimento

Só desenvolvimento. Postgres 18 + Redis, portas apenas em 127.0.0.1.

- Subir: `docker compose -f infra/docker-compose.dev.yml up -d --wait`
- Verificar: `infra/scripts/dev-check.sh` (sobe se preciso; termina com `OK: ...`)
- Apagar tudo (inclui volumes): `docker compose -f infra/docker-compose.dev.yml down -v`
- Passwords: ver `infra/.env.example` (omissões de dev; `.env` real nunca versionado)

URLs de ligação por papel:
- migrator: `postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket`
- app (API Rust): `postgres://ptmarket_app:dev_app@127.0.0.1:5432/ptmarket`
- worker (Go): `postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket`
- redis: `redis://127.0.0.1:6379`

O superuser `postgres` serve só o init; nenhuma aplicação liga com ele.
