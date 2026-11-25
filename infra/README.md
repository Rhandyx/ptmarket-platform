# Infra de desenvolvimento

Só desenvolvimento. Postgres 18 (+ pgaudit) + Redis + WORM local (S3 com Object Lock), portas apenas em 127.0.0.1.

- Subir: `docker compose -f infra/docker-compose.dev.yml up -d --wait` (a 1.ª vez constrói a imagem do Postgres)
- Verificar: `infra/scripts/dev-check.sh` (sobe se preciso; termina com `OK: pg18 uuidv7 papéis redis pgaudit worm`).
  `DEV_CHECK_NO_UP=1` verifica sem subir nada (ex.: testar a falha com o `worm` parado).
- Apagar tudo (inclui volumes): `docker compose -f infra/docker-compose.dev.yml down -v`
- Passwords e chaves: ver `infra/.env.example` (omissões de dev; `.env` real nunca versionado)

## Recriar a BD de dev (obrigatório depois de mudar `postgres/init/` ou o Dockerfile)
Os scripts de `postgres/init/` (papéis, pgaudit) só correm com volume novo. Para os aplicar:
`docker compose -f infra/docker-compose.dev.yml down -v && docker compose -f infra/docker-compose.dev.yml up -d --build --wait`
— **apaga os dados de dev** (BD, Redis e WORM local); depois correr as migrations. Os nomes dos volumes
(`pgdata`, `redisdata`, `wormdata`) mantêm-se.

URLs de ligação por papel:
- migrator: `postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket`
- app (API Rust): `postgres://ptmarket_app:dev_app@127.0.0.1:5432/ptmarket`
- worker (Go): `postgres://ptmarket_worker:dev_worker@127.0.0.1:5432/ptmarket`
- redis: `redis://127.0.0.1:6379`
- WORM (S3): `http://127.0.0.1:7070`, bucket `ptmarket-audit-worm`, região `us-east-1`

O superuser `postgres` serve só o init; nenhuma aplicação liga com ele.

## pgaudit (spec 13 §0 L3)
Imagem própria (`postgres/Dockerfile`): `postgres:18.1` + `postgresql-18-pgaudit` com versão fixada.
- Global: `pgaudit.log='ddl,role'` (inclui `ptmarket_app`/`ptmarket_worker`; o resto é a L1, triggers),
  `log_parameter=off` (parâmetros podem ter dados pessoais), `log_catalog=off`, `log_relation=on`.
- `postgres` (superuser): `pgaudit.log='all'`; `ptmarket_migrator`: `'write,ddl,role,misc'` (`init/02-pgaudit.sh`).
- Logs em JSON dentro do contentor: `$PGDATA/log/*.json` (`log_destination=jsonlog` + `logging_collector=on`);
  `docker logs` só mostra o arranque. O envio destes logs para o WORM é do épico de infra/produção.

## WORM local (spec 13 §3.4)
Serviço `worm`: **Versity Gateway** (`versity/versitygw`, versão fixada, Apache-2.0) com backend POSIX e
versionamento. Não é MinIO porque o repositório `minio/minio` está arquivado no GitHub (último push abr/2026) e deixou de ter
imagens mantidas; o Versity Gateway é mantido ativamente e suporta Object Lock (GOVERNANCE/COMPLIANCE).
O serviço `worm-init` (`amazon/aws-cli`, versão fixada) cria o bucket `ptmarket-audit-worm` com Object Lock
e retenção por omissão **COMPLIANCE de 1 dia** (só dev) e fica a correr como cliente S3 do `dev-check.sh`.
Objetos gravados não se apagam nem se encurta a retenção durante 1 dia — nem com a chave root.

Variáveis novas (`.env.example`): `WORM_ENDPOINT`, `WORM_REGION`, `WORM_BUCKET`, `WORM_ACCESS_KEY`,
`WORM_SECRET_KEY`, `WORM_RETENTION_DAYS`.

**Produção:** o WORM é externo (R2 ou S3 Object Lock, decisão do owner) e vive numa conta **diferente** da que
corre a aplicação; as credenciais da app só podem gravar (sem apagar nem alterar retenção/configuração).
