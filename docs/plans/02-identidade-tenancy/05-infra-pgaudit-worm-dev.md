# 05 — L3: `pgaudit` no Postgres de dev + armazenamento WORM local (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** — · **Paralelo com:** 01, 15

## Objetivo
O Postgres de dev arranca com `pgaudit` (sessões de superuser e manutenção ficam nos logs) e existe um bucket S3 local com Object Lock para os cartões Go da raiz diária.

## Pode alterar
- `infra/postgres/Dockerfile`, `infra/postgres/init/02-pgaudit.sh` (criar); `infra/docker-compose.dev.yml`, `infra/.env.example`, `infra/scripts/dev-check.sh`, `infra/README.md` (editar)

## Não tocar
- `infra/postgres/init/01-roles.sh` — aprovado (papéis); `migrations/`, `backend-rust/`, `workers-go/`, `frontend-web/`; nunca ler nem imprimir `infra/.env` (só `.env.example`)

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §0 L3: pgaudit (logs do Postgres, enviados para WORM): sessões de superuser e manutenção, que podem passar ao lado dos triggers. §3.2: fora da app, o pgaudit guarda o SQL completo.
Spec 13 §3.4: raiz diária publicada em armazenamento WORM externo (R2/S3 Object Lock). §1: ações de superadmin vão para WORM quase em tempo real.
Postgres: imagem própria FROM postgres:18.1 + pacote postgresql-18-pgaudit (repositório PGDG já vem na imagem oficial; fixar a versão do pacote). Sem outras extensões.
  Arranque: shared_preload_libraries=pgaudit · pgaudit.log='ddl,role' (toda a gente) · pgaudit.log_catalog=off · pgaudit.log_parameter=off (parâmetros podem ter dados pessoais) · pgaudit.log_relation=on · log_destination=jsonlog + logging_collector=on · log_connections/log_disconnections=on.
  init/02-pgaudit.sh (superuser, 1.º arranque): CREATE EXTENSION pgaudit na BD ptmarket; ALTER ROLE postgres SET pgaudit.log='all'; ALTER ROLE ptmarket_migrator SET pgaudit.log='write,ddl,role,misc'. ptmarket_app/ptmarket_worker ficam só com 'ddl,role' (o resto é a L1).
  Os scripts de init só correm com volume novo: documentar no README `docker compose -f infra/docker-compose.dev.yml down -v` (apaga os dados de dev) e manter o nome do volume.
WORM local: serviço S3 compatível COM Object Lock, só em 127.0.0.1, imagem com versão fixada (MinIO; se a imagem já não for mantida, outro S3 compatível com Object Lock — justificar no README). Um passo de init cria o bucket `ptmarket-audit-worm` com Object Lock ligado e retenção por omissão COMPLIANCE de 1 dia (só dev).
  .env.example (nomes, sem valores reais): WORM_ENDPOINT, WORM_REGION, WORM_BUCKET, WORM_ACCESS_KEY, WORM_SECRET_KEY, WORM_RETENTION_DAYS.
Fora deste cartão (épico infra/produção): envio dos logs do pgaudit para o WORM e escolha do fornecedor real (decisão do owner: R2 vs S3).
Regras: portas só em 127.0.0.1; nenhum papel da aplicação passa a SUPERUSER/BYPASSRLS; passwords só por variáveis de ambiente.
```

## Feito quando
- [ ] `dev-check.sh` verifica: `SHOW shared_preload_libraries` contém `pgaudit`; extensão criada na BD `ptmarket`; `rolconfig` de `postgres` e `ptmarket_migrator` com o `pgaudit.log` acima
- [ ] `dev-check.sh` executa como superuser `CREATE TABLE _pgaudit_probe(); DROP TABLE _pgaudit_probe;` e encontra a linha `AUDIT:` correspondente no log do contentor
- [ ] `dev-check.sh` verifica o WORM: grava um objeto de prova no bucket e a tentativa de o apagar (versão incluída) ou de encurtar a retenção é RECUSADA
- [ ] `dev-check.sh` continua a falhar se alguma porta estiver em `0.0.0.0` e se algum papel tiver SUPERUSER/BYPASSRLS; caso de erro testado (parar o serviço WORM → o script sai ≠ 0 com mensagem clara)
- [ ] README: como recriar o volume, variáveis novas, e a nota de que em produção o WORM é externo à conta que corre a aplicação

## Prova (um comando)
`infra/scripts/dev-check.sh` → esperado: `OK: pg18 uuidv7 papéis redis pgaudit worm`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Migrations na BD de dev recriada — `sqlx migrate run --source migrations` + `migrations/tests/run.sh`
- Backend e worker contra a BD nova — `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api` · `cd workers-go && go test ./...`
