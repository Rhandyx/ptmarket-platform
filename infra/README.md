# Infra de desenvolvimento

Só desenvolvimento. Postgres 18 (+ pgaudit) + Redis + WORM local (S3 com Object Lock), portas apenas em 127.0.0.1.

- Subir: `docker compose -f infra/docker-compose.dev.yml up -d --wait` (a 1.ª vez constrói a imagem do Postgres)
- Verificar: `infra/scripts/dev-check.sh` (sobe se preciso; termina com `OK: pg18 uuidv7 papéis redis pgaudit worm`).
  `DEV_CHECK_NO_UP=1` verifica sem subir nada (ex.: testar a falha com o `worm` parado).
- Apagar tudo (inclui volumes): `docker compose -f infra/docker-compose.dev.yml down -v`
- Passwords e chaves: ver `infra/.env.example` (omissões de dev; `.env` real nunca versionado)

## Recriar a BD de dev (obrigatório depois de mudar `postgres/init/` ou o Dockerfile)
Os scripts de `postgres/init/` (papéis, pgaudit, caixa negra) só correm com volume novo. Para os aplicar:
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

## Caixa negra: bootstrap e selagem (spec 13; `init/03-audit-bootstrap.sh`)
Corre como superuser no 1.º arranque, em `template1` (as BDs do `sqlx::test` herdam) e em `ptmarket`;
o `migrations/tests/run.sh` corre o mesmo ficheiro no seu postgres descartável. É idempotente.
- Papéis `ptmarket_audit_owner`, `ptmarket_audit_writer` e `ptmarket_audit_retention`: NOLOGIN, sem
  SUPERUSER/BYPASSRLS/CREATEROLE, **sem membros** (nem o migrator, nem com ADMIN). Cria também
  `ptmarket_price_writer` (e app/worker, se faltarem) e dá ao migrator SET neles (sem INHERIT nem ADMIN), para
  as migrations seguirem sempre pelo ramo "já existe" (sem 23505 com `sqlx::test` em paralelo).
- Schema `audit` (dono `ptmarket_audit_owner`): o migrator tem USAGE + CREATE (cria objetos novos nas
  migrations; o CREATE não lhe dá poder sobre objetos selados, que não são dele).
  Schema `audit_admin` (dono `postgres`): `audit_seal()`, SECURITY DEFINER, EXECUTE só para o migrator.
- **Cada migration que cria ou altera objetos em `audit` termina com `SELECT audit_admin.audit_seal();`**:
  recusa funções SECURITY DEFINER fora da allowlist e sobrecargas; passa todos os objetos para
  `ptmarket_audit_owner`/`_writer`; tira ao migrator e a PUBLIC todos os privilégios em `audit.*` (ficam os
  GRANTs explícitos da migration); verifica donos, search_path das DEFINER, membros e dependências de objetos
  de papéis com LOGIN. Se falhar, a migration é desfeita.
- **Nova função SECURITY DEFINER em `audit` (duas pessoas):** o autor da migration pede; quem revê edita a
  ALLOWLIST (`v_allow_sig` + `v_allow_owner`, assinatura como `regprocedure` com `search_path=pg_catalog`, ex.:
  `audit.audit_day_root(date)`; a função tem de ter `SET search_path = pg_catalog, pg_temp`) em `init/03-audit-bootstrap.sh` e aplica-o como superuser no cluster existente,
  antes da migration:
  `docker compose -f infra/docker-compose.dev.yml exec -T -e PTM_BOOTSTRAP_DBS='template1 ptmarket' postgres bash -s < infra/postgres/init/03-audit-bootstrap.sh`
  (em produção, o mesmo ficheiro com `psql -U postgres` e a lista de BDs certa). É idempotente: papéis
  `IF NOT EXISTS`, GRANTs repetíveis, `CREATE OR REPLACE` da `audit_seal`. O pgaudit regista as duas coisas.
- `audit_seal()` e `audit_upgrade()` correm com `search_path = pg_catalog, pg_temp` e catálogos qualificados
  (`pg_catalog.pg_proc`, …): sem o `pg_temp` na lista, o PostgreSQL pesquisa-o **primeiro** para relações e
  tipos, e quem migra (`CREATE TEMP TABLE pg_proc …`) fazia a selagem ler catálogos falsos. Pela mesma razão a
  selagem recusa DEFINER de `audit.*` cujo `search_path` fixo não termine em `pg_temp`.
- **Alterar um objeto selado** (`ALTER TABLE audit.audit_events`, `CREATE OR REPLACE` de `_chain_insert`, …;
  duas pessoas): o migrator não é dono de nada em `audit.*`, por isso só o `audit_admin.audit_upgrade(nome,
  sha256)` (dono `postgres`, EXECUTE só do migrator) o faz, e só com SQL aprovado.
  1. O autor da migration escreve o SQL (nomes qualificados, tipos exatos) e pede a aprovação.
  2. Quem revê cola-o no bootstrap como uma nova entrada `INSERT INTO pg_temp.ptm_sealed_changes_new … $chg_<n>$
     … $chg_<n>$` (ver `0011_db_user`) e reaplica o bootstrap como superuser no cluster existente (comando acima).
     O sha256 é calculado na BD: `SELECT sha256 FROM audit_admin.sealed_changes WHERE name = '<nome>'` (como
     superuser) ou `sha256` do texto entre os dois `$chg_<n>$`, em UTF-8.
  3. Só depois a migration: `SELECT audit_admin.audit_upgrade('<nome>'::text, '<sha256>'::text);` e, no fim,
     `SELECT audit_admin.audit_seal();`. Nome inexistente, sha256 diferente ou já aplicada nesta BD → erro e a
     migration é desfeita. O sqlx fixa o checksum da migration e o superuser fixa o texto: os dois têm de bater.
  `audit_upgrade` sela antes e depois do `EXECUTE` (os objetos criados nascem com dono `postgres` e a selagem
  passa-os para owner/writer) e grava em `audit_admin.sealed_changes_applied`. Mudar o texto de uma alteração
  já aplicada numa BD faz o bootstrap falhar (corrigir = nova alteração com outro nome). As tabelas
  `audit_admin.sealed_changes*` são do `postgres`, sem GRANT a ninguém.
  Na BD de dev (depois de mudar o bootstrap): reaplicar o bootstrap (comando acima) e só então
  `sqlx migrate run --source migrations --database-url <URL do migrator>`.
- **`db_user` (0011):** o migrator tem SET em `ptmarket_app`/`_worker`/`_price_writer` (precisa dele para os
  GRANT/OWNER e para os testes) e, com `SET ROLE` + `app.actor_type`, gravava eventos iguais aos da app. O
  `session_user` não muda com `SET ROLE` nem dentro de uma DEFINER (só o superuser o muda), por isso
  `_chain_insert` grava-o em `audit_events.db_user`, dentro do hash (linhas antigas, NULL, mantêm a fórmula
  antiga). `audit.audit_verify_actors(chain_key, classe, de, até)` (worker) assinala `actor_db_user_mismatch`
  (ator de pessoa/`system` gravado por um LOGIN que não é `ptmarket_app` nem `ptmarket_worker`),
  `db_label_mismatch` e `db_user_missing`. Em dev/CI os testes ligam como migrator e fazem `SET ROLE
  ptmarket_app`: esses eventos SÃO assinalados (o verify corre só na BD real). `audit_append` recusa
  `app.actor_type = 'db'` e qualquer valor fora da lista (PTA01): `'db'` só nasce em `audit_append_db`.
- **Endurecimento (0012, alteração aprovada `0012_hardening`):**
  - Máscara recursiva em **todos** os caminhos (`_chain_insert` aplica `audit_redact` a app, worker e db;
    idempotente): segredos (`password|secret|token|credential|passkey|split_key|api_?key|private|otp|totp|cvv|cvc|
    pan|authorization|_enc$|_hash$`) → `"[redacted]"`; PII em qualquer tabela (`email|phone|telefone|nif|nipc|
    vat_number|name$|full_name|first_name|last_name|address|morada|street|postal|zip|birth|ip$`) → `"[pii]"`;
    IBAN → 4 últimos. Em claro: chaves `*_id` e `name`/`legal_name` de `tenants`, `categories` e `products` ao
    nível das colunas (raiz de `changes` ou `changes.before/after`; aninhado volta a ser PII). O valor inteiro de
    uma chave mascarada é substituído (ex.: `address: {...}` → `"[pii]"`).
  - Dedupe do worker: id repetido com o mesmo conteúdo (`audit._event_content_hash`: campos do produtor, sem
    `chain_seq/prev_hash/hash/created_at`) → `false`; com conteúdo diferente (incluindo `occurred_at`) →
    **SQLSTATE `PTA03`** e nada gravado (o worker trata-o como veneno + alerta).
  - `audit_append_event`: erros de conversão → PTA02 com a chave e o SQLSTATE, nunca o valor; `lock_timeout` 2s
    durante a escrita (no corpo, reposto no fim).
  - `audit_verify_chain` (mesma assinatura) assinala também `bad_genesis` (seq 1 sem `prev_hash` a zeros),
    `gap_before` (a 1.ª linha da janela não continua a última anterior à janela, se existir) e `head_mismatch`
    (com `p_to > now()`: última linha da cadeia ≠ `audit_chain_heads`).
  - Defaults de `app.*` fora da transação (`ALTER DATABASE/ROLE … SET app.actor_type`) satisfazem o PTA01 em
    todas as sessões. O `pg_settings` não mostra GUCs personalizados (passo 0, provado no PG 18), por isso a BD
    não os recusa na escrita: `audit.audit_guc_defaults()` (worker) lista-os de `pg_db_role_setting`; o verify
    do cartão 09 alerta se devolver linhas.
- Chamadas entre funções de `audit.*` passam argumentos com o tipo exato da assinatura (ex.: `::text`), para
  que uma sobrecarga plantada com o CREATE nunca ganhe a resolução.
- Regra: nenhuma função SECURITY DEFINER de `audit.*` lê ou escreve objetos cujo dono tenha LOGIN (o dono
  poderia pôr lá triggers que correm como `ptmarket_audit_writer`). Os alertas de admin/impersonação ficam
  em `audit.audit_alerts` (o worker só marca `published_at`), não no outbox.
- Risco residual: o superuser pode tudo (mitigação: `pgaudit.log='all'` no `postgres` e raiz diária em WORM,
  cartão 09). O dono da BD pode fazer `DROP DATABASE`: **em produção a BD tem dono `postgres` e o migrator não
  tem CREATEDB** (o CREATEDB do migrator só existe em dev/CI, para o `sqlx::test`). Com o CREATE no schema
  `audit`, o migrator pode plantar uma sobrecarga com argumentos DEFAULT que torna ambígua uma chamada interna
  (erro "is not unique" → as escritas da caixa negra falham, fechado; não forja nada). Fica no pgaudit (DDL) e a
  `audit_seal()` seguinte recusa-a. O resto fica no pgaudit.

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
