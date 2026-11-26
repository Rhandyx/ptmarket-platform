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
  **Cadeia linear:** cada entrada indica a anterior (`INSERT … (name, requires, sql)`; `requires` NULL só na
  primeira): `0011_db_user` → `0012_hardening` → `0013_ddl_owner_exec` → `0014_mask_limits` →
  `0015_critical_timeline` → `0020_mask_v2` → `0023_mask_uuid` → `0025_admin_read_events` (timeline global do
  Super-Admin: `public.identity_admin_read_events`, dono `ptmarket_identity`, faz a porta e chama a selada) →
  `0026_admin_read_events_v2` (só com `session_user` = `ptmarket_app`, grava `admin.audit_timeline.read` na cadeia,
  24 h sem filtro seletivo, `chain_ok` com a cauda). O bootstrap recusa
  `requires` que não seja uma alteração aprovada ou uma cadeia com ramos; `audit_upgrade` recusa uma alteração cuja
  anterior não esteja em `sealed_changes_applied` nesta BD ("<nome> exige <anterior> aplicada antes").
  `audit_upgrade` sela antes e depois do `EXECUTE` (os objetos criados nascem com dono `postgres` e a selagem
  passa-os para owner/writer) e grava em `audit_admin.sealed_changes_applied`.
  `audit_seal`/`audit_upgrade` serializam-se com o advisory lock `hashtextextended('ptmarket:audit_seal', 0)`.
  A chave é pública: qualquer sessão pode segurá-lo (`pg_advisory_lock`) e **atrasar migrations** (DoS). Não forja
  nem altera nada e fica no pgaudit, por isso a chave não deriva de um segredo (decisão do cartão 03d). Mudar o texto de uma alteração
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
- **L2: event triggers de DDL (0013, cartão 02/04):** `audit.audit_ddl_end()` (ddl_command_end) e
  `audit.audit_ddl_drop()` (sql_drop), INVOKER e seladas. Cada comando gera um evento `ddl.<tag>` (ou
  `ddl.drop_<tipo>`) na cadeia da plataforma, com `changes = {query_sha256 (do texto já mascarado, inteiro), query (mascarado:
  literal a seguir a PASSWORD/SECRET → '[redacted]'; cortado a 4096), truncated}`. Uma tabela nova em `public`
  (fora de `audit_events`/`outbox_events`, não partição) recebe sozinha `zz_audit_row` + `zz_audit_truncate`
  (ALWAYS): **as migrations novas não criam esses triggers à mão**. Qualquer papel não superuser (o migrator
  incluído) que desligue, troque, renomeie ou apague um `zz_audit_*` recebe `PTA04` (e o comando é desfeito).
  - `CREATE EVENT TRIGGER` exige superuser: os event triggers vivem em `postgres/bootstrap/event-triggers.sql`
    (idempotente), corrido **depois das migrations** pelo `migrations/tests/run.sh` e pelo `scripts/dev-check.sh`;
    em produção é um passo do deploy. Na BD de dev, depois de aplicar a 0013:
    `docker compose -f infra/docker-compose.dev.yml exec -T postgres psql -U postgres -d ptmarket -X -q -v ON_ERROR_STOP=1 -f - < infra/postgres/bootstrap/event-triggers.sql`
  - Alteração aprovada `0013_ddl_owner_exec`: EXECUTE em `audit_append_db` para `ptmarket_audit_owner`
    (`audit_ensure_partitions` corre como ele; cada partição criada fica em `ddl.create_table`).
  - Limites do PostgreSQL: objetos globais (CREATE/ALTER/DROP ROLE, GRANT de pertença) não disparam event
    triggers: só a L3 (pgaudit) os vê. Num GRANT/REVOKE o evento fica sem `target_id` (o alvo está em
    `changes.query`). As BDs do `sqlx::test` (criadas de `template1`, sem as funções) não têm L2: a prova da L2 é o
    `run.sh`. O superuser pode desligar a L2 (`event_triggers = off`, `ALTER EVENT TRIGGER … DISABLE`): fica no
    pgaudit (`pgaudit.log='all'` no `postgres`).
  - Volume: cada `audit_seal()` (fim de cada migration que mexe em `audit`) grava dezenas de `ddl.grant`/`ddl.revoke`
    (um por objeto de `audit.*`), na cadeia da plataforma. `ALTER TABLE … DETACH PARTITION` de uma tabela de
    `public` com L1 apaga os `zz_audit_*` clonados e é recusado (`PTA04`); hoje não há tabelas particionadas em `public`.
- **Máscara e limites (0014, alteração aprovada `0014_mask_limits`, cartão 02/03d):**
  - Chaves comparadas em minúsculas e sem acentos (`audit._redact_key`). Segredos (`"[redacted]"`) passam a
    incluir `senha|palavra-passe|segredo|chave|pwd|passw|access_key|api-key|jwt|bearer|cookie|session|signature|
    hmac|pin$|card_number|cartao|passport|passaporte`; `pan` só como token (`(^|[_-])pan($|[_-])`: `card_pan`
    mascarado, `company_id`/`expand_id`/`japan` em claro). PII (`"[pii]"`) inclui `nome|apelido|telemovel|
    contribuinte|nascimento|morada`. **Os segredos correm antes da exceção `*_id`** (`reset_token_id`,
    `secret_id`, `api_key_id` → `"[redacted]"`); a exceção `*_id` só vale para a PII.
  - Pares genéricos `{key|name|field, value}`: se a etiqueta for segredo/IBAN/PII, o `value` é mascarado.
  - Por valor (`audit._redact_text`), em todas as strings (também sob chaves neutras e em arrays) e em `reason` e
    `actor_label` (`target_id` não, é um id): e-mail → `"[pii]"`; JWT (`eyJ…` com três segmentos, ou três
    segmentos base64url ≥ 16) e prefixos `sk_`, `pk_live_`, `rk_`, `ghp_`, `xoxb-`/`xoxp-`, `AKIA…` →
    `"[redacted]"`; IBAN (ISO compacto ou em grupos de 4; `PT50` + 21 dígitos) → `****` + 4 últimos, no lugar.
  - `_redact_walk(text, jsonb, text)` mantém a assinatura e chama `audit._redact_node(…, profundidade)`:
    contentores abaixo da profundidade 16 → `"[depth]"`. A máscara é idempotente.
  - Limites em `_chain_insert`, medidos antes da máscara: `octet_length(changes::text)` ≤ 65536, profundidade de
    `changes` ≤ 16, `reason` ≤ 1024, `target_id` ≤ 256, `actor_label` ≤ 128 caracteres.
    **Eventos da aplicação** (`audit_append` chamado diretamente, `audit_append_event` do worker) → `PTA02` com
    mensagem fixa (nunca o valor) e nada gravado. **A auditoria nunca faz falhar uma escrita de negócio nem uma
    migration:** com ator `db`, dentro de um trigger (L1, `pg_trigger_depth() > 0`) ou de um event trigger de DDL
    (L2, pela pilha de chamadas) corta e marca: `target_id` → 180 caracteres + `…sha256:<hex>`; `reason`/
    `actor_label` → cortados com `…[truncated]`; folhas string > 4096 → `{"truncated": true, "bytes": n,
    "sha256": hex}` e, se ainda passar de 64 KiB, o `changes` inteiro fica esse marcador; profundidade → `"[depth]"`.
  - **Desvio do cartão:** "chr(0) em reason/actor_label/target_id → PTA02" é impossível: o PostgreSQL recusa NUL
    antes de a função correr (`chr(0)` → 54000, NUL no protocolo → 22021, `\u0000` em jsonb → 22P05). Não há
    verificação no código (seria inatingível); `migrations/tests/audit_mask_limits.sql` prova a recusa nativa
    nos quatro campos e que nada fica gravado.
- **Eventos críticos e timeline (0015, alteração aprovada `0015_critical_timeline`, cartão 02/09a):**
  - `audit.critical_kind(action, outcome, actor_type)` (INVOKER, IMMUTABLE, nasce na migration e é selada; EXECUTE
    só do writer): `iban_change` (prefixos `stores.iban`, `payout_accounts.`, `merchants.iban`, qualquer outcome),
    `payment_failure` (`payments.`/`refunds.` com `error`, ou `payments.failed`), `invoice_failure` (`invoices.`
    com `error`, ou `invoices.failed`), `superadmin_login` (`auth.login` com ator `admin`), `verify_failure`
    (`audit.verify_failed`); NULL = não crítico. Mudar a lista = nova alteração aprovada.
  - `audit_alerts.kind` (CHECK com a mesma lista; o guard recusa mudá-lo). `_chain_insert` grava um alerta quando o
    ator é `admin`, há `impersonator_id` ou o kind não é NULL: `event_type` `audit.critical` (com kind) ou
    `audit.superadmin_action` (kind NULL). Payload = linha já mascarada + hashes em hex; com `iban_change` sai sem
    `changes` nem `reason` (o IBAN nunca, nem mascarado; o evento na cadeia fica com o IBAN mascarado).
  - Índices da timeline em `audit.audit_events`: `(store_id, created_at)`, `(actor_id, created_at)` e
    `((changes->>'order_id'), created_at) WHERE changes ? 'order_id'` (correlação de pagamento/fatura/envio com a
    encomenda); tenant e `(target_type, target_id, created_at)` já existiam. A consulta da encomenda usa
    `(target_type = 'order' AND target_id = $1) OR (changes ? 'order_id' AND changes->>'order_id' = $1)` (o
    `changes ? 'order_id'` tem de estar na consulta para o índice parcial servir).
- **Máscara v2, iban_change e tolerância explícita (0020, alteração aprovada `0020_mask_v2`, cartão 02/03e):**
  - **Antes de aplicar a 0020 em produção: esvaziar o stream de auditoria** (o worker consome tudo e a fila morta
    fica vazia). Um evento gravado antes da 0020 e reentregue depois pode dar `PTA03` (o dedupe compara o conteúdo
    mascarado e a máscara nova pode mudar `reason`/`actor_label`).
  - Máscara (vetores partilhados com o Rust e o Go em `docs/testdata/redaction-vectors.json`, só editados por este
    cartão): chaves camelCase normalizadas (`taxId` → `tax_id`); PII de identificação antes da exceção `*_id`
    (`tax_id`, `vat_id`, `national_id`, `niss`, `dni`, `nie`, `cif`, …); `mobile`/`cell`/`whatsapp`; `nib`,
    `account_number`, `bank_account`, `numero_conta` como IBAN; pares `{key|name|field|path|label|type|k,
    value|v|val}` e tuplos `["nif", "…"]`. Por valor: IBAN em qualquer caixa com espaços/NBSP/`-`/`.` e NIB de 21
    dígitos (controlo certo) → `****` + 4 últimos; string que é só um UUID ou só uma data/hora ISO → em claro; PAN
    (13–19 dígitos entre fronteiras de palavra, Luhn) → `"[redacted]"`; NIF PT (mód. 11), DNI/NIE ES e telefone
    (E.164, PT nacional) → `"[pii]"`. `_chain_insert` é o **único** ponto de máscara (`audit_append_db` e
    `audit_row_trigger` entregam `changes` em cru).
  - `iban_change`: medido em `_chain_insert` antes da máscara (chave de classe IBAN que muda entre `before` e
    `after`, `after` não nulo; INSERT e UPDATE, DELETE não), com prioridade sobre `critical_kind`; a action não muda
    (`stores.update`) e o alerta sai sem `changes` nem `reason`. Dois IBAN com os mesmos 4 últimos contam.
  - **Tolerância (cortar e marcar em vez de `PTA02`):** `_chain_insert(p_row, p_dedupe, p_tolerant)` (a de 2
    argumentos foi apagada e sai da allowlist da `audit_seal` nesta BD); sem `pg_trigger_depth()`.
    `audit_append_db` → sempre; `audit_append_event` → nunca; `audit_append` (a app tem EXECUTE) → só se a linha 2
    do `PG_CONTEXT`, inteira, for `PL/pgSQL function audit.audit_(row_trigger|ddl_end|ddl_drop)() line N at
    assignment`. Por isso as três funções chamam `v_ev := audit.audit_append(…)` e **nunca `PERFORM`**: um
    `PERFORM` (ou EXECUTE, `query_to_xml`) corre por SPI e põe antes uma linha `SQL statement "…"` com texto
    controlável (forjável com um alias entre aspas com quebras de linha). Ninguém cria funções em `audit.*`
    (selagem) nem em `pg_temp`: `REVOKE TEMPORARY ON DATABASE` de PUBLIC, app, worker e price_writer (o migrator,
    dono da BD em dev/CI, mantém; os testes criam tabelas temporárias como superuser/migrator).
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

## Criar o 1.º super_admin (migration 0024, cartão 02/20b)
Sem DDL, sem BYPASSRLS e sem desligar o FORCE RLS: uma chamada atómica a
`public.identity_create_superadmin(id uuid, email text, nome text, phc text, totp_secret_enc text, recovery_hashes bytea[])`
(DEFINER, dono `ptmarket_bootstrap`), que cria a conta ativa com TOTP ligado, o papel `super_admin` global e os 10
códigos de recuperação. Só `ptmarket_operator` tem EXECUTE. O CLI liga como migrator e faz, numa transação:
`BEGIN; SET LOCAL ROLE ptmarket_operator; SELECT public.identity_create_superadmin($1, $2, $3, $4, $5, $6); COMMIT;`
- Argumentos: email já em minúsculas e sem espaços nas pontas (3–255, com `@`); nome 1–255; PHC `$argon2id$…`;
  segredo `v1:<kid>:…`; exatamente 10 hashes HMAC de 32 bytes, distintos. Erro de validação = 22023; email
  (sem distinção de maiúsculas) ou id já existentes = 23505. As mensagens nunca ecoam os valores.
- Os eventos L1 ficam com ator `db` e `actor_label` = o login que ligou (o `SET ROLE` não o muda).
- Pré-requisito: o bootstrap da caixa negra cria `ptmarket_bootstrap` (com USAGE em `audit` e EXECUTE em
  `audit.audit_append_db`, na allowlist de grants da `audit_seal`). Num cluster existente: reaplicar o bootstrap
  (comando da secção anterior) **antes** da 0024; sem isso a 0024 recusa-se a correr.
- Produção: o owner pode criar um login próprio, membro de `ptmarket_operator` (`WITH INHERIT FALSE, SET TRUE`),
  depois de aplicada a 0024. Em dev, não acrescentar membros: as BDs do `sqlx::test` voltam a correr a 0024 e
  a guarda de memberships recusa-os.

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
