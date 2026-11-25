# 04 — L2: event trigger de DDL + L1 automático em tabelas novas (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03, 05 · **Paralelo com:** 06, 09

## Objetivo
Todo o `CREATE`/`ALTER`/`DROP`/`GRANT`/`REVOKE` fica em `audit_events` (`ddl.*`) e qualquer tabela criada a partir de agora recebe sozinha os triggers da L1.

## Pode alterar
- `migrations/0011_audit_ddl.sql`, `migrations/tests/audit_ddl.sql` (criar)
- Só se o passo 0 o exigir: `infra/postgres/bootstrap/event-triggers.sql` (criar), `migrations/tests/run.sh` e `infra/scripts/dev-check.sh` (editar: correr esse ficheiro como superuser depois das migrations), `infra/README.md`

## Não tocar
- `migrations/0001–0010` — imutáveis; `infra/docker-compose.dev.yml`, `infra/postgres/Dockerfile` — cartão 05; `backend-rust/`, `workers-go/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §0 L2: event trigger de DDL — CREATE/ALTER/DROP de tabelas, funções, policies, papéis e grants vão para audit_events (action = 'ddl.*'). Uma tabela criada por migration recebe logo o trigger da L1 automaticamente.
Passo 0 (provar antes de escrever): ptmarket_migrator (NOSUPERUSER, dono da BD) consegue CREATE EVENT TRIGGER no PG 18.1?
  Sim → tudo em 0011.
  Não → 0011 cria só as funções; os CREATE EVENT TRIGGER vão para infra/postgres/bootstrap/event-triggers.sql (idempotente, corrido como superuser DEPOIS das migrations em run.sh e dev-check.sh; em produção é passo de deploy). O teste falha se os event triggers não existirem ou não estiverem ativos.
audit_ddl_end() em ddl_command_end: por cada linha de pg_event_trigger_ddl_commands() → audit_append_db (ou audit_append se houver app.actor_type) com action = 'ddl.' || lower(replace(command_tag,' ','_')) (ex.: ddl.create_table, ddl.alter_table, ddl.create_policy, ddl.grant, ddl.create_function), target_type = object_type, target_id = object_identity, changes = {"query": current_query() mascarada}, tenant NULL (cadeia da plataforma).
  Máscara do SQL: PASSWORD '…' → PASSWORD '[redacted]'; nunca gravar literais a seguir a PASSWORD/SECRET.
  Se command_tag = 'CREATE TABLE', schema public, não partição e fora da allowlist {audit_events, outbox_events} → criar zz_audit_row + zz_audit_truncate (ENABLE ALWAYS), como em 0010.
audit_ddl_drop() em sql_drop: por cada pg_event_trigger_dropped_objects() original → 'ddl.drop_' || object_type. DROP ou DISABLE de zz_audit_row/zz_audit_truncate, e ALTER TABLE … DISABLE TRIGGER, por ptmarket_app/ptmarket_worker → RAISE (para os outros papéis fica registado; a L3 guarda o SQL).
Quem dispara o event trigger precisa de EXECUTE em audit_append_db: o dono (migrator) já tem; outro papel sem EXECUTE falha fechado.
Limite do PostgreSQL (escrever no topo da migration): event triggers NÃO disparam para objetos globais (CREATE/ALTER/DROP ROLE, GRANT de pertença a papel). Esses ficam cobertos só pela L3 (pgaudit, classe `role`, cartão 05). Não inventar alternativa. Não existe função nem GUC de bypass.
```

## Feito quando
- [ ] `audit_ddl.sql`: `CREATE TABLE t_probe (id uuid primary key)` deixa 1 evento `ddl.create_table` e a tabela já tem `zz_audit_row`/`zz_audit_truncate` ativos; um INSERT nela gera `t_probe.insert`; `DROP TABLE` deixa `ddl.drop_table`
- [ ] `CREATE POLICY`, `GRANT … ON TABLE`, `ALTER TABLE … ADD COLUMN`, `CREATE FUNCTION` deixam cada um o seu evento `ddl.*` com `actor_type = 'db'`
- [ ] `ALTER ROLE … PASSWORD` dentro de um bloco com outro DDL: o `changes.query` gravado não contém a password
- [ ] `ptmarket_app` a tentar `ALTER TABLE stores DISABLE TRIGGER zz_audit_row` falha (não é dono) e, se fosse dono, o event trigger recusava (testar com tabela de prova cujo dono é a app)
- [ ] O teste de cobertura do cartão 03 continua verde sem nenhum `CREATE TRIGGER` manual para tabelas novas

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0 (e `infra/scripts/dev-check.sh` verde se o passo 0 deu "Não")

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Cartões 01–03 (`audit_core.sql`, `audit_worker.sql`, `audit_l1.sql`), RLS e Omnibus — todos no `run.sh`
