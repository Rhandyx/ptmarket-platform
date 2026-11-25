# 01b — Selar a caixa negra: o migrator não fica dono nem membro dos papéis de auditoria (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01, 02 · **Paralelo com:** — (bloqueia o 03)

## Objetivo
Corrige o achado ALTO da auditoria da onda 1. Hoje o `ptmarket_migrator`, que tem LOGIN e é a credencial de CI/deploy, consegue `SET ROLE ptmarket_audit_writer`, forjar linhas com hash válido, mexer em `audit_chain_heads` e, como dono do schema `public`, fazer DROP/DETACH de partições. Depois deste cartão, nenhum papel com LOGIN altera a caixa negra sem deixar rasto no pgaudit e na L2.

## Pode alterar
- `migrations/0008_audit_events.sql` e a migration do cartão 02 (não foram enviadas para o remoto nem aplicadas em nenhuma BD persistente, por isso podem editar-se); `migrations/tests/audit_core.sql`, `migrations/tests/run.sh`
- `infra/postgres/init/03-audit-bootstrap.sh` (criar), `infra/scripts/dev-check.sh`, `infra/README.md`

## Não tocar
- `migrations/0001–0007`, `backend-rust/`, `workers-go/`, `frontend-web/`; nunca ler `.env`

## Desenho (decidido pelo supervisor)
```
Bootstrap como superuser (03-audit-bootstrap.sh; corre em template1 E em ptmarket, para os sqlx::test e o run.sh herdarem; o run.sh corre o mesmo SQL no seu postgres descartável):
  papéis ptmarket_audit_owner e ptmarket_audit_writer: NOLOGIN, sem SUPERUSER/BYPASSRLS/CREATEROLE; o migrator NÃO é membro (nem ADMIN). Criados aqui, uma vez por cluster, e não na migration (isto acaba também com a corrida do CREATE ROLE).
  schema audit OWNER ptmarket_audit_owner; GRANT USAGE, CREATE ON SCHEMA audit TO ptmarket_migrator (temporário, até à selagem); USAGE a app, worker e price_writer.
  schema audit_admin OWNER postgres; função audit_admin.audit_seal() SECURITY DEFINER (dono postgres), SET search_path = pg_catalog, sem argumentos, EXECUTE só para o migrator. Faz:
    ALTER OWNER de todas as tabelas, partições e sequências de audit.* → ptmarket_audit_owner; das funções → o dono previsto (audit_append e funções de escrita → ptmarket_audit_writer; audit_ensure_partitions → ptmarket_audit_owner);
    REVOKE CREATE ON SCHEMA audit FROM ptmarket_migrator; REVOKE ALL em audit.* ao migrator;
    verifica no fim e faz RAISE se o migrator ficar com algum privilégio ou dono em audit.*, ou com membership em audit_owner/audit_writer. É idempotente. Só itera pg_class/pg_proc do schema audit, nunca recebe nomes de fora.
  A seguir, o superuser corta o ADMIN implícito: se a 0007 criou papéis com o migrator, isso não muda; isto só se aplica aos papéis de auditoria.
Migrations: audit_events (pai e partições), audit_chain_heads, audit_retention_class, audit_ensure_partitions, audit_append e as funções do cartão 02 passam para o schema audit; a última instrução da 0008 (e da 0009) é SELECT audit_admin.audit_seal(). Uma migration futura que mexa em audit.* precisa que o superuser volte a dar CREATE (duas pessoas; documentar no README).
Correções da auditoria a incluir:
  lock_timeout = '2s' na cláusula SET de audit_append (o FOR UPDATE da cabeça não pode bloquear um tenant para sempre); comentário: chamar audit_append no fim da transação.
  p_tenant_id só é aceite quando app.actor_type = 'system'; caso contrário RAISE (a app sem tenant não injeta eventos na cadeia de outro tenant).
  O hash usa ip::text (com máscara), e não host(ip). Atualizar a recomputação nos testes.
  Corrigir o comentário "dono incluído": o dono passa a ser ptmarket_audit_owner (NOLOGIN), e mesmo esse não tem UPDATE/DELETE/TRUNCATE.
Uma só implementação do hash: hoje o cálculo e o INSERT estão duplicados entre audit_append (0008) e audit_append_event (0009). Extrai uma função interna audit._chain_insert(...) (dono ptmarket_audit_writer, sem EXECUTE para mais ninguém), que as duas chamam; aplica o ip::text só aí. Teste: as duas entradas produzem hashes que o verify da 0009 aceita.
Corrida do CREATE ROLE na 0001/0007 (cluster novo + sqlx::test em paralelo → 23505): o bootstrap (init e run.sh) cria também ptmarket_app, ptmarket_worker e ptmarket_price_writer com os mesmos atributos das migrations, para que estas sigam sempre pelo ramo "já existe". Prova: cargo test em paralelo num postgres descartável acabado de criar, sem aquecimento com --test-threads=1.
Risco residual a documentar no topo da 0008: o superuser pode tudo. Mitigação: pgaudit.log='all' no postgres e a raiz para WORM (cartão 09).
```

## Feito quando
- [ ] Como migrator (LOGIN): `SET ROLE ptmarket_audit_writer` e `SET ROLE ptmarket_audit_owner` falham; INSERT/UPDATE/DELETE direto em `audit.audit_events`, numa partição ou em `audit.audit_chain_heads` falha; `DROP TABLE`, `ALTER TABLE … DETACH PARTITION`, `DISABLE TRIGGER`, `CREATE OR REPLACE FUNCTION audit.audit_append` e `CREATE TABLE audit.x` falham (42501)
- [ ] `audit_seal()` é idempotente; correr a 0008 duas vezes em BDs diferentes do mesmo cluster (sqlx::test em paralelo) passa sem 23505
- [ ] `audit_append` com `p_tenant_id` e ator ≠ `system` → RAISE; com `system` → grava na cadeia do tenant; mudar o `ip` de `/32` para `/8` dá um hash diferente
- [ ] Todos os testes de `audit_core.sql` e do cartão 02 continuam verdes, agora com o schema `audit`

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar
- `infra/scripts/dev-check.sh` com o volume recriado (`down -v`, dados de dev) → OK; `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket cargo test -p ptmarket-api` em paralelo → código 0; `cd workers-go && go test ./...`
