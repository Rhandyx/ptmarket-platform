# 03b — `db_user` em cada evento + alterações seladas aprovadas (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03 · **Paralelo com:** 06 · **Antes de:** 04, 09a (renumerados para 0012/0013)

> **Mudou no 01b (ler antes de começar):** a caixa negra vive no schema `audit` (dono NOLOGIN). O migrator só tem USAGE + CREATE em `audit` e não é dono de nada selado (não consegue fazer ALTER TABLE nem CREATE OR REPLACE em `audit.*`). Cada migration que toca em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma DEFINER nova só entra pela allowlist em `infra/postgres/init/03-audit-bootstrap.sh`. Chamar `audit.*` sempre com schema e tipos exatos. Lê o topo da 0008 e a secção "Caixa negra" de `infra/README.md` antes de escrever.

## Objetivo
1. **Forja pelo migrator detetada:** o migrator tem SET em `ptmarket_app`/`ptmarket_worker`/`ptmarket_price_writer` (precisa dele para os GRANT/OWNER da 0001/0007 e para os testes) e, com `SET ROLE` + `app.actor_type`, consegue gravar eventos que parecem da app. O `session_user` não muda com SET ROLE nem dentro de DEFINER, e só o superuser o pode alterar (SET SESSION AUTHORIZATION). Cada evento passa a gravar `db_user = session_user` dentro do hash, e a verificação assinala o ator incoerente com o papel LOGIN.
2. **Achados ALTOS da auditoria ASVS (ondas 2+, 26/11):** (a) `audit_admin.audit_seal()` tem `SET search_path = pg_catalog` SEM `pg_temp`: o pg_temp é pesquisado primeiro para relações, e o migrator, com `CREATE TEMP TABLE pg_class/pg_proc/pg_roles/pg_depend`, faz a selagem (DEFINER do postgres) ler catálogos falsos; (b) `audit.audit_append` aceita `app.actor_type = 'db'` vindo do GUC: a app (ou uma SQLi) forja eventos iguais aos do trigger.
3. **Caminho para alterar objetos selados:** hoje nenhuma migration consegue alterar `audit.audit_events`, `_chain_insert` ou `audit_alerts` (o 09a precisa disto). Cria-se `audit_admin.audit_upgrade`: o superuser aprova o SQL exato no bootstrap (duas pessoas), e a migration só o pode disparar por nome e hash.

## Pode alterar
- `migrations/0011_audit_db_user.sql`, `migrations/tests/audit_db_user.sql` (criar)
- `infra/postgres/init/03-audit-bootstrap.sh` (mecanismo `audit_upgrade` + alteração aprovada `0011_db_user` + allowlist), `migrations/tests/run.sh` (só se o teste novo não entrar sozinho), `infra/README.md` (secção da caixa negra)

## Não tocar
- `migrations/0001–0010` (imutáveis), `backend-rust/`, `workers-go/`, `frontend-web/`; nunca ler `.env`

## Contexto exato
```
A) audit_admin.audit_upgrade (no bootstrap, em template1 e nas BDs da lista, como os outros objetos de audit_admin)
  Tabela audit_admin.sealed_changes(name text PK, sql text NOT NULL, sha256 text NOT NULL) — dono postgres, sem
    GRANT a ninguém. O bootstrap faz upsert das alterações aprovadas (texto dollar-quoted no próprio bootstrap;
    sha256 = encode(sha256(convert_to(sql,'UTF8')),'hex') calculado na BD). Tabela audit_admin.sealed_changes_applied
    (name PK, applied_at, session_user_name) — dono postgres.
  audit_admin.audit_upgrade(p_name text, p_sha256 text) RETURNS void — SECURITY DEFINER, dono postgres,
    SET search_path = pg_catalog, pg_temp; EXECUTE só para ptmarket_migrator (REVOKE de PUBLIC).
    Nome inexistente → RAISE; sha256 diferente do aprovado → RAISE (a migration, checksumada pelo sqlx, e o texto
    aprovado pelo superuser têm de bater); já aplicada nesta BD → RAISE. Senão EXECUTE o sql, grava em _applied,
    e no fim PERFORM audit_admin.audit_seal() (os objetos criados pelo EXECUTE nascem com dono postgres: a selagem
    tem de os passar para owner/writer — confirmar que a audit_seal já o faz; se não, corrigi-la).
  Corre na transação da migration (falha = tudo desfeito). Nunca aceita SQL do chamador.
  Rever: pode o migrator, com CREATE em audit, influenciar o EXECUTE (sobrecargas, operadores, tipos em audit ou
    public)? O sql aprovado usa sempre nomes qualificados e tipos exatos; search_path pg_catalog, pg_temp.

B) Alteração aprovada '0011_db_user' (texto no bootstrap):
  ALTER TABLE audit.audit_events ADD COLUMN db_user text;   (sem DEFAULT; linhas antigas ficam NULL)
  audit._event_hash: db_user IS NULL → fórmula atual sem mudanças (linhas antigas continuam a verificar);
    db_user NOT NULL → o mesmo array com db_user acrescentado no fim.
  audit._chain_insert: v_row.db_user := session_user (ignora o que vier em p_row); INSERT com a coluna nova.
  Manter assinaturas, donos, search_path e grants (CREATE OR REPLACE).

B2) Na mesma alteração aprovada: audit.audit_append recusa app.actor_type = 'db' (RAISE PTA01) e qualquer valor fora
  da lista do CHECK; o 'db' só nasce em audit_append_db (0010).

D) audit_seal (bootstrap, CREATE OR REPLACE como superuser; não precisa de migration):
  SET search_path = pg_catalog, pg_temp e TODOS os catálogos qualificados (pg_catalog.pg_class, …). A verificação
  das DEFINER passa a exigir que o search_path fixo termine em pg_temp. O mesmo para audit_upgrade (A).

C) Migration 0011 (como migrator):
  SELECT audit_admin.audit_upgrade('0011_db_user'::text, '<sha256>'::text);
  audit.audit_verify_actors(p_chain_key uuid, p_class text, p_from timestamptz, p_to timestamptz)
    RETURNS TABLE (event_id uuid, chain_seq bigint, actor_type text, db_user text, problem text)
    — DEFINER (dono ptmarket_audit_writer, na allowlist), STABLE, EXECUTE só ptmarket_worker. Regras:
      actor_type IN (customer, merchant, municipal, admin, api_key, anonymous) e db_user <> 'ptmarket_app' → 'actor_db_user_mismatch'
      actor_type = 'system' e db_user NOT IN ('ptmarket_app','ptmarket_worker') → 'actor_db_user_mismatch'
      actor_type = 'db' e actor_label não termina em '/' || db_user → 'db_label_mismatch'
      db_user IS NULL em evento criado depois da aplicação de 0011_db_user (ler applied_at numa função DEFINER
        de audit_admin, ou gravar o instante numa tabela selada de audit) → 'db_user_missing'
    Nunca devolve changes nem dados pessoais.
  Termina com SELECT audit_admin.audit_seal();
  Nota: em dev/CI os testes ligam como migrator e fazem SET ROLE ptmarket_app; esses eventos SÃO assinalados
    (é o comportamento certo; o worker do cartão 09 corre o verify só na BD real).
```

## Feito quando
- [ ] Ligado como `ptmarket_migrator` + `SET ROLE ptmarket_app` + `app.actor_type='merchant'` → o evento grava `db_user = 'ptmarket_migrator'` e `audit_verify_actors` devolve-o como `actor_db_user_mismatch`; ligado como LOGIN `ptmarket_app` (criar um LOGIN de teste no run.sh, se preciso) → `db_user = 'ptmarket_app'` e nada é assinalado
- [ ] `db_user` entra no hash: `audit_verify_chain` passa com eventos antigos (NULL) e novos na mesma cadeia; mudar o db_user de uma linha (como superuser, no teste) parte a cadeia
- [ ] `audit_seal.sql`: o migrator cria `TEMP TABLE pg_proc/pg_class/pg_roles/pg_depend` falsas e chama `audit_seal()` → a selagem ignora-as (continua a recusar uma DEFINER fora da allowlist plantada no mesmo teste); DEFINER com `search_path = pg_catalog` (sem pg_temp) é recusada
- [ ] `audit_append` com `app.actor_type = 'db'` → PTA01 e nada gravado
- [ ] `audit_upgrade`: nome desconhecido, sha256 errado e segunda aplicação → erro; o migrator não lê nem escreve `sealed_changes`/`_applied`; `ptmarket_app`/`worker` não têm EXECUTE
- [ ] Depois da 0011: `audit_seal()` passa; nenhum objeto em `audit.*` tem dono `postgres` ou `ptmarket_migrator`; o migrator não tem privilégios nos objetos novos
- [ ] `infra/README.md`: como aprovar uma alteração selada (editar o bootstrap, reaplicar como superuser, só depois a migration) e o porquê do `db_user`

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar
- `audit_seal.sql`, `audit_l1.sql`, `rls.sql`, `omnibus.sql` (no mesmo `run.sh`) · `cd workers-go && go test ./...` (o escritor do stream passa por `_chain_insert`: continua verde) · BD de dev: reaplicar o bootstrap como superuser (comando no README) e `sqlx migrate run` → sem erros

## Fora de âmbito (registar no relatório, não fazer)
- Recusar na escrita (em vez de assinalar) o ator incoerente: exige que os testes liguem como LOGIN da app; avaliar em produção.
- Tirar ao migrator o SET em app/worker depois do bootstrap (produção).
