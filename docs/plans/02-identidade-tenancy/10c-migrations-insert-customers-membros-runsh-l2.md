# 10c — BD: INSERT de clientes sem colunas de estado, papéis DEFINER sem memberships, run.sh com a L2 ativa na última migration (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 10b (0021 aplicada) · **Paralelo com:** 09c · **Antes de:** 11b, 17

> Achados médios 2 e 3 da auditoria ASVS do 10b/09b (26/11) + dívida técnica do run.sh (a 0021 passou no run.sh e falhou na BD de dev com a L2: o DDL feito com SET ROLE para um papel sem acesso a `audit` é recusado, 42501).

## Objetivo
A app não consegue criar um cliente já verificado nem anonimizado. Os papéis donos de objetos DEFINER/views (`ptmarket_identity`, `ptmarket_portal`) não pertencem a outros papéis nem têm membros inesperados. O `run.sh` passa a provar cada migration nova com os event triggers já ligados.

## Pode alterar
- `migrations/0022_customers_insert_role_guards.sql`, `migrations/tests/customers_insert_role_guards.sql` (criar); `migrations/tests/run.sh` (2.ª passagem); `migrations/tests/customers.sql` (só se uma asserção de grants de INSERT contradisser; listar no relatório)

## Não tocar
- `migrations/0001–0021` (imutáveis); `infra/postgres/bootstrap/` (só ler); `backend-rust/`, `workers-go/`; nunca ler `.env`. Não aplicar à BD de dev (o supervisor aplica).

## Contexto exato
```
A. customers (0017:95): ptmarket_app tem INSERT em todas as colunas, incluindo email_verified_at e anonymized_at → pre-account hijacking (conta com e-mail alheio já verificado). Nenhum código faz hoje INSERT em customers (o cartão 17 vai fazer).
   → REVOKE INSERT ON customers FROM ptmarket_app; GRANT INSERT (todas as colunas EXCETO email_verified_at e anonymized_at) TO ptmarket_app. Ler as colunas ATUAIS (0017 + posteriores). Os outros papéis: não mexer.
B. Papéis do cluster criados com IF NOT EXISTS (0017 ptmarket_identity, 0021 ptmarket_portal): só se recusam SUPERUSER/BYPASSRLS/LOGIN. Se um deles for membro de outro papel (ex.: do dono de stores, ou de ptmarket_app), herda privilégios e o RLS/colunas deixam de valer.
   → DO no início da 0022: RAISE se algum dos dois for membro de QUALQUER papel (pg_auth_members.member = papel), ou se tiver membros que não sejam o migrator atual (current_user) — os grants do bootstrap (grantor superuser, ADMIN) e o do migrator (SET TRUE, INHERIT FALSE) são os únicos aceites. Também RAISE se o migrator tiver INHERIT TRUE num deles. Mensagem fixa e clara.
C. run.sh: hoje aplica TODAS as migrations e só depois event-triggers.sql. → Depois da passagem atual (que fica igual), uma 2.ª passagem numa BD nova: migrations até N-1 (N = a de número mais alto), event-triggers.sql como superuser, depois a migration N como migrator; falha → run.sh falha com código ≠ 0 e mensagem "migration N falhou com a L2 ativa". Reutilizar o mecanismo do próprio run.sh (contentor descartável / MIGRATIONS_TEST_URL); manter o tempo total razoável.
   Prova de que a 2.ª passagem morde: numa cópia no scratch, uma migration falsa 9999 com SET LOCAL ROLE ptmarket_identity + CREATE OR REPLACE de uma função identity_* → a 2.ª passagem chumba. Não deixar a cópia nem a migration falsa no repo.
Tabelas novas: nenhuma. Rollback mental no topo da migration.
```

## Feito quando
- [ ] `SET ROLE ptmarket_app`: INSERT em customers com email_verified_at ou anonymized_at → 42501; sem essas colunas → funciona (com o contexto que a L1 exige)
- [ ] Papel de teste `x` com `GRANT ptmarket_app TO ptmarket_portal` (ou um membro estranho em ptmarket_identity) → o DO da 0022 recusa (testar a lógica numa transação com ROLLBACK, sem deixar o papel)
- [ ] run.sh: 2.ª passagem verde com a 0022; a prova da migration falsa chumba (relatar a saída)

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar
- todos os testes do run.sh (`customers.sql`, `portal.sql`, `identity_portal_hardening.sql`, `audit_*.sql`)
