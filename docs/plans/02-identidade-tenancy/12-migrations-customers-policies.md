# 12 — Abrir `customers`: policies, grants por coluna e lookup de login (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 10 · **Paralelo com:** 11

## Objetivo
A API consegue registar um cliente, autenticá-lo e deixá-lo ler/alterar SÓ a sua linha; nunca consegue listar nem ler clientes alheios, nem com SQL injetado.

## Pode alterar
- `migrations/0016_customers_policies.sql`, `migrations/tests/customers.sql` (criar); `migrations/tests/rls.sql` (editar: só a asserção "app não lê customers", que passa a "sem ator lê 0 linhas")

## Não tocar
- `migrations/0001–0015` — imutáveis; `backend-rust/`, `workers-go/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Hoje (0005): customers(id, email, name, phone, nif, password_hash /*Argon2id PHC; NULL = só passkey*/, passkeys JSONB, consents JSONB, anonymized_at, created_at, updated_at; CHECK (email IS NOT NULL OR anonymized_at IS NOT NULL); UNIQUE (lower(email))) — global (uma conta para todas as Câmaras), RLS FORCE, ZERO policies e ZERO grants. Já tem zz_audit_row (cartão 03) com email/name/phone/nif mascarados.
Acrescentar: email_verified_at TIMESTAMPTZ (o fluxo de verificação por email é de outro épico).
A := CASE WHEN current_setting('app.actor_type', true) = 'customer' THEN NULLIF(current_setting('app.actor_id', true), '')::uuid END
Policies TO ptmarket_app:
  customer_self_select FOR SELECT USING (id = A AND anonymized_at IS NULL) · customer_self_update FOR UPDATE USING (id = A AND anonymized_at IS NULL) WITH CHECK (id = A)
  customer_register    FOR INSERT WITH CHECK (current_setting('app.actor_type', true) = 'anonymous' AND anonymized_at IS NULL AND email_verified_at IS NULL)
Grants a ptmarket_app: SELECT; INSERT; UPDATE (email, name, phone, nif, password_hash, passkeys, consents, updated_at). SEM DELETE e sem UPDATE de id, created_at, anonymized_at, email_verified_at (esquecimento RGPD = anonymized_at mantendo dados fiscais; é do épico RGPD).
  Consequência para o Rust: o registo é INSERT sem RETURNING e sem ON CONFLICT (o ator anónimo não passa na policy de SELECT); email repetido = 23505.
Papel ptmarket_identity (NOLOGIN, sem SUPERUSER/BYPASSRLS, padrão de 0007): dono das funções de lookup; GRANT SELECT (id, email, password_hash, anonymized_at) ON customers + policy FOR SELECT TO ptmarket_identity USING (true).
identity_customer_credentials(p_email text) RETURNS TABLE (id uuid, password_hash text) — SECURITY DEFINER, STABLE, SET search_path = pg_catalog, public; WHERE lower(email) = lower(p_email) AND anonymized_at IS NULL; no máximo 1 linha; REVOKE de PUBLIC; EXECUTE só ptmarket_app.
  É a ÚNICA leitura por email. Não devolve nome, telefone nem NIF. Proibida qualquer função que liste ou pesquise clientes.
RGPD: consents guarda versão + data de cada consentimento; marketing nunca vem ligado por omissão (validado na API, cartão 17). Nenhuma tabela nova; os eventos customers.insert/update saem do trigger L1 com o ator do contexto.
```

## Feito quando
- [ ] `customers.sql` (sempre `SET ROLE ptmarket_app`): ator anónimo insere e não consegue ler a linha; ator `customer` X lê e altera só a sua; SELECT/UPDATE da linha de Y devolve/afeta 0 linhas (anti-IDOR); sem ator → 0 linhas
- [ ] Ator `merchant`/`admin` com o mesmo `actor_id` NÃO lê a linha (o tipo conta); DELETE falha (42501); UPDATE de `anonymized_at` e `email_verified_at` falha
- [ ] `identity_customer_credentials` devolve id + hash para email existente (maiúsculas ignoradas) e 0 linhas para inexistente/anonimizado; `ptmarket_worker` não a executa; `ptmarket_identity` não tem INSERT/UPDATE/DELETE
- [ ] Cada INSERT/UPDATE dos testes deixou evento em `audit_events` sem email/nome/NIF em claro

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `rls.sql`, `omnibus.sql`, `portal.sql`, `audit_*.sql` — todos no `run.sh`
