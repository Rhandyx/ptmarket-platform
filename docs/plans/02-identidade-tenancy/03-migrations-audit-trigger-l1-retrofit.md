# 03 — L1: trigger genérico de auditoria em TODAS as tabelas + retrofit 0002–0007 (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 02 · **Paralelo com:** 08

> **Mudou no 01b (ler antes de começar):** a caixa negra vive no schema `audit` (dono NOLOGIN). O migrator só tem USAGE + CREATE em `audit`. Qualquer migration que crie objetos em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma função SECURITY DEFINER nova em `audit` só passa a selagem se a sua assinatura estiver na allowlist da `audit_seal()` em `infra/postgres/init/03-audit-bootstrap.sh` (este cartão pode editá-la; o README de infra diz como aplicar como superuser). Nenhuma função DEFINER de `audit.*` toca em objetos de papéis com LOGIN. Escrever na cadeia: só através de `audit._chain_insert` (fórmula única `audit._event_hash`).

## Objetivo
Cada INSERT/UPDATE/DELETE/TRUNCATE em qualquer tabela fica em `audit_events` com ator e antes/depois mascarados; mutação da app/worker sem ator aborta; uma tabela sem trigger chumba os testes.

## Pode alterar
- `migrations/0010_audit_row_trigger.sql`, `migrations/tests/audit_l1.sql` (criar); `migrations/tests/rls.sql`, `migrations/tests/omnibus.sql` (editar: só fixar o ator onde atuam como app); `infra/postgres/init/03-audit-bootstrap.sh` (só a allowlist da `audit_seal`)

## Não tocar
- `migrations/0001–0009` — imutáveis; `backend-rust/` — os testes `rls_isolation` ficam VERMELHOS depois deste cartão até ao cartão 06 (esperado; não contornar); `workers-go/`, `infra/`

## Contexto exato (colado da spec; não ler a spec)
```
Spec 13 §0: TODAS as tabelas, sem exceção, registam cada INSERT, UPDATE e DELETE: quem, quando, de onde, o quê, valores antes/depois. Exceções só técnicas, em allowlist FIXA no teste: audit_events, audit_chain_heads (cabeça da cadeia, 0008) e outbox_events. Não há opt-in: tabela nova sem trigger chumba os testes.
Spec 13 §3.2: falha fechado — mutação de ptmarket_app/ptmarket_worker sem app.actor_type → RAISE e a transação aborta. Fora da app (SQL manual, Data Studio) o trigger regista actor_type = 'db' com o session_user. §3.5: nunca gravar segredos, passwords, PAN ou IBAN completo; dados pessoais só como referência ao id.
audit_append_db(p_action, p_target_type, p_target_id, p_changes jsonb, p_tenant_id uuid, p_db_role text) RETURNS uuid — DEFINER (dono ptmarket_audit_writer): igual a audit_append (0008) mas actor_type = 'db', actor_label = p_db_role || '/' || session_user. EXECUTE: REVOKE de PUBLIC; GRANT só a ptmarket_migrator e ptmarket_price_writer. NUNCA a ptmarket_app/ptmarket_worker (não podem fingir ser 'db'). Papel sem EXECUTE = a mutação falha (fechado).
audit_row_trigger() — SECURITY INVOKER (precisa do current_user real), search_path fixo:
  sem app.actor_type: current_user IN ('ptmarket_app','ptmarket_worker') → RAISE SQLSTATE 'PTA01' 'mutação sem ator'; qualquer outro papel → audit_append_db. Com app.actor_type → audit_append.
  action = TG_TABLE_NAME || '.' || lower(TG_OP); target_type = TG_TABLE_NAME; target_id = id da linha (texto); outcome 'success'. Tenant: coluna tenant_id da linha se existir; na tabela tenants = id; senão NULL (a função usa o contexto). store_id: coluna store_id, ou id na tabela stores.
  changes: INSERT {"after": linha} · DELETE {"before": linha} · UPDATE {"before": {...}, "after": {...}} só com as colunas alteradas; UPDATE sem diferenças não grava evento.
  Máscara antes de gravar (audit_redact(tabela, jsonb)): coluna cujo nome case com (password|secret|token|credential|passkey|split_key|_enc$|_hash$) → "[redacted]"; iban → só os 4 últimos; PII por tabela → "[pii]": customers(email, name, phone, nif), users(email, full_name), qualquer coluna ip. O evento diz QUE mudou, não o valor.
Ligação: CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE FOR EACH ROW + zz_audit_truncate BEFORE TRUNCATE FOR EACH STATEMENT (action '<tabela>.truncate'); ambos ENABLE ALWAYS (session_replication_role não os salta).
Retrofit: tenants, categories, stores, products, product_variants, customers, product_price_history e _sqlx_migrations. NÃO em audit_events, audit_chain_heads nem outbox_events.
Nota Omnibus: o INSERT em product_price_history corre como ptmarket_price_writer (trigger DEFINER de 0007); com ator no contexto usa audit_append, sem ator (seed pelo dono) usa audit_append_db — é seguro porque o zz_audit_row de product_variants já aborta a app sem ator.
Testes existentes: onde rls.sql/omnibus.sql mutam como ptmarket_app, fixar antes SELECT set_config('app.actor_type','system',true) + app.actor_label = 'test'.
```

## Feito quando
- [ ] `audit_l1.sql` — cobertura: falha se existir tabela em `public` (`relkind IN ('r','p')`, não partição) fora da allowlist `{audit_events, audit_chain_heads, outbox_events}` sem `zz_audit_row` e `zz_audit_truncate` com `tgenabled = 'A'`
- [ ] App com ator: UPDATE de `price_cents` grava `product_variants.update` (classe `fiscal`) só com esse campo, e `product_price_history.insert`; INSERT e DELETE gravam; ROLLBACK não deixa evento; tenant A não lê os eventos de B (anti-IDOR)
- [ ] App e worker sem ator: qualquer mutação → PTA01 e nada gravado; `ptmarket_app` não chama `audit_append_db`; dono sem ator grava `actor_type = 'db'` com o `session_user`
- [ ] Máscara: evento de `customers` sem email/nome/NIF/telefone/`password_hash`; `stores` só com 4 dígitos do IBAN; o teste falha se uma coluna de nome sensível (regex acima) aparecer em claro

## Prova (um comando)
`migrations/tests/run.sh` → esperado: `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- RLS base e Omnibus (`rls.sql`, `omnibus.sql` no `run.sh`, com as mesmas asserções de antes) · publicador outbox — `cd workers-go && go test ./...` (continua verde: o outbox está na allowlist)
