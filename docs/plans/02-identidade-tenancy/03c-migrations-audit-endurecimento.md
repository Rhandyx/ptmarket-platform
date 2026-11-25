# 03c — Endurecimento da caixa negra (achados médios/baixos da auditoria ASVS, 26/11) (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03b (usa `audit_admin.audit_upgrade`) · **Paralelo com:** 06, 08b · **Antes de:** 04

> Lê primeiro o cartão 03b (feito) e a secção "Caixa negra" de `infra/README.md`: qualquer alteração a um objeto selado de `audit.*` é uma **alteração aprovada** no bootstrap (`sealed_changes`), disparada na migration por `audit_admin.audit_upgrade(nome, sha256)`. Funções novas em `audit` podem ser criadas pela migration (DEFINER → allowlist). Termina com `SELECT audit_admin.audit_seal();`.

## Objetivo
A caixa negra não guarda segredos nem dados pessoais, mesmo que um produtor se engane. Não descarta em silêncio um evento real com id repetido. A verificação apanha cortes no início e no fim da cadeia, e defaults de `app.*` postos na BD ou no papel.

## Pode alterar
- `migrations/0012_audit_hardening.sql`, `migrations/tests/audit_hardening.sql` (criar); `infra/postgres/init/03-audit-bootstrap.sh` (alteração aprovada `0012_hardening` + allowlist); `infra/README.md`

## Não tocar
- `migrations/0001–0011`, `backend-rust/`, `workers-go/`; nunca ler `.env`

## Contexto exato
```
1. Máscara (audit.audit_redact, 0010:47-53, hoje denylist estreita):
   segredo (→ "[redacted]") quando o nome da chave casa com
     password|secret|token|credential|passkey|split_key|api_?key|private|otp|totp|cvv|cvc|pan|authorization|_enc$|_hash$
   PII (→ "[pii]") em QUALQUER tabela: email|phone|telefone|nif|nipc|vat_number|name$|full_name|first_name|last_name|
     address|morada|street|postal|zip|birth|ip$   (exceto chaves técnicas *_id e as colunas legal_name/name das tabelas
     tenants, categories e products, que não são pessoais: lista fixa no corpo)
   iban → só os 4 últimos (como hoje). Recursivo: objetos e arrays JSONB aninhados (ex.: settings).
   _chain_insert aplica audit.audit_redact(p_row.target_type, changes) a TODOS os caminhos (app, worker, db); idempotente.
2. audit_append_event (0009:104-106): mensagens de erro fixas, só com o nome da chave e o SQLSTATE; nunca SQLERRM
   (os erros de conversão citam o valor). SET lock_timeout = '2s' (como audit_append).
3. Dedupe (_chain_insert, 0008:435): id repetido com conteúdo IGUAL (mesmo sha256 dos campos do evento, sem
   chain_seq/prev_hash/hash/created_at) → NULL como hoje (reentrega). Id repetido com conteúdo DIFERENTE → RAISE
   SQLSTATE 'PTA03' (o worker trata-o como veneno + alerta; nunca descarta em silêncio).
4. audit_verify_chain (0009:143-181) passa a assinalar também: seq 1 sem prev_hash zero ('bad_genesis'); a primeira
   linha da janela não continua a última anterior à janela ('gap_before'); a última linha da cadeia ≠
   audit_chain_heads (last_seq, last_hash) quando p_to > agora ('head_mismatch'). Assinatura igual.
5. Defaults de app.* fora da transação: o migrator é dono da BD e pode fazer ALTER DATABASE/ROLE … SET
   app.actor_type, o que satisfaz o PTA01 em todas as sessões.
   Passo 0 (provar): pg_settings expõe `source` de um GUC personalizado app.actor_type?
     Sim → audit_append e o caminho app do trigger recusam (PTA01) quando source IN ('database','user','database user').
     Não → função audit.audit_guc_defaults() RETURNS TABLE(setdatabase oid, setrole oid, setting text), lida de
       pg_db_role_setting filtrada a app.%; DEFINER na allowlist; EXECUTE ptmarket_worker (o verify do cartão 09 alerta
       se devolver linhas).
```

## Feito quando
- [ ] Tabela de casos da máscara: `stores.email`, `tenants.settings.{api_key,smtp:{password}}`, `users.totp_secret`, `x.authorization`, `customers.address.street` → mascarados; `products.title`, `categories.name`, `*_id` → em claro
- [ ] `audit_append` e `audit_append_event` com `changes` em claro (email, password) → o evento gravado sai mascarado
- [ ] Id repetido, mesmo conteúdo → 1 evento; conteúdo diferente → PTA03 e nada gravado
- [ ] verify: cadeia íntegra → 0 linhas; génese adulterada, buraco antes da janela e cabeça divergente (simulados como superuser no teste) → o problema certo
- [ ] Passo 0 documentado no topo da migration; o caso escolhido tem teste (default de BD em `app.actor_type` → recusa, ou → linha devolvida)
- [ ] Erro de conversão em `audit_append_event` (uuid inválido) → a mensagem não contém o valor

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar
- `audit_*.sql`, `rls.sql`, `omnibus.sql` no mesmo `run.sh` · `cd workers-go && go test ./...`
