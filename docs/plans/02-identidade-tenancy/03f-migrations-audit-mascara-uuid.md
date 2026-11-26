# 03f — Caixa negra: a máscara da BD deixa de corromper UUIDs dentro de texto (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03e (0020), 10c (0022; numeração 0023) · **Antes de:** 17

> Bug encontrado pelo supervisor (26/11): `tests/audit_layer.rs::request_id_is_always_server_generated` falha de forma intermitente. `audit._redact_text('01a2185a-ac77-73f5-8fa6-b4840a004eeb')` devolve `01a2185a-****8fa6-b4840a004eeb`: a regra 4 (IBAN, "2 letras + 2 dígitos + grupos de 4 com '-'") apanha `ac77-73f5-8fa6` ANTES da regra 6 (UUID em claro), que só protege o valor inteiro. O segmento do meio de um UUIDv7 depende da hora → ids de pedido/alvo gravados corrompidos na caixa negra.

## Objetivo
Nenhum UUID (sozinho ou dentro de texto) é alterado pela máscara da BD; tudo o que hoje é mascarado continua a sê-lo.

## Pode alterar
- `infra/postgres/init/03-audit-bootstrap.sh` (só uma entrada NOVA em sealed_changes: `0023_mask_uuid`, requires `0020_mask_v2`; as antigas são imutáveis); `migrations/0023_audit_mask_uuid.sql` (criar); `migrations/tests/audit_mask_uuid.sql` (criar); `docs/testdata/redaction-vectors.json` (só ACRESCENTAR vetores)

## Não tocar
- `migrations/0001–0022`; entradas antigas do bootstrap; `backend-rust/`, `workers-go/` (só correr os testes de vetores deles); nunca ler `.env`. Não aplicar à BD de dev (o supervisor aplica o bootstrap + migration).

## Contexto exato
```
Ler primeiro: o topo da 0008, a secção "Caixa negra" de infra/README.md (procedimento de alteração selada: entrada no bootstrap, sha256 calculado na BD, audit_admin.audit_upgrade(nome, sha256) na migration, SELECT audit_admin.audit_seal(); no fim), e a 0020 (corpo ATUAL de audit._redact_text).
Correção: em audit._redact_text, as regras numéricas (IBAN, NIB, PAN, NIF, DNI/NIE, telefone — tudo o que vem depois do e-mail) não podem tocar em substrings com forma de UUID (8-4-4-4-12 hex, qualquer caixa, entre fronteiras). Padrão do Rust (backend-rust/src/http/telemetry.rs, redact_str): JWT/chaves/e-mail sobre o texto inteiro; depois as regras numéricas só nos troços FORA dos UUID. Implementação livre (troços, ou marcadores sem dígitos nem letras hex restaurados no fim — que não possam colidir com input real). Mantém IMMUTABLE PARALLEL SAFE, search_path, assinatura, dono e grants. Só _redact_text muda (se outra função tiver de mudar, parar e reportar).
Vetores novos (kind "text", layers ["db","rust","go"], must_equal_input): "01a2185a-ac77-73f5-8fa6-b4840a004eeb"; "pedido 01a2185a-bd21-7437-b788-4e359b080843 falhou"; dois UUIDs separados por espaço. Vetor de controlo (must_not_contain o IBAN): "PT50 0002 0123 1234 5678 9015 4 ref 01a2185a-ac77-73f5-8fa6-b4840a004eeb" (o UUID também tem de ficar intacto: must_contain se o formato o tiver; senão um teste SQL).
Stream: como na 0020, um evento reentregue depois pode dar PTA03 se a máscara mudar o texto → nota no topo da migration (esvaziar o stream antes de migrar em produção).
```

## Feito quando
- [ ] `audit._redact_text` devolve os 4 UUIDs do relatório (`ac77-73f5`, `bd21-7437`, `dd68-71a1`, `ee44-73f2` no meio) intactos, sozinhos e dentro de texto; 10 000 UUIDv7/v4 gerados no teste → todos intactos
- [ ] Todos os vetores `db` (antigos + novos) verdes; os vetores `rust` e `go` também verdes com os novos (correr `cargo test -p ptmarket-api --lib telemetry` e `go test ./internal/logx/`; se falharem, parar e reportar — não mexer no código deles)
- [ ] run.sh verde, incluindo a 2.ª passagem (0023 com a L2 ativa)

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar
- `audit_*.sql`, `identity_portal_hardening.sql`, `customers_insert_role_guards.sql` (no run.sh); depois de o supervisor aplicar à BD de dev: `cargo test -p ptmarket-api --all-features` (audit_layer 5× seguidas sem falhas)
