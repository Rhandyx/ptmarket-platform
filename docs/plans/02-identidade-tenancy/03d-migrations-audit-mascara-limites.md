# 03d — Caixa negra: máscara PT/EN por chave e por valor, limites de tamanho, alterações encadeadas (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03c, 04 (numeração 0014) · **Paralelo com:** 07b · **Antes de:** 09a

> Lê a secção "Caixa negra" de `infra/README.md` e as alterações aprovadas `0011_db_user` e `0012_hardening` no bootstrap. Alterar objetos selados = alteração aprovada `0014_mask_limits` + `audit_admin.audit_upgrade` na 0014. Parte das funções ATUAIS (`_redact_walk`, `_chain_insert`, `audit_append_event`), não do texto das migrations antigas.

## Objetivo
Nenhum segredo nem dado pessoal entra na caixa negra por um nome de chave em português, por um par chave/valor genérico ou por um valor que denuncie o que é. Nenhum evento é grande ou fundo demais. As alterações seladas só se aplicam pela ordem certa.

## Pode alterar
- `migrations/0014_audit_mask_limits.sql`, `migrations/tests/audit_mask_limits.sql` (criar); `infra/postgres/init/03-audit-bootstrap.sh` (alteração aprovada + `audit_upgrade` + allowlist); `infra/README.md`

## Não tocar
- `migrations/0001–0013`, testes existentes (se um contradisser o cartão: parar e reportar), `backend-rust/`, `workers-go/`; nunca ler `.env`

## Contexto exato
```
Máscara (_redact_walk, bootstrap:~625-660):
  Segredo (→ "[redacted]") acrescentar: senha|palavra.?passe|segredo|chave|pwd|passw|access.?key|api.?key (também hífen)|
    jwt|bearer|cookie|session|signature|hmac|pin$|card.?number|cartao|passport|passaporte. A regra de SEGREDOS corre ANTES
    da exceção *_id (reset_token_id, secret_id → mascarados); a exceção *_id só vale para a PII.
  PII (→ "[pii]") acrescentar: nome|apelido|telemovel|telemóvel|contribuinte|nascimento|morada (sem e com acentos;
    comparar depois de unaccent-like: translate das vogais acentuadas, sem extensão).
  Pares genéricos: objeto com chaves {key|name|field, value} cujo key/name/field case com segredo/PII → value mascarado.
  Por valor (todos os escalares string, mesmo sob chave neutra e dentro de arrays): e-mail (regex simples) → "[pii]";
    JWT (três segmentos base64url com ponto) → "[redacted]"; prefixos de chave de API (sk_, pk_live_, rk_, ghp_, xox[bp]-,
    AKIA[0-9A-Z]{16}) → "[redacted]"; IBAN (PT50 + 21 dígitos, ou qualquer IBAN ISO) → 4 últimos.
  reason e actor_label também passam pela máscara por valor; target_id NÃO (é um id).
Limites (em _chain_insert, RAISE 'PTA02' com mensagem fixa, sem o valor):
  pg_column_size(changes) ≤ 65536; char_length(reason) ≤ 1024; char_length(target_id) ≤ 256; char_length(actor_label) ≤ 128;
  profundidade de changes ≤ 16 (verificada ANTES da máscara; a máscara recursiva para nesse limite).
  Bytes \u0000 não chegam ao jsonb (recusa nativa); reason/actor_label/target_id com chr(0) → RAISE PTA02.
Alterações encadeadas: sealed_changes ganha a coluna requires (nome da anterior ou NULL); audit_upgrade recusa se a
  anterior não estiver em _applied. 0011 → NULL, 0012 → 0011_db_user, 0014 → 0012_hardening.
Advisory lock 'ptmarket:audit_seal': passa para uma chave derivada de um segredo? NÃO — documentar o DoS (só atrasa
  migrations; fica no pgaudit) no README e seguir.
```

## Feito quando
- [ ] Tabela de casos: `{"senha":"x"}`, `{"palavra-passe":"x"}`, `{"reset_token_id":"x"}`, `{"key":"password","value":"x"}`, `{"note":"eyJhbGciOi...x.y"}`, `{"notes":["joao@x.pt"]}`, `{"telemóvel":"9"}`, `{"comment":"sk_live_abc"}` → mascarados; `{"store_id":"…"}`, `{"title":"Bolo"}` → em claro
- [ ] changes > 64 KiB, profundidade 17, reason > 1 KiB, reason com chr(0) → PTA02 e nada gravado; a mensagem não contém o valor
- [ ] `audit_upgrade` de uma alteração cuja anterior não foi aplicada → erro; a ordem certa passa
- [ ] `audit_seal()` passa; `run.sh` completo verde

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0
