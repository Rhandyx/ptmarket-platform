# 03e — Caixa negra: máscara v2 (NIF, telefone, PAN, IBAN/NIB), `iban_change` pela L1 e tolerância explícita (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 09a, 14 (numeração 0020) · **Paralelo com:** — · **Antes de:** 10b, 09b, 11b

> Achados 1, 2, 3, 8 e 13 da auditoria ASVS da onda 4. Lê a secção "Caixa negra" de `infra/README.md` e a alteração aprovada `0015_critical_timeline` no bootstrap. Objetos selados só mudam pela alteração aprovada `0020_mask_v2` (`requires` = `0015_critical_timeline`), disparada na 0020 por `audit_admin.audit_upgrade(nome, sha256)`; a 0020 termina com `audit_admin.audit_seal()`. Parte dos corpos ATUAIS (`_redact_key`, `_redact_text`, `_redact_node` da 0014; `_chain_insert` da 0015; `audit_append` da 0011; `audit_append_db` e `audit_row_trigger` da 0010).

## Objetivo
Nenhum NIF, telefone, PAN, IBAN ou NIB entra em claro na caixa negra, venha por chave camelCase, par etiquetado, tuplo ou só pelo valor. Mudar o IBAN de uma loja por SQL direto gera o alerta crítico `iban_change`. O caminho tolerante dos limites deixa de poder ser forjado.

## Pode alterar
- `migrations/0020_audit_mask_v2.sql`, `migrations/tests/audit_mask_v2.sql`, `docs/testdata/redaction-vectors.json` (criar); `infra/postgres/init/03-audit-bootstrap.sh` (alteração aprovada + allowlist da `audit_seal`); `migrations/tests/run.sh` (só para passar o JSON dos vetores ao psql como variável: os testes entram por stdin no contentor); `infra/README.md`

## Não tocar
- `migrations/0001–0019`; `backend-rust/`, `workers-go/`; nunca ler `.env`. Testes existentes: só onde criarem objetos temporários com um papel da app (TOLERÂNCIA) — listar cada alteração no relatório; qualquer outra contradição: parar e reportar

## Contexto exato
```
CHAVES (_redact_key). Normalizar por esta ordem: regexp_replace(k,'([a-z0-9])([A-Z])','\1_\2','g') → translate dos acentos → lower (taxId → tax_id, cardPan → card_pan). ANTES da exceção _id$ → 'pii': (tax|vat|fiscal|national|citizen|taxpayer|social.?security)[_-]?(id|number|no|num|code)$, niss, dni, nie, cif. 'pii' acrescenta mobile, cell, whatsapp. Classe 'iban' acrescenta (^|[_-])nib($|[_-]), account.?number, bank.?account, numero.?conta. Segredos continuam primeiro (card_pan cai no token pan); store_id, order_id, company_id continuam em claro.
PARES E TUPLOS (_redact_node). Etiquetas: key|name|field|path|label|type|k; valor em value|v|val; em path classifica-se o último segmento (separadores . / [ ]). Array com exatamente 2 elementos, [0] string de classe secret/iban/pii e [1] escalar → [1] mascarado por essa classe (["nif","123456789"]).
VALORES (_redact_text), por esta ordem: marcadores já postos → iguais; JWT/chaves de API → "[redacted]"; e-mail → "[pii]"; IBAN no sítio (****4 últimos) em qualquer caixa, aceitando entre grupos espaço(s), NBSP (U+00A0), "-" e "."; NIB PT = 21 dígitos (mesmos separadores) sem PT50, só com os 2 dígitos de controlo certos (98 − (19 primeiros × 100 mod 97)) → ****4 últimos; string que é só um UUID ou só uma data/hora ISO → devolvida como está (um UUID só de dígitos passaria no Luhn);
  depois: PAN de 13–19 dígitos (espaço ou "-" entre eles) com Luhn válido → "[redacted]"; NIF PT: 9 dígitos entre fronteiras de palavra (prefixo "PT" opcional), 1.º ≠ 0, dígito de controlo módulo 11 (pesos 9..2; resto < 2 → 0, senão 11 − resto) → "[pii]"; DNI/NIE ES: 8 dígitos + letra, ou X/Y/Z + 7 dígitos + letra, letra = 'TRWAGMYFPDXBNJZSQVHLCKE'[n mod 23] (X=0, Y=1, Z=2) → "[pii]" (RGPD nos tenants ES);
  telefone: E.164 ("+" ou "00" + 8–15 dígitos, separadores espaço . - ( )) e PT nacional de 9 dígitos a começar por 2 ou 9, com ou sem grupos de 3 → "[pii]". Continua IMMUTABLE e idempotente (mascarar duas vezes = mascarar uma). target_id continua sem máscara.
IBAN_CHANGE (_chain_insert, medido ANTES da máscara): existe uma chave k de classe 'iban' em changes->'before' ∪ changes->'after' com (before->k) IS DISTINCT FROM (after->k) e after->k não nulo (UPDATE e INSERT contam; DELETE não) → kind = 'iban_change', com prioridade sobre critical_kind(...). A action NÃO muda (stores.update); o payload do alerta continua sem changes nem reason.
  ARMADILHA: hoje audit_row_trigger (ramo app, 0010:170) e audit_append_db (0010:97) chamam audit_redact ANTES, e o IBAN chega como ****1234 (dois IBAN com os mesmos 4 últimos pareciam iguais). Passam a entregar changes em cru: _chain_insert é o ÚNICO ponto de máscara (já mascara em todos os caminhos). Provar que nada em cru chega a audit_events, audit_alerts nem a mensagens de erro.
TOLERÂNCIA: _chain_insert(p_row, p_dedupe, p_tolerant boolean); a de 2 argumentos desaparece (allowlist; sem sobrecargas) e deixa de haver pg_trigger_depth() lá dentro. audit_append_db → true (EXECUTE só do migrator); audit_append_event → false; audit_append → true só se a linha do chamador imediato em PG_CONTEXT for, inteira e ancorada (^…$), "PL/pgSQL function audit.audit_(row_trigger|ddl_end|ddl_drop)() line N at PERFORM".
  Porquê: a app tem EXECUTE em audit_append, por isso um parâmetro público seria forjável; ninguém cria funções em audit.* (selagem) nem, a partir de agora, em pg_temp: REVOKE TEMPORARY ON DATABASE <atual> FROM PUBLIC, ptmarket_app, ptmarket_worker, ptmarket_price_writer (o migrator é dono da BD e mantém). Se o Rust ou o Go usarem tabelas temporárias (grep só de leitura): parar e reportar.
VETORES (docs/testdata/redaction-vectors.json; lido pelos testes da BD, do Rust e do Go; os cartões 09b e 11b NÃO o editam): lista de {"id","kind":"text"|"json","input","must_not_contain":[…],"must_equal_input":bool,"layers":["db","rust","go"]}. Cobre os casos de "Feito quando" + os do 03d. Valores sintéticos com dígitos de controlo válidos, nunca dados reais. Casos "em claro" que só a BD garante (dígito de controlo errado, sem Luhn) levam layers ["db"].
```

## Feito quando
- [ ] Mascarados: `tax_id`, `vat_id`, `national_id`, `taxId`, `vatNumber`, `mobile`, `nib`, `accountNumber`, `cardPan`; `{"path":"billing.taxId","value":…}`, `{"k":"nif","v":…}`, `["nif","…"]`; sob chave neutra: NIF válido, DNI válido, `+351 912 345 678`, PAN com Luhn, IBAN em minúsculas, com `-`, `.`, NBSP e espaços duplos, NIB de 21 dígitos
- [ ] Em claro: `store_id`, UUID só de dígitos, data/hora ISO, 9 dígitos com dígito de controlo errado, 16 dígitos sem Luhn, `{"title":"Bolo"}`; a segunda passagem da máscara não altera nada; o teste corre todos os vetores com `db` em layers
- [ ] `UPDATE stores SET iban` (app com ator e migrator) → evento `stores.update` + 1 linha em `audit_alerts` com kind `iban_change` e sem IBAN, mesmo quando os 4 últimos dígitos coincidem; UPDATE de outra coluna → sem `iban_change`
- [ ] `ptmarket_app`: `CREATE TEMP TABLE` → 42501; `audit_append` com changes > 64 KiB chamado de um bloco DO → PTA02 e nada gravado; L1, L2 e `db` acima do limite continuam a gravar (cortado); `audit_upgrade` fora de ordem falha; `audit_seal()` passa

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `audit_*.sql`, `customers.sql`, `users_rbac.sql`, `sessions.sql` (no `run.sh`) · reentrega do stream: um evento gravado antes da 0020 e reentregue depois pode dar PTA03 se a máscara nova mudar `reason`/`actor_label` — documentar no `infra/README.md` (esvaziar o stream antes de migrar)
