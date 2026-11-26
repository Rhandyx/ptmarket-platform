-- 0020 — Caixa negra: máscara v2 (NIF, telefone, PAN, IBAN/NIB), iban_change pela L1 e tolerância explícita
-- (cartão 02/03e).
--
-- Rollback mental (só em dev, como superuser — objetos selados):
--   CREATE OR REPLACE de audit._redact_key, audit._redact_text, audit._redact_node (corpos da '0014_mask_limits'),
--   audit.audit_append (corpo da '0011_db_user'), audit.audit_append_event (corpo da '0012_hardening'),
--   audit.audit_append_db e audit.audit_row_trigger (corpos da 0010); CREATE de audit._chain_insert(audit_events,
--   boolean) com o corpo da '0015_critical_timeline' e DROP FUNCTION audit._chain_insert(audit_events, boolean,
--   boolean); GRANT TEMPORARY ON DATABASE <bd> TO PUBLIC;
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0020_mask_v2';
--   (eventos e alertas gravados ficam como estão; a fórmula do hash não muda.)
--
-- Tudo é a alteração aprovada '0020_mask_v2' em infra/postgres/init/03-audit-bootstrap.sh (texto exato; o
-- superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256. Exige
-- '0015_critical_timeline' aplicada (cadeia linear: sealed_changes.requires).
--   - Máscara v2 (chaves camelCase, PII de identificação antes de *_id, NIB/conta como IBAN, pares e tuplos, e por
--     valor: IBAN em qualquer caixa e separadores, NIB, PAN com Luhn, NIF, DNI/NIE, telefone; UUID/ISO em claro).
--     Vetores partilhados com o Rust e o Go: docs/testdata/redaction-vectors.json.
--   - _chain_insert(p_row, p_dedupe, p_tolerant) é o ÚNICO ponto de máscara; iban_change medido antes da máscara.
--   - Tolerância explícita: audit_append_db → true; audit_append_event → false; audit_append → true só se a
--     linha 2 do PG_CONTEXT for 'PL/pgSQL function audit.audit_(row_trigger|ddl_end|ddl_drop)() line N at
--     assignment' (os três chamam-na com v_ev := …; DESVIO aprovado: um PERFORM corre por SPI e põe antes uma linha
--     'SQL statement "…"' forjável). A de 2 argumentos desaparece (e da allowlist).
--   Rollback também de audit.audit_ddl_end/audit_ddl_drop (corpos da 0013).
--   - REVOKE TEMPORARY ON DATABASE (atual) FROM PUBLIC, ptmarket_app, ptmarket_worker, ptmarket_price_writer.
-- Stream: um evento gravado antes desta migration e reentregue depois pode dar PTA03 se a máscara nova mudar
--   reason/actor_label: esvaziar o stream antes de migrar (infra/README.md).

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0020: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0020_mask_v2'::text,
    '11ddb2a27f1e3c1e3b6e1615bda42acf3937a166cb604761adfb0b0a90cff237'::text);

SELECT audit_admin.audit_seal();
