-- 0023 — Caixa negra: a máscara da BD deixa de corromper UUIDs dentro de texto (cartão 02/03f).
--
-- Rollback mental (só em dev, como superuser — objeto selado):
--   CREATE OR REPLACE de audit._redact_text com o corpo da '0020_mask_v2' (infra/postgres/init/03-audit-bootstrap.sh);
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0023_mask_uuid';
--   (eventos e alertas gravados ficam como estão; a fórmula do hash não muda.)
--
-- Tudo é a alteração aprovada '0023_mask_uuid' em infra/postgres/init/03-audit-bootstrap.sh (texto exato; o
-- superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256. Exige '0020_mask_v2'
-- aplicada (cadeia linear: sealed_changes.requires).
--   - Bug: a regra do IBAN ("2 letras + 2 dígitos + grupos de 4 com '-'") apanhava 'ac77-73f5-8fa6' no meio de um
--     UUIDv7 ANTES da regra do UUID em claro (que só protegia o valor inteiro): ids de pedido/alvo gravados
--     corrompidos na caixa negra.
--   - Correção (só audit._redact_text; assinatura, dono, grants, IMMUTABLE PARALLEL SAFE e search_path iguais):
--     JWT/chaves e e-mail sobre o texto inteiro; IBAN, NIB, PAN, NIF, DNI/NIE e telefone só nos troços fora dos
--     UUID (8-4-4-4-12 hex, qualquer caixa, entre fronteiras de palavra), como redact_str (Rust) e Redact (Go).
--     Vetores partilhados: docs/testdata/redaction-vectors.json.
-- Stream: um evento gravado antes desta migration e reentregue depois pode dar PTA03 se a máscara nova mudar
--   reason/actor_label (ex.: um UUID que antes saía corrompido): esvaziar o stream antes de migrar em produção
--   (infra/README.md).

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0023: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0023_mask_uuid'::text,
    '643d2b792d24eb5009d8ca6110d3a759bf139abf6daf4db7d318bf6458d64bf1'::text);

SELECT audit_admin.audit_seal();
