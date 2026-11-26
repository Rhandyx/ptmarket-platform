-- 0014 — Caixa negra: máscara PT/EN por chave e por valor, limites de tamanho, alterações encadeadas (cartão 02/03d).
--
-- Rollback mental (só em dev, como superuser — objetos selados):
--   CREATE OR REPLACE de audit._redact_walk, audit._event_content_hash e audit._chain_insert com os corpos da
--   alteração '0012_hardening'; DROP FUNCTION audit._redact_node(text, jsonb, text, integer),
--   audit._redact_text(text), audit._redact_key(text), audit._truncate_leaves(jsonb);
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0014_mask_limits';
--   (os eventos gravados ficam como estão; a fórmula do hash não muda.)
--
-- Tudo é a alteração aprovada '0014_mask_limits' em infra/postgres/init/03-audit-bootstrap.sh (texto exato; o
-- superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256. Exige '0013_ddl_owner_exec'
-- aplicada (cadeia linear: sealed_changes.requires; audit_upgrade recusa fora de ordem).
--   - Máscara: chaves em minúsculas e sem acentos (senha, palavra-passe, chave, telemóvel, contribuinte, morada, …);
--     segredos ANTES da exceção *_id (reset_token_id, secret_id, api_key_id → "[redacted]"); pan só como token
--     (company_id em claro); pares {key|name|field, value}; por valor em todas as strings, reason e actor_label
--     (e-mail → "[pii]", JWT e prefixos de chave de API → "[redacted]", IBAN → ****4 últimos); target_id não.
--   - Limites em _chain_insert (antes da máscara): changes ≤ 64 KiB (octet_length do texto), profundidade ≤ 16,
--     reason ≤ 1024, target_id ≤ 256, actor_label ≤ 128. Eventos da aplicação (audit_append direto,
--     audit_append_event) → PTA02 com mensagem fixa, nada gravado. L1/L2/'db' nunca falham por isto: cortam e
--     marcam (target_id → 180 + '…sha256:<hex>'; reason/actor_label → '…[truncated]'; folhas string > 4096 e,
--     se preciso, changes inteiro → {"truncated": true, "bytes": n, "sha256": hex}; profundidade → "[depth]").
--
-- DESVIO DO CARTÃO (decisão do supervisor): "reason/actor_label/target_id com chr(0) → PTA02" não é possível: o
--   PostgreSQL recusa NUL antes de a função correr (chr(0) → 54000; NUL no protocolo → 22021; \u0000 em jsonb →
--   22P05). Não há verificação no código (seria inatingível); migrations/tests/audit_mask_limits.sql prova a
--   recusa nativa nos quatro campos e que nada fica gravado.

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0014: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0014_mask_limits'::text,
    '4a8bb31a0d2b10ded579373f9c15d5b8ded161f34e3e6f7416557e48e9f44efc'::text);

SELECT audit_admin.audit_seal();
