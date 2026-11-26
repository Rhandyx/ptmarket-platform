-- 0015 — Caixa negra: eventos críticos (alerta + WORM) e índices da timeline do Super-Admin (cartão 02/09a).
--
-- Rollback mental (só em dev, como superuser — objetos selados):
--   CREATE OR REPLACE de audit._chain_insert e audit.audit_alerts_guard com os corpos das alterações
--   '0014_mask_limits' e 0008; ALTER TABLE audit.audit_alerts DROP COLUMN kind;
--   DROP INDEX audit.audit_events_store_created_idx, audit.audit_events_actor_created_idx,
--   audit.audit_events_order_created_idx; DROP FUNCTION audit.critical_kind(text, text, text);
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0015_critical_timeline';
--   (eventos e alertas gravados ficam como estão; a fórmula do hash não muda.)
--
-- audit.critical_kind é função nova (INVOKER, IMMUTABLE): nasce aqui, ANTES do audit_upgrade, e a selagem
-- passa-a para ptmarket_audit_owner (o migrator fica sem privilégios). Mudar a lista = nova alteração aprovada.
-- O resto é a alteração aprovada '0015_critical_timeline' em infra/postgres/init/03-audit-bootstrap.sh (texto
-- exato; o superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256. Exige
-- '0014_mask_limits' aplicada (cadeia linear: sealed_changes.requires).
--   - audit_alerts.kind (NULL = não crítico); o guard passa a recusar alterações a kind.
--   - _chain_insert (o da 0014) insere em audit_alerts quando actor_type = 'admin', impersonator_id não nulo ou
--     critical_kind(...) não nulo: event_type 'audit.critical' + kind, ou 'audit.superadmin_action' com kind
--     NULL. Payload = linha já mascarada; kind 'iban_change' sem changes nem reason (o IBAN nunca, nem mascarado).
--   - Índices da timeline em audit.audit_events: (store_id, created_at), (actor_id, created_at) e
--     ((changes->>'order_id'), created_at) WHERE changes ? 'order_id'. Tenant e encomenda por
--     (target_type, target_id, created_at) já existiam (0008).

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0015: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
END
$$;

-- Lista fixa (NULL = não crítico). Prefixos com starts_with; ações exatas com =.
CREATE FUNCTION audit.critical_kind(p_action text, p_outcome text, p_actor_type text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT CASE
        WHEN starts_with(p_action, 'stores.iban')
             OR starts_with(p_action, 'payout_accounts.')
             OR starts_with(p_action, 'merchants.iban')
            THEN 'iban_change'
        WHEN ((starts_with(p_action, 'payments.') OR starts_with(p_action, 'refunds.')) AND p_outcome = 'error')
             OR p_action = 'payments.failed'
            THEN 'payment_failure'
        WHEN (starts_with(p_action, 'invoices.') AND p_outcome = 'error')
             OR p_action = 'invoices.failed'
            THEN 'invoice_failure'
        WHEN p_action = 'auth.login' AND p_actor_type = 'admin'
            THEN 'superadmin_login'
        WHEN p_action = 'audit.verify_failed'
            THEN 'verify_failure'
    END
$$;

REVOKE ALL ON FUNCTION audit.critical_kind(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.critical_kind(text, text, text) TO ptmarket_audit_writer;

SELECT audit_admin.audit_upgrade(
    '0015_critical_timeline'::text,
    'fbcb808aab137447b632b42dc907c33a24ea981bb733cba20e353b08caf575f6'::text);

SELECT audit_admin.audit_seal();
