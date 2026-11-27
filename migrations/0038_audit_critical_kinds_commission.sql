-- 0038 — Caixa negra: kinds críticos de comissão e patrocínio; âmbito por loja na leitura de audit.audit_events
--   (cartão 03/11 + adenda do supervisor; spec 14 §9).
--
-- Rollback mental (só em dev, como superuser — objetos selados):
--   CREATE OR REPLACE de audit.critical_kind com o corpo da 0015 (migrations/0015_audit_critical_timeline.sql);
--   ALTER TABLE audit.audit_alerts DROP CONSTRAINT audit_alerts_kind_check, ADD CONSTRAINT audit_alerts_kind_check
--     CHECK (kind IN ('iban_change', 'payment_failure', 'invoice_failure', 'superadmin_login', 'verify_failure'))
--     (falha se já houver alertas com os kinds novos: a caixa negra é só de acréscimo, ficam);
--   DROP POLICY store_scope_read ON audit.audit_events;
--   DELETE FROM audit_admin.sealed_changes_applied WHERE name = '0038_critical_kinds_commission'.
--
-- Tudo é a alteração aprovada '0038_critical_kinds_commission' em infra/postgres/init/03-audit-bootstrap.sh (texto
-- exato; o superuser aplica o bootstrap antes desta migration), disparada aqui por nome + sha256. Exige
-- '0026_admin_read_events_v2' aplicada (cadeia linear: sealed_changes.requires).
--   - audit.critical_kind (mesma assinatura, INVOKER, IMMUTABLE; EXECUTE só do writer): 4 kinds novos, só com
--     outcome 'success': platform_settings.insert|update|delete|truncate → commission_base_change;
--     billing_plan_tiers.insert|update|delete|truncate → billing_tiers_change (nomes da L1, 0010:
--     '<tabela>.<operação>'); store.commission_override →
--     store_commission_override; sponsorship.revoked → sponsorship_revoked. Os 5 ramos antigos ficam iguais.
--     O worker não muda: os kinds novos seguem a regra geral de agrupamento (> 5 do mesmo kind/tenant em 5 min).
--   - audit_alerts_kind_check com os 4 kinds novos.
--   - Policy store_scope_read (RESTRICTIVE, FOR SELECT, TO ptmarket_app) em audit.audit_events, fechada como a 0035:
--     USING (store_id = <app_store_id> OR <app_is_platform_admin>). A app só lê os eventos da loja de app.store_id
--     (os sem store_id do tenant ficam de fora), exceto o ator admin sem impersonação; sem âmbito de loja nem admin,
--     0 linhas (substitui o "sem app.store_id vê o tenant" da adenda; decisão da auditoria do cartão 11). As expressões DUPLICAM public.app_store_id() e public.app_is_platform_admin()
--     (0035), escritas só com pg_catalog: a audit_seal recusa dependências de audit.* para objetos de papéis com
--     LOGIN (o migrator é dono das funções de public). Equivalência provada em tests/audit_critical_commission.sql;
--     app.store_id que não é uuid dá 22P02, como app_store_id(). Quando a app_is_platform_admin passar a DEFINER com
--     a porta da 0026 (dívida do 08b), esta policy selada tem de ser atualizada numa alteração selada nova.
-- Na BD de dev: reaplicar o bootstrap (como superuser) ANTES desta migration (infra/README.md, "Caixa negra").

DO $$
BEGIN
    IF to_regprocedure('audit_admin.audit_upgrade(text,text)') IS NULL
       OR NOT has_function_privilege(to_regprocedure('audit_admin.audit_upgrade(text,text)'), 'EXECUTE') THEN
        RAISE EXCEPTION '0038: falta audit_admin.audit_upgrade (reaplicar infra/postgres/init/03-audit-bootstrap.sh como superuser)';
    END IF;
    IF to_regprocedure('audit.critical_kind(text,text,text)') IS NULL THEN
        RAISE EXCEPTION '0038: falta audit.critical_kind (aplicar a 0015 primeiro)';
    END IF;
END
$$;

SELECT audit_admin.audit_upgrade(
    '0038_critical_kinds_commission'::text,
    '3284c8b090732ebe1bfa467de6fd9c12e6d522cd24a2d2fd25f6730f775ef64d'::text);

SELECT audit_admin.audit_seal();
