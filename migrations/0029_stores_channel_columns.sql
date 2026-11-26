-- 0029 — stores: âmbito de entrega, plano de faturação, aceitação do contrato, moradas com DICOFRE e trinco de dinheiro
--   (cartão 03/04; spec 14 §1.1, §3, §4, §5, §6).
-- Rollback mental (só em dev):
--   REVOKE INSERT, UPDATE ON stores FROM ptmarket_app; GRANT INSERT, UPDATE ON stores TO ptmarket_app;  (estado da 0003)
--   COMMENT ON COLUMN stores.address_json / stores.publish_to_national_portal / tenants.default_commission_bps IS NULL;
--   COMMENT ON COLUMN stores.custom_commission_bps IS NULL;
--   DROP INDEX stores_storefront_dicofre_idx;
--   ALTER TABLE stores DROP CONSTRAINT stores_contract_all_or_none, DROP COLUMN shipping_scope, DROP COLUMN billing_plan_code,
--       DROP COLUMN accepted_base_commission_bps, DROP COLUMN terms_version, DROP COLUMN terms_accepted_at,
--       DROP COLUMN fiscal_address, DROP COLUMN storefront_address, DROP COLUMN storefront_dicofre;
--   (os eventos gravados pelos zz_audit_* de stores ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * shipping_scope não esconde a loja: o checkout só oferece o que o âmbito permite.
--   * Contrato: accepted_base_commission_bps, terms_version e terms_accepted_at são os três NULL (lojas de dev antigas)
--     ou os três preenchidos (a aceitação grava-se na transação do registo da loja).
--   * storefront_dicofre: freguesia (6 caracteres; os 2 últimos podem ser letras, ex. 0302FA). Só length() + FK para
--     geo_dicofre (nunca regex de algarismos).
--   * Trinco de dinheiro: ptmarket_app deixa de escrever custom_commission_bps e kyc_verified (e de mudar id, tenant_id,
--     created_at por UPDATE). Grants por coluna tirados de information_schema (inclui as colunas novas); SELECT e
--     DELETE inalterados. ptmarket_portal não recebe nada aqui (cartão 08). Sem tabelas novas: os zz_audit_* de
--     stores continuam a gravar.

-- ---------------------------------------------------------------------------
-- Colunas novas.
-- ---------------------------------------------------------------------------
ALTER TABLE stores
    ADD COLUMN shipping_scope VARCHAR(16) NOT NULL DEFAULT 'national'
        CONSTRAINT stores_shipping_scope_check CHECK (shipping_scope IN ('national', 'local_only', 'pickup_only')),
    ADD COLUMN billing_plan_code VARCHAR(32) NOT NULL DEFAULT 'commission_payg'
        CONSTRAINT stores_billing_plan_code_check CHECK (billing_plan_code IN ('commission_payg', 'tiered_subscription')),
    ADD COLUMN accepted_base_commission_bps INT
        CONSTRAINT stores_accepted_base_commission_bps_check CHECK (accepted_base_commission_bps BETWEEN 0 AND 10000),
    ADD COLUMN terms_version VARCHAR(32),
    ADD COLUMN terms_accepted_at TIMESTAMPTZ,
    ADD COLUMN fiscal_address JSONB NOT NULL DEFAULT '{}', -- faturação
    ADD COLUMN storefront_address JSONB NOT NULL DEFAULT '{}', -- morada física: dá elegibilidade ao patrocínio
    ADD COLUMN storefront_dicofre VARCHAR(6) REFERENCES geo_dicofre (code) ON DELETE RESTRICT
        CONSTRAINT stores_storefront_dicofre_len CHECK (length(storefront_dicofre) = 6),
    ADD CONSTRAINT stores_contract_all_or_none CHECK (
        num_nulls(accepted_base_commission_bps, terms_version, terms_accepted_at) IN (0, 3)
    );

CREATE INDEX stores_storefront_dicofre_idx ON stores (storefront_dicofre);

-- ---------------------------------------------------------------------------
-- Comentários (deprecações e exceção de comissão).
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN stores.address_json IS 'DEPRECADO (spec 14 §5): usar fiscal_address/storefront_address';
COMMENT ON COLUMN stores.publish_to_national_portal IS
    'DEPRECADO (spec 14 §1.1): já não é lido; sai numa migration posterior';
COMMENT ON COLUMN stores.custom_commission_bps IS
    'Exceção negociada; NULL = sem exceção. Só o super_admin a define (auditada). Já NÃO herda do tenant';
COMMENT ON COLUMN tenants.default_commission_bps IS
    'DEPRECADO: a base vem de platform_settings.base_commission_bps';

-- ---------------------------------------------------------------------------
-- Trinco de dinheiro: INSERT/UPDATE de ptmarket_app passam a ser por coluna.
-- ---------------------------------------------------------------------------
REVOKE INSERT, UPDATE ON stores FROM ptmarket_app;

DO $$
DECLARE
    v_insert text;
    v_update text;
BEGIN
    -- As colunas excluídas têm de existir (um nome trocado deixava o trinco aberto sem erro).
    IF (SELECT count(*) FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'stores'
          AND column_name IN ('id', 'tenant_id', 'custom_commission_bps', 'kyc_verified', 'created_at')) <> 5 THEN
        RAISE EXCEPTION '0029: colunas do trinco de stores em falta';
    END IF;

    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) INTO v_insert
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'stores'
      AND column_name NOT IN ('custom_commission_bps', 'kyc_verified');

    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) INTO v_update
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'stores'
      AND column_name NOT IN ('id', 'tenant_id', 'custom_commission_bps', 'kyc_verified', 'created_at');

    EXECUTE format('GRANT INSERT (%s) ON public.stores TO ptmarket_app', v_insert);
    EXECUTE format('GRANT UPDATE (%s) ON public.stores TO ptmarket_app', v_update);
END
$$;
