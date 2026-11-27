-- 0034 — tiered_subscription passa a mensalidade 100% fixa por escalão de volume mensal, 0% de comissão em todos os
-- escalões (decisão do owner, 27/11/2026; spec 14 §4). Protege o retalho de margem curta (informática,
-- eletrodomésticos). commission_payg não muda (0 €/mês; 8% até 20.000 € e 6% só no excedente).
-- Rollback mental (só em dev):
--   DELETE FROM billing_plan_tiers WHERE plan_code = 'tiered_subscription'; e voltar a inserir as 5 linhas do seed da
--   0032 (na mesma transação: o constraint trigger diferido só valida no COMMIT).
--
-- Regras:
--   * Só dados; nenhuma estrutura muda. O cálculo marginal (money::effective_commission) continua igual: com 0 bps
--     em todos os escalões, a fee do plano é sempre 0. Planos híbridos futuros (mensalidade + bps) continuam possíveis.
--   * DELETE + INSERT do plano numa só transação (sqlx): EXCLUDE imediato (as linhas antigas já saíram);
--     billing_plan_tiers_contiguous (DEFERRABLE INITIALLY DEFERRED) valida o plano no COMMIT.
--   * Corre como o migrator (policy migrator_all). Caixa negra L1: cada linha apagada e inserida fica em
--     audit_events (billing_plan_tiers.delete / .insert, ator 'db').
--   * O escalão cobre o volume mensal em ]gmv_from_cents, gmv_to_cents]; a mensalidade é a do escalão atingido no
--     fim do mês (money::monthly_fee_for). Há degraus de mensalidade entre escalões (por desenho).

DELETE FROM billing_plan_tiers WHERE plan_code = 'tiered_subscription';

INSERT INTO billing_plan_tiers (plan_code, gmv_from_cents, gmv_to_cents, monthly_fee_cents, marginal_commission_bps)
VALUES
    ('tiered_subscription', 0, 100000, 500, 0),               --          até 1.000 €:   5 €/mês
    ('tiered_subscription', 100000, 500000, 1000, 0),         --  1.000,01–5.000 €:     10 €/mês
    ('tiered_subscription', 500000, 1000000, 5000, 0),        --  5.000,01–10.000 €:    50 €/mês
    ('tiered_subscription', 1000000, 2500000, 10000, 0),      -- 10.000,01–25.000 €:   100 €/mês
    ('tiered_subscription', 2500000, 5000000, 17500, 0),      -- 25.000,01–50.000 €:   175 €/mês
    ('tiered_subscription', 5000000, 10000000, 30000, 0),     -- 50.000,01–100.000 €:  300 €/mês
    ('tiered_subscription', 10000000, NULL, 50000, 0);        --     acima de 100.000 €: 500 €/mês
