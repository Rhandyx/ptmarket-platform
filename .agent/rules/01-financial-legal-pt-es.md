---
trigger: always_on
---
# Conformidade Legal e Financeira PT/ES

1. **Comissões Split:** Fórmula obrigatória `COALESCE(store.custom_commission_bps, tenant.default_commission_bps)`. Aceita `0` bps (0%) para Câmaras Municipais e `500`–`800` bps para portal nacional/nichos.
2. **IVA & Isenção:** Suportar PT (6%, 13%, 23%), ES (4%, 10%, 21%) e Isenção Art. 53.º CIVA (`vat_exempt_art53 = true` -> 0% IVA).
3. **Diretiva Omnibus:** Qualquer atualização de `price_cents` (que vive em `product_variants`, spec 11 D1; IVA em bps, D7) tem de inserir registo em `product_price_history` e recalcular `lowest_price_30d_cents`.
4. **Devoluções Parciais:** Bloquear devolução automática de 14 dias quando `is_perishable = true`. Quando aprovada, estornar no gateway, disparar Nota de Crédito AT no worker Go e reverter pontos em `loyalty_ledger`.
5. **Data Studio Admin:** Exigir role `super_admin` + 2FA, iniciar em Read-Only, executar dry-run transacional (`BEGIN ... ROLLBACK`) antes de escritas SQL e gravar em `admin_audit_logs`.
