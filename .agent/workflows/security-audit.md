---
description: Auditoria completa de isolamento Multi-Tenant, segurança financeira e conformidade.
---
1. Inspeciona todas as queries SQL em `/backend-rust` e `/workers-go` para detetar ausência de filtro `tenant_id` ou de contexto RLS.
2. Procura ocorrências proibidas de `.unwrap()`, `.expect()`, `f32`, `f64` em lógica financeira.
3. Verifica validação HMAC em webhooks Eupago/Stripe e proteção 2FA em `/api/v1/superadmin/*`.
4. Gera um relatório classificado por severidade (Crítico / Alto / Médio) sem alterar ficheiros antes da aprovação.
