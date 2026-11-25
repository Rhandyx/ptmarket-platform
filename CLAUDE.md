# PT Market & Loja Portugal (Segjar Soluções)

Rust/Axum/SQLx `backend-rust/` · Go/Asynq `workers-go/` · PostgreSQL 18 `migrations/` · Next.js `frontend-web/` · `infra/`

## Regras inegociáveis
1. Dinheiro nunca em float: cêntimos `BIGINT`/`i64`, percentagens em bps `INT`, `Decimal` em Rust.
2. Multi-tenant: RLS + filtro `tenant_id` + verificação de dono em cada handler (anti-IDOR). Portal nacional só lojas com `publish_to_national_portal`.
3. Segurança ASVS L2 (L3 pagamentos/admin), spec 12. Admin: `super_admin` + 2FA; Data Studio com dry-run + `admin_audit_logs`.
4. UI: nunca `alert()`/`confirm()`/`prompt()`; WCAG 2.2 AA; sem prova em browser real não entra.
5. Omnibus: mudar preço → `product_price_history`. Art. 53.º → IVA 0%.

## Método
- Nova conversa: ler `docs/ESTADO.md` primeiro.
- Épico → `architect-master` escreve cartões em `docs/plans/` → um agente por cartão (lê só o cartão) → `security-auditor` + `ux-reviewer` → supervisor revê o diff.
- Sonnet por defeito; Opus em dinheiro/RLS/stock/auth/webhooks.
- Regras por pasta em `.claude/rules/`; os hooks verificam cada edição.

## Specs `docs/specs/` (ler só a secção necessária)
02 arquitetura e BD · 03 pagamentos, IVA, AT, logística · 04 catálogo IA, templates, mobile · 05 migração e onboarding · 07 backoffices, RBAC, Data Studio · 08 imagens, demo, 2 VPS · 10 pontos cegos · **11 escala, dados, design, W3C** · **12 segurança, domínios** (11 e 12 prevalecem sobre a 02)
