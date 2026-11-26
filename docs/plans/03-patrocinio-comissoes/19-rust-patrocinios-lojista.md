# 19 — Rust: patrocínios, API do lojista (pedir e consultar) (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 14, 18 · **Paralelo com:** — (Rust em série)

## Objetivo
O dono de uma loja pede o patrocínio de uma entidade que cobre a sua freguesia e vê o estado dos seus pedidos; nenhum pedido fica ativo sem aprovação da entidade.

## Pode alterar
- `backend-rust/src/sponsors/{sponsorships,http,mod}.rs`; `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**`; `backend-rust/tests/sponsorships_merchant.rs` (criar)

## Não tocar
- `src/identity/` e `src/tenancy/db.rs` (fechados no 14: só se usam); `src/money/`, `src/payments/`; `src/audit/`; `migrations/`.

## Contexto exato (spec 14 §2, §9)
```
Estados: pending (pedido do lojista ou convite da entidade), active, rejected, expired, revoked. Quem aprova é o sponsor_admin da entidade, no painel. Nenhuma loja fica patrocinada sem aprovação explícita.
Elegibilidade pela morada física (stores.storefront_dicofre): usar sponsors::eligibility::covers (cartão 17) e tenancy::store_terms::commission_terms (cartão 18) para ler o storefront_dicofre da loja.
BD (cartão 06): store_sponsorships(id, tenant_id, store_id, sponsor_entity_id, status, initiated_by, valid_from, valid_to, commission_override_bps, requested_by, decided_by, decided_at, decision_reason, created_at). A app só insere (id, tenant_id, store_id, sponsor_entity_id, initiated_by, requested_by) e a linha nasce 'pending'; há índice único de um pending por par (23505 → 409).
Rotas em PLATFORM_ADMIN_HOST. Transação: begin_store_tx com o scope() do extractor (cartão 14): põe o canal nacional e o GUC app.store_id; a RLS recusa qualquer linha de outra loja mesmo que o handler se engane. id = Uuid::now_v7():
  POST /api/v1/stores/{store_id}/sponsorships — RequireStoreOwner (2FA) — body {"sponsor_entity_id": uuid} (deny_unknown_fields) → 201 {"id","status":"pending"}; initiated_by = 'store', requested_by = utilizador. O corpo NÃO aceita datas, estado nem bps.
    loja sem storefront_dicofre → 422 'store_address_missing' · entidade inexistente, inativa, de outro país ou que não cobre a freguesia → 422 'not_eligible' (resposta igual nos 4 casos) · já existe pending, ou active vigente, para o par → 409 'already_requested' · a loja já tem 10 pending → 409 'too_many_pending'
  GET /api/v1/stores/{store_id}/sponsorships — RequireStoreRole → [{"id","sponsor":{"id","kind","name","slug","logo_key"},"status","valid_from","valid_to","commission_override_bps","created_at","decided_at","decision_reason"}] por created_at DESC, máximo 100. commission_override_bps vai sempre (o lojista tem direito a saber o que paga).
  GET /api/v1/stores/{store_id}/sponsors/eligible — RequireStoreRole → entidades que cobrem a freguesia da loja, na ordem fixa dos selos, cada uma com "already": "none" | "pending" | "active".
Auditoria (AuditCtx obrigatório, na mesma transação): 'sponsorship.requested' (target_type 'store_sponsorship', target_id, store_id; changes com sponsor_entity_id). As recusas 401/403/IDOR já são gravadas pelos extractors; as recusas 422/409 gravam o evento com outcome de falha e o motivo.
Sem dados pessoais nas respostas. O lojista não cancela nem altera um pedido neste épico (fica para o backoffice).
```

## Feito quando
- [ ] `sponsorships_merchant`: o dono pede → 201 `pending` + evento `sponsorship.requested`; repetir → 409; entidade que não cobre a freguesia → 422 e nada gravado
- [ ] **Anti-IDOR no mesmo país:** o dono da loja L1 faz POST e GET em `/stores/{L2}/…` → 404 + `denied`/`idor`; `merchant_staff` no POST → 403; sem 2FA → 403 `mfa_required`
- [ ] **Co-patrocínio:** a mesma loja pede Câmara e Junta → dois `pending` independentes; a lista devolve os dois; `eligible` marca cada um como `pending`
- [ ] Corpo com `status`, `valid_from` ou `commission_override_bps` → 4xx (campo desconhecido); só com `pending`, a loja continua na regra Plan (verificar com `effective_commission_bps`)

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test sponsorships_merchant` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis), que inclui `rbac`, `store_scope`, `commission` e `sponsors_public`
