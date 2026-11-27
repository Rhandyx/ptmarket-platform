# 20 — Rust: patrocínios, API do `sponsor_admin` (aprovar, rejeitar, revogar) (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 19, 16, 11 · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório

## Objetivo
O `sponsor_admin` de uma entidade vê os pedidos e as lojas patrocinadas da sua entidade e aprova, rejeita ou revoga, com tudo na caixa negra e a revogação como evento crítico.

## Pode alterar
- `backend-rust/src/sponsors/{admin,sponsorships,http,mod}.rs` (`admin.rs` criar); `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**`; `backend-rust/tests/sponsorships_admin.rs` (criar)

## Não tocar
- `src/identity/` e `src/tenancy/` (só se usam `RequireSponsorAdmin`, `begin_sponsor_tx` e `tenancy::portal`); `src/money/`, `src/payments/`; `src/audit/`; `migrations/`.

## Contexto exato (spec 14 §2, §3, §7, §9)
```
Aprovação explícita pelo sponsor_admin da entidade. Vigência: valid_from, valid_to (NULL = sem fim). A BD recusa dois períodos active sobrepostos para o mesmo par (EXCLUDE → 23P01 → 409) e transições fora de: pending → active | rejected; active → revoked | expired. Em revoked a BD põe valid_to = agora. commission_override_bps fica 0: a app não o pode escrever.
Se todos os patrocínios cessarem, a loja continua no portal e passa à exceção ou ao plano (aceitou no contrato).
Rotas em PLATFORM_ADMIN_HOST, todas com RequireSponsorAdmin { entity_id } (2FA sempre). Transação: begin_sponsor_tx com o scope() do extractor (cartão 14), no canal nacional do país da entidade (tenant national_portal ativo com o country_code da entidade; se não houver → erro interno): põe o GUC app.sponsor_entity_id.
ANTI-IDOR em duas camadas: CADA query leva `AND sponsor_entity_id = $entity_id`, e a RLS (08b) só deixa ver e alterar patrocínios da entidade do GUC. O sponsor_admin NÃO lê `stores`: os dados da loja vêm de tenancy::portal::stores_by_ids (cartão 16), e o storefront_dicofre para a elegibilidade também.
  GET /api/v1/sponsors/{entity_id}/sponsorships?status=&cursor=&limit= → página por (created_at, id) DESC, cursor opaco, limit ≤ 100: [{"id","status","valid_from","valid_to","store":{"id","name","slug","legal_name","nif","storefront_dicofre"},"requested_at","decided_at"}]
    Da loja só estes campos (os públicos do portal, DSA). NUNCA iban, chaves, comissões, email/telefone, nem dados de compradores (spec 14 §7: as entidades só veem agregados por loja, data, canal e DICOFRE).
  POST …/sponsorships/{id}/approve — body {"valid_from"?: datetime, "valid_to"?: datetime}: valid_from por defeito = agora e nunca anterior a agora − 1 min; valid_to > valid_from. Volta a verificar a elegibilidade (covers) → 422 'not_eligible'. 200 {"id","status":"active","valid_from","valid_to"}
  POST …/sponsorships/{id}/reject — body {"reason": string 1..500} (pending → rejected) · POST …/sponsorships/{id}/revoke — body {"reason": string 1..500} (active → revoked)
  {id} de outra entidade ou inexistente → 404 + Denied("idor"); transição inválida → 409. DTOs com deny_unknown_fields.
Auditoria na mesma transação (AuditCtx): 'sponsorship.approved' / 'sponsorship.rejected' / 'sponsorship.revoked', com target_type 'store_sponsorship', store_id e changes {sponsor_entity_id, valid_from, valid_to, reason}. 'sponsorship.revoked' é kind crítico (cartão 11): o teste confirma que o evento crítico nasce. A listagem é leitura de admin: síncrona na caixa negra (confirmar que a rota fica nessa classe do middleware).
```

## Feito quando
- [ ] `sponsorships_admin`: aprovar um `pending` → `active` + evento `sponsorship.approved`, e `effective_commission_bps` da loja passa a regra Sponsored; rejeitar e revogar com motivo; revogar gera o evento crítico `sponsorship_revoked` e a loja volta ao plano de imediato
- [ ] **Co-patrocínio (Câmara + Junta na mesma loja):** cada sponsor_admin vê a loja na sua lista, uma só vez; o da Câmara não vê nem altera o patrocínio da Junta (`/sponsors/{camara}/sponsorships/{id_da_junta}/revoke` → 404 + `idor`); revogar o da Câmara mantém a loja patrocinada pela Junta (fee 0); só cai para o plano quando ambos cessam
- [ ] sponsor_admin de A em `/sponsors/{B}/…` → 404; sem 2FA → 403; merchant e tenant_admin → 404; aprovar um segundo período sobreposto → 409; `approve` de um `rejected` → 409
- [ ] Nenhuma resposta contém `iban`, `email`, `phone` nem `commission` (teste sobre o JSON); corpo com `commission_override_bps` → 4xx

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test sponsorships_admin` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis), que inclui `sponsorships_merchant`, `commission`, `channels`, `store_scope` e `rbac`

## Adenda do supervisor (auditoria do 14, 27/11)
- **Entidade desativada:** `RequireSponsorAdmin` (cartão 14) só compara o grant com o caminho; não sabe se `sponsor_entities.is_active`. Neste cartão, o módulo `sponsors` (dono da tabela) já lê a entidade para encontrar o canal nacional. Se `is_active = false` → 404 + `Denied("idor")`, antes de qualquer leitura ou escrita de patrocínios. Teste: o sponsor_admin de uma entidade desativada recebe 404 em listar, aprovar, rejeitar e revogar.
- **Canal nacional:** fixar o tenant do `begin_sponsor_tx` a partir da entidade (país → `national_portal` ativo). Nunca vem do pedido.
