# 23a — BD: leitura global da caixa negra para a timeline do Super-Admin (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 0024, 09a (índices da timeline na 0015) · **Paralelo com:** — · **Antes de:** 23

> O cartão 23 precisa de ler `audit.audit_events` de todos os tenants, mas a `ptmarket_app` só vê o seu tenant e não pode receber SELECT global. O schema `audit` está selado: tudo passa por uma alteração selada (secção "Caixa negra" do `infra/README.md` e topo da 0008; a última é `0023_mask_uuid`; a 0015 é o exemplo mais parecido, porque também mexe na timeline).

## Objetivo
Uma só função DEFINER devolve uma página da timeline com filtros, o cursor e o estado da cadeia, e só serve a um super_admin com 2FA verificado na sessão.

## Pode alterar
- `infra/postgres/init/03-audit-bootstrap.sh` (texto da alteração selada nova `0025_admin_read_events`); `migrations/0025_audit_admin_read_events.sql`, `migrations/tests/audit_admin_read_events.sql` (criar); `infra/README.md` (uma linha na lista de alterações seladas)

## Não tocar
- `migrations/0001–0024`; `backend-rust/`, `workers-go/`. Nunca ler `.env`.

## Contexto exato
```
audit.admin_read_events(p_from timestamptz, p_to timestamptz, p_tenant_id uuid, p_store_id uuid, p_actor_id uuid,
    p_order_id uuid, p_action_prefix text, p_outcome text, p_cursor_at timestamptz, p_cursor_id uuid, p_limit int)
  RETURNS TABLE (id, created_at, tenant_id, store_id, actor_type, actor_id, actor_label, impersonator_id, action,
    target_type, target_id, outcome, reason, changes, chain_seq, chain_ok boolean)
  SECURITY DEFINER, dono = o dono das funções seladas, SET search_path = pg_catalog, pg_temp, relações qualificadas.
  Validação (RAISE 22023, mensagem fixa): p_from < p_to, janela ≤ 31 dias, 1 ≤ p_limit ≤ 100; p_action_prefix ≤ 100 caracteres e só [a-z0-9._] (é um LIKE prefix: escapar % e _); p_outcome NULL ou um dos valores válidos.
  Porta (RAISE 42501, mensagem fixa), defesa em profundidade além do extractor da app: current_setting('app.actor_type', true) = 'admin' E app.actor_id tem papel super_admin global em public.user_roles E public.users.totp_enabled E a sessão do contexto (o GUC que o AuditCtx/TenantTx já põe; confirmar o nome na 0008/0010) tem mfa_verified_at NOT NULL e não está revogada. Se a sessão não estiver no contexto, recusar.
  order_id: (target_type = 'order' AND target_id = p_order_id) OR changes->>'order_id' = p_order_id::text.
  Ordem e cursor: (created_at, id) DESC; página seguinte = (created_at, id) < (p_cursor_at, p_cursor_id). Nunca OFFSET. Usar os índices da 0015 (EXPLAIN no teste: sem Seq Scan com tenant, loja ou ator).
  changes: já está mascarado na escrita; devolver como está.
  chain_ok: para cada linha, o elo com o anterior da mesma cadeia (prev_hash/content hash, as mesmas regras de audit.audit_verify_chain, sem duplicar a lógica se der para a reutilizar). Fica false se o elo não confere.
  EXECUTE: REVOKE de PUBLIC; GRANT só a ptmarket_app. Pôr o par na lista de grants permitidos da audit_seal.
  A função não grava eventos: a app grava a consulta com audit::record na mesma transação (cartão 23).
```

## Feito quando
- [ ] Contexto de super_admin com 2FA: os filtros por tenant, loja, ator e encomenda devolvem só os eventos certos; 3 páginas pelo cursor sem repetidos nem buracos
- [ ] Contexto `merchant`/`customer`, super_admin sem TOTP, sessão sem `mfa_verified_at` ou revogada, ou sem sessão no contexto → 42501; janela > 31 dias, limit 101, prefixo com `%` → 22023
- [ ] Um evento adulterado em teste (como superuser, com a guarda desligada só no teste) aparece com `chain_ok = false`
- [ ] A cadeia selada continua válida em dev depois da alteração; `run.sh` verde (com a 2.ª passagem L2)

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `audit_admin_read_events`
