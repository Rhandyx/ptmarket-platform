# 11 — BD: kinds críticos de comissão e patrocínio (alteração selada) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 10 · **Paralelo com:** — · **Antes de:** 15 (fecha a BD), 20, 24

## Objetivo
Mudar a comissão base, os escalões, a exceção de uma loja ou revogar um patrocínio gera um evento crítico (alerta imediato Telegram + Discord pelo worker, sem mudar o worker).

## Pode alterar
- `infra/postgres/init/03-audit-bootstrap.sh` (texto da alteração selada nova `0037_critical_kinds_commission`); `migrations/0037_audit_critical_kinds_commission.sql`, `migrations/tests/audit_critical_commission.sql` (criar); `infra/README.md` (uma linha na lista de alterações seladas)

## Não tocar
- `migrations/0001–0036`; as outras funções de `audit.*`; `workers-go/` (os kinds novos seguem o caminho dos existentes); `backend-rust/`. Nunca ler `.env`.

## Contexto exato (spec 14 §9 + 0015)
```
O schema audit está selado: tudo passa por uma alteração selada. Ler ANTES de escrever: o topo da 0008 e a secção "Caixa negra" do infra/README.md (alteração selada → audit_upgrade → audit_seal()). Exemplo mais parecido: a 0015 ('0015_critical_timeline'), que criou audit.critical_kind; a última alteração selada é '0026_admin_read_events_v2'.
Kinds críticos (alerta imediato): mudança de base_commission_bps, de escalões, de custom_commission_bps e revogação de patrocínio.
audit.critical_kind(p_action text, p_outcome text, p_actor_type text) RETURNS text (INVOKER, IMMUTABLE; EXECUTE só para ptmarket_audit_writer) devolve hoje 'iban_change', 'payment_failure', 'invoice_failure', 'superadmin_login', 'verify_failure'. Acrescentar, sem mudar os ramos existentes nem a assinatura:
  'platform_settings.update' → 'commission_base_change' · 'billing_plan_tiers.insert' | '.update' | '.delete' → 'billing_tiers_change' · 'store.commission_override' → 'store_commission_override' · 'sponsorship.revoked' → 'sponsorship_revoked'
Confirmar na 0010 o formato exato das ações que a L1 gera ('<tabela>.<operação>') e usar esse formato; se a L1 der outro nome ao TRUNCATE de billing_plan_tiers, incluí-lo. Só contam eventos com outcome de sucesso, como nos ramos atuais.
Origem: as duas primeiras nascem da L1 (qualquer ator, incluindo o migrator: é o que se quer). 'sponsorship.revoked' é gravada pela app (cartão 20). 'store.commission_override' será gravada pela função do super_admin (épico de backoffice); até lá a app não consegue escrever a coluna (cartão 04) e uma mudança pelo migrator fica na L1 como 'stores.update'.
Regras: nenhuma DEFINER de audit.* lê public; critical_kind continua INVOKER e IMMUTABLE (sem ler tabelas). Seguir à letra o processo da 0015/0023/0026: texto no bootstrap + migration que o aplica + grants na lista permitida do audit_seal, se mudarem. Nunca SET ROLE para um papel sem acesso a audit.
Depois de mexer no bootstrap, em dev: 1) reaplicá-lo como superuser, 2) sqlx migrate run, 3) event-triggers.sql (se faltarem).
Agrupamento (decisão 2 do owner): estes 4 kinds seguem a regra geral (> 5 do mesmo kind/tenant em 5 min → resumo).
```

## Feito quando
- [ ] Teste `audit_critical_commission`: UPDATE de `platform_settings.base_commission_bps` e INSERT/UPDATE/DELETE em `billing_plan_tiers` (como migrator) geram o evento crítico com o kind certo; um `sponsorship.revoked` e um `store.commission_override` de sucesso também; os mesmos com outcome `denied` não
- [ ] Os 5 kinds antigos devolvem o mesmo que antes (tabela de regressão no teste); um `stores.update` simples não é crítico
- [ ] A cadeia selada continua válida em dev depois da alteração; `audit_seal` verde; `run.sh` verde com a 2.ª passagem L2

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `audit_critical_commission`, `audit_critical`, `audit_seal`

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suites completas verdes: `cd workers-go && go test -race ./...` e `cargo test -p ptmarket-api` (com o `DATABASE_URL`/`REDIS_URL` de dev)
