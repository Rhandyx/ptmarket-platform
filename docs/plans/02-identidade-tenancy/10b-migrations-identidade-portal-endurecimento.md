# 10b — BD: e-mail por verificar, códigos de recuperação de uso único, colunas do portal e `search_path` das `identity_*` (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 03e (numeração 0021), 10, 12, 13, 14 · **Paralelo com:** 09b · **Antes de:** 11b, 20

> Achados 5, 6 e 9 da auditoria ASVS da onda 4 + achado extra da 0019 (códigos de recuperação). Nada aqui mexe em objetos selados de `audit.*`: é uma migration normal. Lê as 0016–0019 para partir dos objetos ATUAIS.

## Objetivo
Mudar o e-mail de um cliente anula a verificação. Um código de recuperação usado nunca volta a servir. Em modo portal, a BD (e não só a app) impede a leitura de colunas sensíveis das lojas de outros tenants. As funções DEFINER de identidade deixam de ter `public` no `search_path`.

## Pode alterar
- `migrations/0021_identity_portal_hardening.sql`, `migrations/tests/identity_portal_hardening.sql` (criar); `migrations/tests/portal.sql` (só as asserções que liam `stores` de outros tenants em modo portal: passam a ler `portal_stores`; listar no relatório)

## Não tocar
- `migrations/0001–0020` — imutáveis; `infra/`, `backend-rust/`, `workers-go/`; nunca ler `.env`. Outros testes existentes: se um contradisser o cartão, parar e reportar

## Contexto exato
```
A. customers (0017): trigger BEFORE UPDATE OF email, FOR EACH ROW. Se NEW.email IS DISTINCT FROM OLD.email e NEW.email_verified_at IS NOT DISTINCT FROM OLD.email_verified_at → NEW.email_verified_at := NULL. (Um fluxo futuro que confirme o e-mail novo no mesmo UPDATE define a coluna e não é anulado; a app não tem UPDATE em email_verified_at.) Função INVOKER, search_path = pg_catalog, pg_temp.
B. user_recovery_codes (0019): hoje a app tem UPDATE (used_at) e consegue repor NULL e reutilizar o código. Trigger BEFORE UPDATE, FOR EACH ROW, para TODOS os papéis: OLD.used_at IS NOT NULL → RAISE com SQLSTATE 23514 e mensagem fixa; NULL → valor: NEW.used_at := now() (a app não escolhe a data); id, user_id, code_hash e created_at nunca mudam. DELETE continua permitido (regenerar a lista).
   Consumo certo (para o cartão 20): UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL → 1 linha; duas transações em paralelo → só uma consome.
C. Portal (0016). O RLS é por linha: com portal_read em stores, a app em modo portal consegue SELECT iban de lojas de outros tenants. Passa a ser: papel ptmarket_portal NOLOGIN, sem SUPERUSER/BYPASSRLS (padrão do ptmarket_identity na 0017), dono da VIEW portal_stores WITH (security_barrier = true), que só tem: id, tenant_id, name, slug, legal_name, nif, email, phone, address_json, geo_lat, geo_lng, business_hours, is_vacation_mode, vacation_message, supports_click_collect, supports_local_courier, supports_national_shipping, vat_exempt_art53.
   NUNCA na view: iban, eupago_split_key, invoicing_credentials_enc, stripe_account_id, custom_commission_bps, kyc_verified, invoicing_provider, shipping_config. (legal_name, NIF, morada e contactos do comerciante são de exibição obrigatória: DSA art. 30.º e DL 7/2004 art. 10.º; vat_exempt_art53 serve a menção do IVA, Art. 53.º.)
   Condição da view = a da policy portal_read de stores na 0016 (app_is_national_portal() AND publish_to_national_portal AND is_active AND tenant ativo do mesmo país). ptmarket_portal: GRANT SELECT só nessas colunas de stores (+ as do filtro) e nas de tenants de que a condição precisa; policy FOR SELECT TO ptmarket_portal em stores.
   DROP POLICY portal_read ON stores (a de ptmarket_app). As policies portal_read de products e product_variants são recriadas com "loja visível" = EXISTS em portal_stores. GRANT SELECT ON portal_stores TO ptmarket_app (sem escrita). tenant_isolation fica como está. Uma view não é tabela: sem bloco L1; confirmar que o teste de cobertura da L1 só conta tabelas. EXPLAIN: produtos por loja em modo portal sem Seq Scan.
D. search_path: identity_customer_credentials(text) (0017), identity_user_credentials(text) (0018), identity_session_lookup(bytea) e identity_passkey_lookup(bytea) (0019) passam a SET search_path = pg_catalog, pg_temp, com TODAS as relações qualificadas (public.…). Mesma assinatura, retorno, dono (ptmarket_identity) e GRANT/REVOKE; usar o padrão da 0017 (GRANT CREATE temporário no schema + REVOKE logo a seguir).
Tabelas novas: nenhuma. Se criares alguma, leva o bloco L1 condicional da 0018 (IF NOT EXISTS zz_audit_row / zz_audit_truncate, ENABLE ALWAYS). Rollback mental no topo da migration.
```

## Feito quando
- [ ] `SET ROLE ptmarket_app`: cliente com e-mail verificado muda o e-mail → `email_verified_at` NULL (e o evento L1 mostra-o); mudar só o nome não o altera
- [ ] Código de recuperação: consumir → `used_at` = now(); repor NULL, mudar a data ou consumir outra vez → 23514; o código de Y continua invisível para X
- [ ] Portal ativo: `SELECT iban` (e cada uma das outras 5 colunas proibidas) `FROM stores` de outro tenant → 0 linhas; `FROM portal_stores` → 42703; `portal_stores` mostra as lojas publicadas de A e B e nenhuma não publicada, inativa ou de outro país; tenant municipal com a flag → 0 linhas de terceiros; produtos e variantes continuam visíveis pela regra do cartão 10
- [ ] As 4 funções têm `proconfig` = `search_path=pg_catalog, pg_temp`, devolvem o mesmo que antes e `ptmarket_worker` continua sem EXECUTE

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `rls.sql`, `portal.sql`, `customers.sql`, `users_rbac.sql`, `sessions.sql`, `omnibus.sql`, `audit_*.sql` (no `run.sh`) · os testes Rust do portal (`tenant_host`, `rls_isolation`) ficam vermelhos até ao cartão 11b: é esperado, não tocar em `backend-rust/`
