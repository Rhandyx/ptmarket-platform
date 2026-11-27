# 10 — BD: funções `identity_admin_verification_*` para a revisão pelo super_admin (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 09 · **Paralelo com:** — · **Auditoria:** security-auditor obrigatório (ASVS L3)

## Objetivo
Três funções DEFINER deixam um super_admin com 2FA verificado listar as verificações, obter a chave do ficheiro ou o código cifrado, e decidir; mais ninguém as consegue usar.

## Pode alterar
- `migrations/0037_identity_admin_verifications.sql`, `migrations/tests/identity_admin_verifications.sql` (criar)

## Não tocar
- `migrations/0001–0036`; `audit.*` e `infra/postgres/init/` (nenhuma função de `audit` muda: não há alteração selada). Nunca ler `.env`.

## Contexto exato
```
Porquê: o super_admin trabalha em admin.ptmarket.pt sem tenant nem loja no contexto, e a ptmarket_app só vê store_verifications do tenant e da loja do contexto. Como na timeline (0025/0026), a leitura e a decisão globais passam por funções DEFINER de identidade com porta própria.
Padrão identity_* (copiar da 0026, identity_admin_read_events): SECURITY DEFINER, dono ptmarket_identity, SET search_path = pg_catalog, pg_temp, relações qualificadas com public., REVOKE ALL FROM PUBLIC, GRANT EXECUTE só a ptmarket_app. Criar como migrator e ALTER FUNCTION … OWNER TO ptmarket_identity (GRANT CREATE ON SCHEMA só durante o ALTER, como na 0018). Nunca SET ROLE ptmarket_identity (não tem acesso a audit: lição L2). Estas funções NÃO chamam audit.* (e nenhuma DEFINER de audit.* lê public).
Porta (RAISE 42501, mensagem fixa), igual à da 0026: session_user = 'ptmarket_app'; app.actor_type = 'admin'; app.actor_id tem super_admin global em public.user_roles; public.users.totp_enabled; a sessão do GUC app.session_id é de plataforma, tem mfa_verified_at NOT NULL e não está revogada. Sem sessão no contexto → recusar.
identity_admin_verifications_list(p_status text, p_cursor_at timestamptz, p_cursor_id uuid, p_limit int) RETURNS TABLE (id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file boolean, has_access_code boolean, sha256, created_at, reviewed_at, delete_after)
  p_status NULL ou um dos 3 estados; 1 ≤ p_limit ≤ 100; ordem (created_at, id) ASC com cursor; nunca OFFSET; erros de validação 22023. NUNCA devolve storage_key, access_code_enc, iban nem outras colunas da loja.
identity_admin_verification_secret(p_id uuid) RETURNS TABLE (tenant_id, store_id, storage_key text, sha256 bytea, access_code_enc text) — a linha se existir (storage_key e access_code_enc podem vir NULL); a BD nunca decifra (não tem a chave).
identity_admin_verification_decide(p_id uuid, p_approve boolean, p_reason text) RETURNS TABLE (tenant_id, store_id, status, delete_after)
  só se status = 'pending' (senão 0 linhas); grava status, reviewed_by = app.actor_id, reviewed_at = now(), review_reason (obrigatório na rejeição; ≤ 500), delete_after = now() + interval '30 days' se houver ficheiro. NÃO mexe em stores.kyc_verified (regra de ativação da loja: épico de onboarding).
Grants mínimos a ptmarket_identity: SELECT nas colunas lidas de store_verifications e de stores (id, tenant_id, name, legal_name, nif); UPDATE (status, reviewed_by, reviewed_at, review_reason, delete_after) em store_verifications; policies FOR SELECT e FOR UPDATE TO ptmarket_identity. A L1 grava o UPDATE; o evento nomeado é gravado pela app (cartão 23).
```

## Feito quando
- [ ] Contexto de super_admin com 2FA: lista pendentes de 2 lojas do mesmo país com cursor (3 páginas, sem repetidos); `decide` aprova e rejeita; `delete_after` = decisão + 30 dias; decidir duas vezes → 0 linhas
- [ ] Contexto `merchant`, `municipal` (sponsor_admin), super_admin sem TOTP, sessão sem `mfa_verified_at` ou revogada, sem sessão, ou `session_user` ≠ `ptmarket_app` → 42501 nas três
- [ ] `proacl`, `prosecdef` e `proconfig` das três verificados no teste (só `ptmarket_app` executa; `search_path` fixo)
- [ ] `limit` 0 e 101, estado inválido, rejeição sem motivo → 22023

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `identity_admin_verifications` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `audit_admin_read_events_v2`, `identity_portal_hardening`, `customers_insert_role_guards` no `run.sh`; suites completas verdes: `cargo test -p ptmarket-api` e `go test -race ./...`
