# 23 — Rust: verificação da loja, revisão pelo super_admin (lista, URL assinado, código, decisão) (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 22, 10 · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório (ASVS L3)

## Objetivo
Um super_admin com 2FA lista as verificações pendentes de todos os canais, abre o documento por um URL assinado de 5 minutos ou vê o código decifrado, e aprova ou rejeita; cada passo fica na caixa negra.

## Pode alterar
- `backend-rust/src/admin/verifications.rs` (criar); `src/admin/mod.rs`, `src/http/{mod,openapi}.rs`, `openapi.json`; `backend-rust/tests/verifications_review.rs` (criar)

## Não tocar
- `src/storage*`, `src/identity/` (a decifra usa a API exposta no 22), `src/audit/`, `src/tenancy/`, `src/admin/audit_timeline.rs` (aprovado; serve de exemplo), `migrations/`.

## Contexto exato (spec 14 §6, §9 + cartão 10)
```
Ficheiros acessíveis só por URL assinado de 5 min, gerado por um super_admin em revisão e auditado. O ficheiro é apagado até 30 dias depois da decisão (job do worker, cartão 25); o hash e os metadados ficam (prova). O código da Certidão Permanente está cifrado (AES-256-GCM 'v1:<kid>', VERIFICATION_ENC_KEY, AAD = id da verificação): só se decifra a pedido e com registo.
BD (cartão 10), funções DEFINER com porta própria (super_admin + TOTP + sessão de plataforma com 2FA; senão 42501):
  identity_admin_verifications_list(p_status text, p_cursor_at timestamptz, p_cursor_id uuid, p_limit int) → (id, tenant_id, store_id, store_name, store_legal_name, store_nif, kind, status, has_file, has_access_code, sha256, created_at, reviewed_at, delete_after)
  identity_admin_verification_secret(p_id uuid) → (tenant_id, store_id, storage_key, sha256, access_code_enc); 0 linhas se não existir
  identity_admin_verification_decide(p_id uuid, p_approve boolean, p_reason text) → (tenant_id, store_id, status, delete_after); 0 linhas se não existir ou já estiver decidida
Regra Rust: funções identity_* com query_as estático + cast de tipo exato em cada argumento e coluna (exceção aprovada). Transação: begin_platform_tx com AuditCtx (o GUC app.session_id já é posto pelo PlatformTx).
Rotas sob /api/v1/superadmin/ (o gate existente dá 404 uniforme a quem não é super_admin com 2FA; manter):
  GET /api/v1/superadmin/verifications?status=pending&cursor=&limit= → página com cursor opaco, limit ≤ 100: [{"id","store":{"id","name","legal_name","nif"},"kind","status","has_file","has_access_code","sha256_hex","created_at","reviewed_at","delete_after"}] (leitura síncrona na caixa negra; nunca traz o código)
  POST /api/v1/superadmin/verifications/{id}/url → 200 {"url","expires_at"} com state.private_storage.signed_url(storage_key, 300 s); sem ficheiro ou id inexistente → 404. Grava 'store_verification.url_issued'.
  POST /api/v1/superadmin/verifications/{id}/access-code → 200 {"access_code"} decifrado, com Cache-Control: no-store; sem código ou id inexistente → 404; falha de decifra → erro interno sem detalhe. Grava 'store_verification.code_viewed'.
    Nos dois: o evento é gravado na MESMA transação, ANTES de devolver o segredo (se a auditoria falhar, não há resposta). O URL, o storage_key e o código nunca vão para logs nem para o evento.
  POST …/{id}/approve — body {"reason"?: string ≤ 500} · POST …/{id}/reject — body {"reason": string 1..500} → 200 {"id","status","delete_after"}; 0 linhas da função → 409 'not_pending'.
    Grava 'store_verification.approved' / 'store_verification.rejected' com target_id, store_id e o tenant_id da loja (para aparecer na timeline da loja). NÃO altera stores.kyc_verified. Erro 42501 vindo da BD → 404 uniforme + denied; nunca 500 nem a mensagem da BD. DTOs com deny_unknown_fields.
```

## Feito quando
- [ ] `verifications_review`: super_admin com 2FA lista pendentes de 2 lojas em páginas; emite o URL e o PDF servido (rota do cartão 21) tem o `sha256` da BD; vê o código decifrado de uma empresa; aprova uma e rejeita outra com motivo; `delete_after` = decisão + 30 dias
- [ ] Eventos `store_verification.url_issued`, `.code_viewed`, `.approved`, `.rejected` com o ator e a loja certos; nenhum contém o URL, o `storage_key` ou o código
- [ ] merchant, sponsor_admin, tenant_admin, super_admin sem 2FA e pedido num Host de canal → 404 em todas as rotas, com `denied`; decidir duas vezes → 409; `reject` sem motivo → 4xx; `/url` sem ficheiro e `/access-code` sem código → 404 e sem evento

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test verifications_review` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis), que inclui `admin_timeline`, `totp`, `verifications_submit` e `private_storage`

## Adenda do supervisor (auditoria do 09/10, 27/11)
- **Leituras e decisão com evento nomeado, síncrono (spec 13):** `identity_admin_verification_secret` não grava nada, e o L1 do `decide` fica com ator `db` / `ptmarket_app`, sem `actor_id` (o revisor só aparece em `reviewed_by`, dentro de `changes`). A app grava `admin.store_verification.secret_read` (antes de devolver o URL assinado ou o código) e o evento da decisão **na mesma transação** da chamada à DEFINER; se a gravação falhar → 503 e nada sai. Teste: com o append a falhar, nem o URL nem o código saem e a decisão faz rollback.
- **0037:** o código cifrado também é apagado até 30 dias depois da decisão (como o ficheiro). Ler `access_code_enc` NULL numa verificação decidida = "código já eliminado" (404 próprio, nunca 500).
