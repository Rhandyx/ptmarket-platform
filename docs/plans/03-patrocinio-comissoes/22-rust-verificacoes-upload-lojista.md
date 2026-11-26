# 22 — Rust: verificação da loja, envio de documentos pelo lojista (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 21, 09 · **Paralelo com:** — (Rust em série) · **Auditoria:** security-auditor obrigatório (cifra)

## Objetivo
O dono de uma loja envia o código da Certidão Permanente (guardado só cifrado) ou o PDF exigido para o seu tipo de NIF; o ficheiro fica no armazenamento privado e a BD guarda o hash.

## Pode alterar
- `backend-rust/src/tenancy/verifications.rs` (criar; `tenancy` é o dono de `stores` e de `store_verifications`); `src/tenancy/{mod,store_terms}.rs`; `src/identity/crypto.rs` (só expor a cifra `v1:<kid>` de forma reutilizável, sem mudar o TOTP); `src/config.rs`, `backend-rust/.env.example`, `infra/README.md`; `src/http/{mod,openapi}.rs`, `openapi.json`, `.sqlx/**`; `backend-rust/tests/verifications_submit.rs` (criar)

## Não tocar
- `src/storage*` (fechado no 21), o resto de `src/identity/` (usar `identity::nif::validate_pt` e os extractors), `src/tenancy/db.rs`, `src/audit/`, `migrations/`. Nunca ler `.env`.

## Contexto exato (spec 14 §6; RGPD: minimização e art. 32.º; decisão do supervisor sobre a cifra)
```
NIF (módulo 11, identity::nif::validate_pt): Empresa (começa por 5): código de acesso à Certidão Permanente, PDF opcional. ENI (1, 2 ou 3): Declaração de Início/Alteração de Atividade (AT) ou Comprovativo de Domicílio Fiscal (PDF). Outros prefixos válidos: revisão manual.
BD (cartão 09): store_verifications(id, tenant_id, store_id, kind, sha256 bytea(32), storage_key, access_code_enc, status, submitted_by, metadata, …). A app só tem SELECT e INSERT, e só com o GUC app.store_id da loja: transação = begin_store_tx com o scope() do extractor (cartão 14).
Cifra do código: AES-256-GCM no formato 'v1:<kid>:…' já usado para o segredo TOTP (identity::crypto; cartão 20 da Fase 2), com chave PRÓPRIA VERIFICATION_ENC_KEY (+ VERIFICATION_ENC_KEYS_OLD para rotação, como TOTP_ENC_KEYS_OLD); AAD = id da verificação. Nunca reutilizar a TOTP_ENC_KEY. Obrigatória em staging/production (config.rs); sem ela em development → 503 no envio de códigos. O código em claro nunca vai para a BD, logs, auditoria, erros nem Debug.
Kinds permitidos pelo NIF da loja (lido da BD, nunca do cliente): prefixo 5 → 'certidao_permanente_code', 'certidao_permanente_pdf' · prefixos 1, 2, 3 → 'declaracao_inicio_atividade', 'comprovativo_domicilio_fiscal' · outros → 'manual_other'. Kind fora da lista → 422 'kind_not_allowed'.
POST /api/v1/stores/{store_id}/verifications — RequireStoreOwner (2FA), PLATFORM_ADMIN_HOST → 201 {"id","kind","status":"pending"}; a loja já tem 5 pending → 409 'too_many_pending'.
  a) application/json {"kind":"certidao_permanente_code","access_code": string}: aparar; aceitar só [0-9A-Za-z-] com 8..32 caracteres (o formato exato do código está A CONFIRMAR pelo owner: não validar mais do que isto); cifrar e gravar em access_code_enc.
  b) multipart/form-data com kind + file. Só PDF: Content-Type application/pdf E os bytes começam por "%PDF-"; 1 byte..5 MB (limite de corpo na rota, antes de ler tudo para memória); um só ficheiro. sha256 calculado no servidor. storage_key = "verifications/<store_id>/<uuid_v7>.pdf". O nome original não se guarda; metadata só {"size_bytes","content_type"}.
     Ordem: private_storage.put → INSERT na transação → commit. Se o INSERT ou o commit falharem → private_storage.delete (melhor esforço) e erro: nunca fica linha sem ficheiro. NullStorage → 503. Os erros nunca devolvem caminhos do disco.
GET /api/v1/stores/{store_id}/verifications — RequireStoreRole → [{"id","kind","status","created_at","reviewed_at","review_reason","has_file"}]. NUNCA devolve storage_key, o código (cifrado ou não) nem sha256. O lojista não descarrega o ficheiro.
Auditoria na mesma transação: 'store_verification.submitted' (target_type 'store_verification'; changes {kind, sha256 em hex}); nunca o código nem bytes do ficheiro. A leitura é síncrona na caixa negra (dados da loja).
```

## Feito quando
- [ ] `verifications_submit`: empresa envia o código → 201, a coluna tem `v1:<kid>:…`, o texto em claro não aparece na BD nem no evento, e decifra de volta com a chave certa (e falha com outra chave ou com outro id como AAD); ENI envia PDF → 201 e o `sha256` da BD confere com os bytes
- [ ] Ficheiro que não começa por `%PDF-`, com 0 bytes, com mais de 5 MB, ou um segundo ficheiro → 4xx e nada gravado (nem em disco); kind não permitido para o NIF → 422; falha simulada do INSERT → o ficheiro é apagado
- [ ] **Anti-IDOR:** dono de L1 em `/stores/{L2}/verifications` (POST e GET) → 404 + `idor`; `merchant_staff` no POST → 403
- [ ] Produção sem `VERIFICATION_ENC_KEY` → a API não arranca; os testes de TOTP passam sem alteração

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test verifications_submit` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Suite completa `cargo test -p ptmarket-api` (mesmas variáveis), que inclui `totp`, `private_storage`, `store_scope` e `rbac`
