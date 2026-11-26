# 21 — Rust: armazenamento privado + URL assinado de 5 min atrás do `StorageBackend` (épico: 03-patrocinio-comissoes)

**Agente:** rust-core · **Modelo:** opus · **Depende de:** 20 (só pela série Rust) · **Paralelo com:** — · **Auditoria:** security-auditor obrigatório

## Objetivo
Existe um armazenamento privado em disco, fora de qualquer pasta servida, e a API consegue emitir e servir um URL assinado que expira em 5 minutos. Ainda sem regras de negócio (cartões 22 e 23).

## Pode alterar
- `backend-rust/src/storage.rs` (ou `src/storage/{mod,local_private,signed}.rs`); `src/{state,config}.rs`; `src/http/mod.rs` (rota de descarga); `backend-rust/.env.example`, `infra/README.md` (variáveis novas); `backend-rust/tests/private_storage.rs` (criar)

## Não tocar
- `src/identity/`, `src/audit/`, `src/tenancy/`; `migrations/`; a configuração do Caddy e de `/media`. Nunca ler `.env` (só o `.env.example`); se faltar uma variável em dev, pedir ao supervisor.

## Contexto exato (spec 08 §1, spec 14 §6)
```
Documentos de verificação: armazenamento PRIVADO, nunca /media nem pasta servida publicamente; só acessíveis por URL assinado de 5 min, gerado por um super_admin em revisão e auditado. STORAGE_DRIVER=local agora; S3 compatível (R2/B2) no futuro sem mudar rotas: nada de código preso a um fornecedor.
Trait atual: StorageBackend { put(key, bytes), get(key), delete(key) } + NullStorage; state.storage: Arc<dyn StorageBackend>.
Passa a:
  StorageBackend ganha `async fn signed_url(&self, key: &str, ttl: Duration) -> anyhow::Result<String>` (NullStorage: erro; um backend S3 futuro devolve o presigned do fornecedor).
  LocalPrivateStorage { root, signer }: grava em PRIVATE_STORAGE_DIR (fora de /var/data/ptmarket/media; diretório 0700, ficheiros 0600). Chaves só com [a-z0-9/_.-], sem "..", sem barra inicial, ≤ 200 caracteres; o caminho final é canonicalizado e tem de ficar dentro de root (anti path traversal). delete de ficheiro inexistente = Ok.
  state.private_storage: Arc<dyn StorageBackend>, separado de state.storage (o público).
  Token: base64url(key ‖ exp_unix) + HMAC-SHA256 com PRIVATE_STORAGE_SIGNING_KEY (≥ 32 bytes; comparação em tempo constante). ttl máximo 300 s. signed_url devolve https://<PLATFORM_ADMIN_HOST>/api/v1/private-files/<token>.
  GET /api/v1/private-files/{token}: só em PLATFORM_ADMIN_HOST E com RequireSuperAdmin (o token sozinho não chega: defesa em profundidade). Token inválido, expirado, de outra chave, ou ficheiro em falta → o mesmo 404.
    Resposta: bytes + Content-Type: application/pdf, Content-Disposition: attachment, X-Content-Type-Options: nosniff, Cache-Control: no-store, Referrer-Policy: no-referrer. A descarga grava 'private_file.read' de forma síncrona (leitura de admin).
  Config: PRIVATE_STORAGE_DIR e PRIVATE_STORAGE_SIGNING_KEY obrigatórias em staging/production (como as outras chaves em config.rs); em development sem elas → NullStorage. Segredos nunca em logs, mensagens de erro nem no Debug.
Sem unwrap/expect; sem bloquear o runtime (tokio::fs); relógio injetável para os testes de expiração.
```

## Feito quando
- [ ] `private_storage`: put/get/delete num diretório temporário; chave com `..`, absoluta, com `\0` ou symlink para fora → erro e nada escrito fora de root
- [ ] Token válido serve o ficheiro com os cabeçalhos acima; expirado (301 s), adulterado num byte ou assinado com outra chave → 404; `ttl` > 300 s → erro
- [ ] Sem sessão, com sessão de merchant ou sponsor_admin, ou num Host de canal → 404 mesmo com token válido, com `denied` na caixa negra
- [ ] Produção sem as duas variáveis → a API não arranca (teste de `config`); a chave não aparece no `Debug` da config

## Prova (um comando)
`cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test private_storage` → esperado: 0 falhas

## Re-provar (funcionalidades já aprovadas que partilham este código)
- Config e gate do super_admin — `cargo test -p ptmarket-api --lib config && cargo test -p ptmarket-api --test totp --test admin_timeline` (mesmas variáveis)
