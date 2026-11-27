# 09 — BD: `store_verifications` (documentos de verificação da loja) (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 08b + 14 (par fechado) · **Paralelo com:** —

## Objetivo
Existe o registo dos documentos de verificação de cada loja, com o hash como prova, o código da Certidão Permanente só cifrado, a data-limite de eliminação do ficheiro garantida pela BD e o worker só com o acesso mínimo para apagar.

## Pode alterar
- `migrations/0036_store_verifications.sql`, `migrations/tests/store_verifications.sql` (criar)

## Não tocar
- `migrations/0001–0035`; `audit.*`; as funções de revisão do super_admin (cartão 10). Nunca ler `.env`.

## Contexto exato (spec 14 §6; RGPD art. 5.º/1/c e e, art. 32.º)
```
Ficheiros num armazenamento PRIVADO (nunca /media), só por URL assinado de 5 min gerado por um super_admin. O ficheiro é apagado até 30 dias depois da decisão; o hash e os metadados ficam (prova). NIF empresa (começa por 5): código de acesso à Certidão Permanente, PDF opcional. ENI (1, 2 ou 3): Declaração de Início/Alteração de Atividade ou Comprovativo de Domicílio Fiscal (PDF). Outros prefixos: revisão manual. O código da Certidão Permanente NUNCA fica em claro: a app cifra-o com AES-256-GCM (formato 'v1:<kid>:…' do identity::crypto, chave própria VERIFICATION_ENC_KEY) e a BD só guarda o texto cifrado.
CREATE TABLE store_verifications (id UUID PRIMARY KEY DEFAULT uuidv7(), tenant_id UUID NOT NULL, store_id UUID NOT NULL,
    kind VARCHAR(32) NOT NULL CHECK (kind IN ('certidao_permanente_code','certidao_permanente_pdf','declaracao_inicio_atividade','comprovativo_domicilio_fiscal','manual_other')),
    sha256 BYTEA CHECK (octet_length(sha256) = 32), storage_key TEXT, access_code_enc TEXT CHECK (access_code_enc LIKE 'v1:%'), status VARCHAR(12) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    submitted_by UUID REFERENCES users (id), reviewed_by UUID REFERENCES users (id), reviewed_at TIMESTAMPTZ, review_reason VARCHAR(500), delete_after TIMESTAMPTZ, file_deleted_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), FOREIGN KEY (tenant_id, store_id) REFERENCES stores (tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT,
    CHECK ((kind = 'certidao_permanente_code') = (access_code_enc IS NOT NULL)), CHECK (kind = 'certidao_permanente_code' OR sha256 IS NOT NULL), CHECK (storage_key IS NULL OR sha256 IS NOT NULL),
    CHECK ((status = 'pending') = (reviewed_at IS NULL)), CHECK (file_deleted_at IS NULL OR storage_key IS NULL),
    CHECK (status = 'pending' OR storage_key IS NULL OR (delete_after IS NOT NULL AND delete_after <= reviewed_at + interval '30 days')));
Trigger BEFORE UPDATE (INVOKER, search_path = pg_catalog, pg_temp): sha256, kind, store_id, tenant_id, access_code_enc e created_at imutáveis; status só pending → approved | rejected; storage_key só pode passar a NULL. Sem DELETE para app/worker. Índices: (tenant_id, store_id); (status, created_at) WHERE status = 'pending'; (delete_after) WHERE storage_key IS NOT NULL.
RLS ENABLE + FORCE. ptmarket_app: tenant_isolation + policies RESTRICTIVE de SELECT e de INSERT com store_id = (SELECT app_store_id()) (isolamento por loja do cartão 08b; sem exceção de admin: o super_admin usa as funções do cartão 10). GRANT SELECT e INSERT (id, tenant_id, store_id, kind, sha256, storage_key, access_code_enc, submitted_by, metadata). A app NÃO tem UPDATE.
ptmarket_worker (cartão 25): policies SELECT/UPDATE USING (storage_key IS NOT NULL AND delete_after <= now()) WITH CHECK (storage_key IS NULL); GRANT SELECT (id, tenant_id, store_id, storage_key, delete_after), UPDATE (storage_key, file_deleted_at).
Bloco L1 condicional (0018, linhas 77–98); a L1 só vê o texto cifrado. Nunca SET ROLE para papéis sem acesso a audit.
```

## Feito quando
- [ ] Teste `store_verifications`: código cifrado (`v1:…`) sem ficheiro e PDF com hash passam; `access_code_enc` sem prefixo `v1:`, PDF sem hash, hash de 31 bytes, `approved` sem `reviewed_at` e `delete_after` a 31 dias da decisão falham
- [ ] Como `ptmarket_app` com `app.store_id = L1`: insere e lê em L1; em L2 do mesmo país INSERT → 42501 e SELECT → 0 linhas; outro tenant não vê; UPDATE e DELETE → 42501
- [ ] Como `ptmarket_worker`: só vê linhas vencidas com ficheiro e só consegue pôr `storage_key = NULL`; não mexe em `sha256`, `status` nem `access_code_enc`

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `store_verifications` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- `audit_l1`, `store_scope_rls` no `run.sh`; suites completas verdes: `cargo test -p ptmarket-api` e `cd workers-go && go test -race ./...`
