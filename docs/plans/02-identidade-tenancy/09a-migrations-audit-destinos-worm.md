# 09a — `audit.worm_targets`: cada Câmara guarda a prova no seu próprio bucket (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01b, 04 (numeração 0012) · **Paralelo com:** 06, 08

> **Mudou no 01b (ler antes de começar):** a caixa negra vive no schema `audit` (dono NOLOGIN). O migrator só tem USAGE + CREATE em `audit`. Qualquer migration que crie objetos em `audit` termina com `SELECT audit_admin.audit_seal();`. Uma função SECURITY DEFINER nova em `audit` só passa a selagem se a sua assinatura estiver na allowlist da `audit_seal()` em `infra/postgres/init/03-audit-bootstrap.sh` (este cartão pode editá-la; o README de infra diz como aplicar como superuser). Nenhuma função DEFINER de `audit.*` toca em objetos de papéis com LOGIN. Escrever na cadeia: só através de `audit._chain_insert` (fórmula única `audit._event_hash`).

## Objetivo
A raiz diária e os alertas de superadmin de cada tenant-Câmara vão para o bucket WORM da própria Câmara, que é ela que paga e que controla (decisão do owner, 25/11/2026: "quanto menos responsabilidades para nós, melhor"). Os eventos de plataforma e os tenants de comércio direto (onde a plataforma recebe comissão) usam o bucket da plataforma.

## Pode alterar
- `migrations/0012_audit_worm_targets.sql`, `migrations/tests/audit_worm_targets.sql` (criar); `migrations/tests/run.sh` (só para incluir o teste); `infra/postgres/init/03-audit-bootstrap.sh` (só a allowlist da `audit_seal`)

## Não tocar
- `migrations/0001–0011`, `infra/`, `backend-rust/`, `workers-go/`; nunca ler `.env`

## Contexto exato
```
Tabela audit.worm_targets (schema audit, selada com audit_admin.audit_seal() no fim, como na 0008):
  tenant_id UUID PRIMARY KEY (NULL não; a plataforma usa a config WORM_* do worker), provider VARCHAR(16) NOT NULL CHECK IN ('s3'),
  endpoint TEXT NULL (NULL = AWS), region TEXT NOT NULL, bucket TEXT NOT NULL CHECK (bucket ~ '^[a-z0-9][a-z0-9.-]{2,62}$'),
  roots_retention_days INT NOT NULL DEFAULT 3650, details_retention_days INT NOT NULL DEFAULT 730, created_at, created_by TEXT NOT NULL.
Modelo de acesso sem segredos por tenant: a Câmara cria o bucket (Object Lock COMPLIANCE ligado) e dá ao principal IAM da plataforma, por bucket policy, só s3:PutObject, s3:GetObject e s3:GetObjectRetention. A BD não guarda nenhuma credencial.
Escrita: redirecionar a prova para outro bucket é um ato sensível (regra das duas pessoas da spec 13), por isso a app, o worker e o migrator NÃO têm INSERT, UPDATE nem DELETE. Só o superuser altera, num passo documentado no README de infra (fica no pgaudit 'all'). O ptmarket_worker tem SELECT. UI de gestão = épico admin, com aprovação dupla.
Cada alteração é auditada: trigger que chama audit._chain_insert (actor 'db', actor_label = session_user) com o antes/depois.
Retenção (defaults até à revisão jurídica): raízes 10 anos (KB por dia, custo desprezável, e mantêm prova da cadeia fiscal); detalhes de superadmin 2 anos. O Object Lock deixa prolongar mas nunca encurtar, por isso começa-se curto nos detalhes.
```

## Feito quando
- [ ] app, worker e migrator: INSERT/UPDATE/DELETE em `audit.worm_targets` → 42501; worker lê
- [ ] Como superuser, inserir e alterar um destino gera um evento na cadeia da plataforma com o antes/depois
- [ ] Bucket com nome inválido → CHECK falha; `audit_seal()` deixa o migrator sem privilégios na tabela nova

## Prova (um comando)
`migrations/tests/run.sh` → `TODOS OS TESTES PASSARAM`, código 0
