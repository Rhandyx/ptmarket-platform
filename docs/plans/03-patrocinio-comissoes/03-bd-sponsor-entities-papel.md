# 03 — BD: `sponsor_entities`, áreas e papel `sponsor_admin` (épico: 03-patrocinio-comissoes)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 01 · **Paralelo com:** —

## Objetivo
Existem as entidades patrocinadoras (Câmara, Junta, Associação) com área DICOFRE e canal opcional, e `user_roles` aceita `sponsor_admin` com âmbito de entidade.

## Pode alterar
- `migrations/0028_sponsor_entities.sql`, `migrations/tests/sponsor_entities.sql` (criar); `migrations/tests/users_rbac.sql` (acrescentar casos)

## Não tocar
- `migrations/0001–0027`; `tenants` (o `custom_domain` continua `NOT NULL UNIQUE`; nenhuma coluna muda); `backend-rust/`, `workers-go/`. Nunca ler `.env`.

## Contexto exato (spec 14 §1, §2, §8)
```
CREATE TABLE sponsor_entities (id UUID PRIMARY KEY DEFAULT uuidv7(),
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('municipality', 'parish', 'association')), country_code CHAR(2) NOT NULL DEFAULT 'PT' CHECK (country_code IN ('PT', 'ES')),
    name VARCHAR(255) NOT NULL, slug VARCHAR(120) NOT NULL, logo_key TEXT /* logótipo/brasão, storage público */, area_code VARCHAR(6) REFERENCES geo_dicofre (code) ON DELETE RESTRICT,
    channel_tenant_id UUID REFERENCES tenants (id) ON DELETE RESTRICT /* NULL = sem domínio próprio */, is_active BOOLEAN NOT NULL DEFAULT true, created_at/updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), UNIQUE (country_code, slug),
    CHECK (CASE kind WHEN 'municipality' THEN length(area_code) = 4 WHEN 'parish' THEN length(area_code) = 6 ELSE area_code IS NULL END));  -- municipality cobre o concelho DDCC; parish a freguesia DDCCFF
CREATE TABLE sponsor_entity_areas (sponsor_entity_id UUID NOT NULL REFERENCES sponsor_entities (id) ON DELETE CASCADE, area_code VARCHAR(6) NOT NULL REFERENCES geo_dicofre (code) ON DELETE RESTRICT, PRIMARY KEY (sponsor_entity_id, area_code));  -- só 'association': lista de áreas (DDCC ou DDCCFF)
Triggers (INVOKER, SET search_path = pg_catalog, pg_temp, relações qualificadas): channel_tenant_id, se não NULL, é um tenant com tenant_type <> 'national_portal' e o mesmo country_code; sponsor_entity_areas só aceita entidades 'association'. Índices: (channel_tenant_id) WHERE channel_tenant_id IS NOT NULL; (kind, area_code); sponsor_entity_areas (area_code).
RLS nas duas: ENABLE + FORCE; SELECT para ptmarket_app USING (true) (dados públicos: nome, selo, área); a app NÃO escreve (neste épico as entidades criam-se pelo migrator; o CRUD do super_admin é do épico de backoffice).
user_roles (0018) hoje: CHECK (role IN ('super_admin','tenant_admin','merchant_owner','merchant_staff')), user_roles_scope, user_roles_unique UNIQUE NULLS NOT DISTINCT (user_id, role, tenant_id, store_id). Passa a:
  + coluna sponsor_entity_id UUID REFERENCES sponsor_entities (id) ON DELETE CASCADE, com índice; role aceita também 'sponsor_admin' (confirmar o nome real da constraint em pg_constraint antes do DROP);
  user_roles_scope: super_admin → tudo NULL · tenant_admin → só tenant_id · sponsor_admin → só sponsor_entity_id (tenant_id e store_id NULL) · merchant_* → tenant_id e store_id, sponsor_entity_id NULL; user_roles_unique passa a incluir sponsor_entity_id.
  A policy own_select e os grants ficam iguais: a app só LÊ os papéis do próprio e continua sem os poder escrever.
Bloco L1 condicional (0018, linhas 77–98) para as duas tabelas novas. Nunca SET ROLE para papéis sem acesso a audit (lição L2).
```

## Feito quando
- [ ] Teste `sponsor_entities`: Câmara com área de 4 dígitos, Junta com 6 e Associação com 2 áreas passam; Câmara com 6 dígitos, Associação com `area_code`, canal `national_portal` ou de outro país, e área numa entidade não-associação falham
- [ ] `users_rbac`: `sponsor_admin` com entidade passa; com `tenant_id`/`store_id` ou sem entidade falha; `merchant_owner` com entidade falha; duplicado exato falha
- [ ] Como `ptmarket_app`: lê entidades; qualquer escrita em `sponsor_entities`, `sponsor_entity_areas` e `user_roles` → 42501; um utilizador não vê os papéis de outro

## Prova (um comando)
`migrations/tests/run.sh` → todos OK, incluindo `sponsor_entities` e `users_rbac` (com L2)

## Re-provar (funcionalidades já aprovadas que partilham este código)
- RBAC e login de staff — `cd backend-rust && DATABASE_URL=postgres://ptmarket_migrator:dev_migrator@127.0.0.1:5432/ptmarket REDIS_URL=redis://127.0.0.1:6379 cargo test -p ptmarket-api --test rbac --test login`
