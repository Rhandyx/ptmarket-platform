-- 0028 — sponsor_entities (Câmara, Junta, Associação), áreas DICOFRE e papel sponsor_admin (cartão 03/03; spec 14 §1, §2, §8).
-- Rollback mental (só em dev):
--   ALTER TABLE user_roles DROP CONSTRAINT user_roles_unique, DROP CONSTRAINT user_roles_scope,
--       DROP CONSTRAINT user_roles_role_check;  (repor os três textos da 0018)  ALTER TABLE user_roles DROP COLUMN sponsor_entity_id;
--   DROP TABLE sponsor_entity_areas; DROP TABLE sponsor_entities;
--   DROP FUNCTION sponsor_entities_check(); DROP FUNCTION sponsor_entity_areas_check();
--   (policies, índices, grants e zz_audit_* caem com as tabelas; os eventos gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   * kind: municipality → area_code DDCC (4) · parish → DDCCFF (6; os 2 últimos podem ser letras, ex. 0302FA) ·
--     association → area_code NULL e a lista de áreas em sponsor_entity_areas (DDCC ou DDCCFF). Validação só por
--     length() + FK para geo_dicofre (nunca regex de algarismos).
--   * channel_tenant_id (NULL = sem domínio próprio): tenant que não é 'national_portal' e do mesmo país (trigger).
--   * sponsor_entity_areas só para entidades 'association'; uma entidade com áreas não deixa de ser associação.
--   * Dados públicos (nome, selo, área): ptmarket_app só LÊ. Escrita só pelo migrator neste épico (policy própria,
--     como a 0027: com FORCE o dono também passa pelas policies); o CRUD do super_admin é do épico de backoffice.
--   * user_roles: + sponsor_admin com âmbito sponsor_entity_id (tenant e loja NULL). own_select e grants inalterados.
--   * Não coberto aqui (não se toca em tenants): mudar depois o tenant_type/country_code de um tenant já usado
--     como canal não é revalidado.

-- ---------------------------------------------------------------------------
-- Tabelas.
-- ---------------------------------------------------------------------------
CREATE TABLE sponsor_entities (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    kind              VARCHAR(16)  NOT NULL CHECK (kind IN ('municipality', 'parish', 'association')),
    country_code      CHAR(2)      NOT NULL DEFAULT 'PT' CHECK (country_code IN ('PT', 'ES')),
    name              VARCHAR(255) NOT NULL,
    slug              VARCHAR(120) NOT NULL,
    logo_key          TEXT, -- logótipo/brasão, storage público
    area_code         VARCHAR(6) REFERENCES geo_dicofre (code) ON DELETE RESTRICT,
    channel_tenant_id UUID REFERENCES tenants (id) ON DELETE RESTRICT, -- NULL = sem domínio próprio
    is_active         BOOLEAN      NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT sponsor_entities_country_slug_key UNIQUE (country_code, slug),
    -- municipality cobre o concelho DDCC; parish a freguesia DDCCFF; association usa sponsor_entity_areas.
    -- COALESCE: sem ele, area_code NULL dava CHECK NULL (= passa) e uma Câmara/Junta ficava sem área (spec 14 §2).
    CONSTRAINT sponsor_entities_area_by_kind CHECK (
        CASE kind
            WHEN 'municipality' THEN COALESCE(length(area_code) = 4, false)
            WHEN 'parish'       THEN COALESCE(length(area_code) = 6, false)
            ELSE area_code IS NULL
        END
    )
);

CREATE INDEX sponsor_entities_channel_idx ON sponsor_entities (channel_tenant_id) WHERE channel_tenant_id IS NOT NULL;
CREATE INDEX sponsor_entities_kind_area_idx ON sponsor_entities (kind, area_code);

-- Só 'association': lista de áreas (DDCC ou DDCCFF).
CREATE TABLE sponsor_entity_areas (
    sponsor_entity_id UUID       NOT NULL REFERENCES sponsor_entities (id) ON DELETE CASCADE,
    area_code         VARCHAR(6) NOT NULL REFERENCES geo_dicofre (code) ON DELETE RESTRICT
        CONSTRAINT sponsor_entity_areas_area_len CHECK (length(area_code) IN (4, 6)),
    PRIMARY KEY (sponsor_entity_id, area_code)
);

CREATE INDEX sponsor_entity_areas_area_idx ON sponsor_entity_areas (area_code);

-- ---------------------------------------------------------------------------
-- Triggers de coerência (INVOKER; search_path fixo; relações qualificadas).
-- ---------------------------------------------------------------------------
CREATE FUNCTION sponsor_entities_check() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
DECLARE
    v_type    text;
    v_country text;
BEGIN
    IF NEW.channel_tenant_id IS NOT NULL THEN
        SELECT t.tenant_type, t.country_code INTO v_type, v_country
        FROM public.tenants t WHERE t.id = NEW.channel_tenant_id;
        -- Tenant inexistente: a FK responde (23503).
        IF FOUND AND (v_type = 'national_portal' OR v_country IS DISTINCT FROM NEW.country_code) THEN
            RAISE EXCEPTION 'sponsor_entities: canal tem de ser um tenant não national_portal do mesmo país'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.kind <> 'association'
       AND EXISTS (SELECT 1 FROM public.sponsor_entity_areas a WHERE a.sponsor_entity_id = NEW.id) THEN
        RAISE EXCEPTION 'sponsor_entities: entidade com áreas tem de ser association'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER sponsor_entities_check BEFORE INSERT OR UPDATE OF kind, country_code, channel_tenant_id
    ON sponsor_entities FOR EACH ROW EXECUTE FUNCTION sponsor_entities_check();

CREATE FUNCTION sponsor_entity_areas_check() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS
$$
DECLARE
    v_kind text;
BEGIN
    -- FOR SHARE: uma mudança de kind concorrente espera por esta transação.
    SELECT e.kind INTO v_kind FROM public.sponsor_entities e WHERE e.id = NEW.sponsor_entity_id FOR SHARE;
    -- Entidade inexistente: a FK responde (23503).
    IF FOUND AND v_kind <> 'association' THEN
        RAISE EXCEPTION 'sponsor_entity_areas: só entidades association têm lista de áreas'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER sponsor_entity_areas_check BEFORE INSERT OR UPDATE ON sponsor_entity_areas
    FOR EACH ROW EXECUTE FUNCTION sponsor_entity_areas_check();

REVOKE ALL ON FUNCTION sponsor_entities_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION sponsor_entity_areas_check() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Caixa negra L1 (só se a L2 ainda não os criou: ver o cabeçalho da 0018).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sponsor_entities', 'sponsor_entity_areas'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_row') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_row AFTER INSERT OR UPDATE OR DELETE ON %I '
                           'FOR EACH ROW EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_row', t);
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                       WHERE tgrelid = format('public.%I', t)::regclass AND tgname = 'zz_audit_truncate') THEN
            EXECUTE format('CREATE TRIGGER zz_audit_truncate BEFORE TRUNCATE ON %I '
                           'FOR EACH STATEMENT EXECUTE FUNCTION audit.audit_row_trigger()', t);
            EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER zz_audit_truncate', t);
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- RLS: leitura pública para a app; escrita só pelo migrator.
-- ---------------------------------------------------------------------------
ALTER TABLE sponsor_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE sponsor_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE sponsor_entity_areas ENABLE ROW LEVEL SECURITY;
ALTER TABLE sponsor_entity_areas FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON sponsor_entities AS PERMISSIVE FOR SELECT TO ptmarket_app USING (true);
CREATE POLICY app_select ON sponsor_entity_areas AS PERMISSIVE FOR SELECT TO ptmarket_app USING (true);
CREATE POLICY migrator_all ON sponsor_entities AS PERMISSIVE FOR ALL TO ptmarket_migrator
    USING (true) WITH CHECK (true);
CREATE POLICY migrator_all ON sponsor_entity_areas AS PERMISSIVE FOR ALL TO ptmarket_migrator
    USING (true) WITH CHECK (true);

REVOKE ALL ON sponsor_entities, sponsor_entity_areas FROM PUBLIC;
GRANT SELECT ON sponsor_entities, sponsor_entity_areas TO ptmarket_app;

-- ---------------------------------------------------------------------------
-- user_roles: papel sponsor_admin com âmbito de entidade (nomes confirmados em pg_constraint na BD de dev).
-- ---------------------------------------------------------------------------
ALTER TABLE user_roles
    ADD COLUMN sponsor_entity_id UUID REFERENCES sponsor_entities (id) ON DELETE CASCADE,
    DROP CONSTRAINT user_roles_role_check,
    ADD CONSTRAINT user_roles_role_check
        CHECK (role IN ('super_admin', 'tenant_admin', 'sponsor_admin', 'merchant_owner', 'merchant_staff')),
    DROP CONSTRAINT user_roles_scope,
    ADD CONSTRAINT user_roles_scope CHECK (
        CASE role
            WHEN 'super_admin'   THEN tenant_id IS NULL AND store_id IS NULL AND sponsor_entity_id IS NULL
            WHEN 'tenant_admin'  THEN tenant_id IS NOT NULL AND store_id IS NULL AND sponsor_entity_id IS NULL
            WHEN 'sponsor_admin' THEN sponsor_entity_id IS NOT NULL AND tenant_id IS NULL AND store_id IS NULL
            ELSE tenant_id IS NOT NULL AND store_id IS NOT NULL AND sponsor_entity_id IS NULL
        END
    ),
    DROP CONSTRAINT user_roles_unique,
    ADD CONSTRAINT user_roles_unique UNIQUE NULLS NOT DISTINCT (user_id, role, tenant_id, store_id, sponsor_entity_id);

CREATE INDEX user_roles_sponsor_entity_idx ON user_roles (sponsor_entity_id) WHERE sponsor_entity_id IS NOT NULL;
