-- 0022 — INSERT de customers sem colunas de estado; papéis donos de DEFINER/views sem memberships (cartão 02/10c;
-- achados médios 2 e 3 da auditoria ASVS do 10b/09b).
-- Rollback mental (só em dev):
--   A. REVOKE INSERT ON customers FROM ptmarket_app; GRANT INSERT ON customers TO ptmarket_app;  (grant da 0017)
--   B. nada (o bloco só lê pg_auth_members).
--   (Nenhuma tabela nova; os eventos ddl.* gravados ficam: a caixa negra é só de acréscimo.)
--
-- Regras:
--   B. ptmarket_identity (0017) e ptmarket_portal (0021) são do cluster e foram criados com IF NOT EXISTS: além de
--      SUPERUSER/BYPASSRLS/LOGIN (já recusados), um deles ser MEMBRO de outro papel herdaria privilégios desse papel
--      e o RLS/grants por coluna deixariam de valer nas DEFINER e na view portal_stores. Recusa (RAISE, mensagem
--      fixa) se algum dos dois:
--        * for membro de QUALQUER papel (pg_auth_members.member = papel);
--        * tiver como membro um papel que não seja o migrator atual (current_user);
--        * tiver o migrator com INHERIT (o 0021 D liga-o só durante o bloco e repõe-no).
--      Grants aceites, só para o migrator: o implícito do CREATE ROLE por um papel CREATEROLE (grantor superuser,
--      ADMIN, sem INHERIT) e o das migrations (SET TRUE, INHERIT FALSE, sem ADMIN). Corre ANTES de tudo o resto.
--   A. ptmarket_app deixa de ter INSERT na tabela inteira: só nas colunas que um registo pode definir. Ficam de fora
--      email_verified_at e anonymized_at (pre-account hijacking: conta com email alheio já verificado; conta que
--      nasce anonimizada). Mencioná-las num INSERT, mesmo com NULL, = 42501. A policy customer_register (0017)
--      continua a exigir as duas NULL (defesa em profundidade). Colunas atuais de customers: 0005 + 0017
--      (email_verified_at); verificadas no fim. Os outros papéis não mudam.

-- ---------------------------------------------------------------------------
-- B. Papéis donos de DEFINER/views: nenhuma membership além das do migrator.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_role text;
    v_oid  oid;
    v_me   oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user);
BEGIN
    FOREACH v_role IN ARRAY ARRAY['ptmarket_identity', 'ptmarket_portal'] LOOP
        v_oid := (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = v_role);
        IF v_oid IS NULL THEN
            RAISE EXCEPTION '0022: o papel % não existe (aplicar a 0017 e a 0021 primeiro); recusado.', v_role;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = v_oid) THEN
            RAISE EXCEPTION '0022: o papel % é membro de outro papel (herdaria os privilégios dele); recusado.', v_role;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                   WHERE m.roleid = v_oid AND m.member = v_me AND m.inherit_option) THEN
            RAISE EXCEPTION '0022: o migrator tem INHERIT no papel %; recusado.', v_role;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members m
            LEFT JOIN pg_catalog.pg_roles g ON g.oid = m.grantor
            WHERE m.roleid = v_oid
              AND NOT (m.member = v_me
                       AND NOT m.inherit_option
                       AND ((m.admin_option AND COALESCE(g.rolsuper, false))
                            OR (m.set_option AND NOT m.admin_option)))
        ) THEN
            RAISE EXCEPTION '0022: o papel % tem membros além do migrator (só ADMIN do bootstrap ou SET sem INHERIT); recusado.',
                v_role;
        END IF;
    END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
-- A. customers: INSERT por coluna, sem email_verified_at nem anonymized_at.
-- ---------------------------------------------------------------------------
-- REVOKE na tabela também retira os privilégios de INSERT por coluna.
REVOKE INSERT ON customers FROM ptmarket_app;
GRANT INSERT (id, email, name, phone, nif, password_hash, passkeys, consents, created_at, updated_at)
    ON customers TO ptmarket_app;

-- Verificação: com as colunas ATUAIS de customers, a app insere em todas exceto as duas de estado.
DO $$
DECLARE
    v_bad text;
BEGIN
    IF has_table_privilege('ptmarket_app', 'public.customers', 'INSERT') THEN
        RAISE EXCEPTION '0022: ptmarket_app ainda tem INSERT na tabela customers inteira';
    END IF;

    SELECT string_agg(a.attname::text, ', ' ORDER BY a.attnum) INTO v_bad
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid = 'public.customers'::regclass
      AND a.attnum > 0
      AND NOT a.attisdropped
      AND has_column_privilege('ptmarket_app', 'public.customers', a.attnum, 'INSERT')
          = (a.attname IN ('email_verified_at', 'anonymized_at'));
    IF v_bad IS NOT NULL THEN
        RAISE EXCEPTION '0022: INSERT de ptmarket_app em customers diferente do esperado nas colunas: %', v_bad;
    END IF;
END
$$;
