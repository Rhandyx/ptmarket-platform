-- Teste 0027 geo_dicofre. Como migrator (inserts) e ptmarket_app (leitura/recusas).
BEGIN;
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES
    ('11', 'district', NULL, 'Lisboa', 'T'),
    ('1106', 'municipality', '11', 'Lisboa', 'T'),
    ('110601', 'parish', '1106', 'Ajuda', 'T'),
    ('03', 'district', NULL, 'Braga', 'T'),
    ('0302', 'municipality', '03', 'Barcelos', 'T'),
    ('0302FA', 'parish', '0302', 'Barcelos FA', 'T');

CREATE FUNCTION pg_temp.expect_fail(sql text, state text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    BEGIN
        EXECUTE sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = state THEN RETURN; END IF;
        RAISE EXCEPTION 'esperado %, obtido % (%) em: %', state, SQLSTATE, SQLERRM, sql;
    END;
    RAISE EXCEPTION 'devia falhar (%): %', state, sql;
END $$;

SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('110','district',NULL,'x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('11060','parish','1106','x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('1107','district','11','x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('1107','municipality','12','x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('120101','parish','1201','x','T')$q$, '23503');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('0302fa','parish','0302','x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('03A2','municipality','03','x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$INSERT INTO geo_dicofre VALUES ('0A','district',NULL,'x','T')$q$, '23514');
SELECT pg_temp.expect_fail($q$DELETE FROM geo_dicofre WHERE code = '110601'$q$, '23001');

DO $$
BEGIN
    IF (SELECT count(*) FROM pg_trigger WHERE tgrelid = 'geo_dicofre'::regclass
        AND tgname IN ('zz_audit_row', 'zz_audit_truncate')) <> 2 THEN
        RAISE EXCEPTION 'geo_dicofre sem os triggers zz_audit_*';
    END IF;
END $$;
COMMIT;

-- App: leitura sem tenant; escrita recusada.
BEGIN;
INSERT INTO geo_dicofre (code, level, parent_code, name, caop_version) VALUES ('99', 'district', NULL, 'Teste', 'T');
SET LOCAL ROLE ptmarket_app;
DO $$
DECLARE s text;
BEGIN
    IF (SELECT count(*) FROM geo_dicofre WHERE code = '99') <> 1 THEN RAISE EXCEPTION 'app não lê geo_dicofre'; END IF;
    FOREACH s IN ARRAY ARRAY[
        $q$INSERT INTO geo_dicofre VALUES ('98','district',NULL,'x','T')$q$,
        $q$UPDATE geo_dicofre SET name = 'y'$q$,
        $q$DELETE FROM geo_dicofre$q$] LOOP
        BEGIN
            EXECUTE s;
            RAISE EXCEPTION 'app conseguiu: %', s;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
    END LOOP;
END $$;
ROLLBACK;
