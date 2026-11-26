# 20b — BD: criar o 1.º super_admin por uma função dedicada, já com TOTP ativo (épico: 02-identidade-tenancy)

**Agente:** db-architect · **Modelo:** opus · **Depende de:** 20 (Rust, sem o CLI), 0023 · **Paralelo com:** — (a BD é sempre em série) · **Antes de:** 20c

> Achados médios 3 e 4 da auditoria L3 do cartão 20 (26/11). O CLI fazia `ALTER TABLE users/user_roles NO FORCE ROW LEVEL SECURITY` com a credencial do dono. Isso dá um lock ACCESS EXCLUSIVE sem `lock_timeout` (para todos os logins), põe DDL de rotina no registo da L2 e cria um super_admin sem TOTP: quem tiver a password associa o seu próprio TOTP. Lê as 0018, 0019 e 0021 para partir dos objetos ATUAIS.

## Objetivo
O 1.º super_admin (e os seguintes, por CLI) nasce numa só chamada atómica, já com o TOTP ativo e os códigos de recuperação gravados. O CLI não precisa de DDL, de BYPASSRLS nem de desligar o FORCE RLS.

## Pode alterar
- `migrations/0024_identity_bootstrap_superadmin.sql`, `migrations/tests/identity_bootstrap_superadmin.sql` (criar); `infra/README.md` (só uma secção curta "Criar o 1.º super_admin")

## Não tocar
- `migrations/0001–0023` (imutáveis); `backend-rust/`, `workers-go/`, `infra/postgres/` (exceto se o bootstrap precisar mesmo; nesse caso parar e reportar). Nunca ler `.env`.

## Contexto exato
```
Papéis (padrão do ptmarket_identity na 0017 e do ptmarket_portal na 0021: NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB, NOCREATEROLE, NOREPLICATION):
  ptmarket_bootstrap: dono da função. Só INSERT em users(id, email, password_hash, full_name, totp_secret_enc, totp_enabled, is_active) e user_roles (as colunas que a função usa) e user_recovery_codes(user_id, code_hash); SELECT só no que precisar para recusar o email repetido. Políticas RLS FOR INSERT TO ptmarket_bootstrap: users sem restrição extra; user_roles WITH CHECK (role = 'super_admin' AND tenant_id IS NULL AND store_id IS NULL); user_recovery_codes WITH CHECK (true).
  ptmarket_operator: o único com EXECUTE na função (REVOKE de PUBLIC, ptmarket_app, ptmarket_worker). GRANT ptmarket_operator TO ptmarket_migrator WITH INHERIT FALSE, SET TRUE (dev: o CLI liga como migrator e faz SET ROLE ptmarket_operator; produção: o owner pode criar um login próprio, membro de ptmarket_operator).
  A 0022 recusa memberships estranhas em ptmarket_identity/ptmarket_portal: aplicar a mesma guarda aos dois papéis novos (só as memberships acima).
  LIÇÃO L2: nunca SET ROLE, dentro da migration, para um papel sem acesso a audit (a L2 recusa o DDL, 42501). Para mudar o dono: ALTER FUNCTION … OWNER TO, com o padrão do ponto D da 0021 (INHERIT temporário no migrator e depois repor INHERIT FALSE, SET TRUE) se for preciso.
Função public.identity_create_superadmin(p_id uuid, p_email text, p_full_name text, p_phc text, p_totp_secret_enc text, p_recovery_hashes bytea[]) RETURNS void
  SECURITY DEFINER, dono ptmarket_bootstrap, SET search_path = pg_catalog, pg_temp, todas as relações qualificadas (public.…).
  Valida (RAISE 22023 com mensagem fixa, sem ecoar valores): p_email = lower(btrim(p_email)), 3–255 caracteres e com '@'; p_full_name com 1–255; p_phc LIKE '$argon2id$%'; p_totp_secret_enc LIKE 'v1:%'; array_length(p_recovery_hashes, 1) = 10 e cada octet_length = 32, sem repetidos.
  Email já existente → RAISE 23505 (mensagem fixa).
  set_config('app.actor_type', 'db', true) (a L1 regista o ator 'db'); INSERT users (totp_enabled = true, is_active = true), user_roles ('super_admin', tenant e store NULL), 10 × user_recovery_codes. Tudo na transação de quem chama.
Tabelas novas: nenhuma. Rollback mental no topo da migration.
```

## Feito quando
- [ ] `SET ROLE ptmarket_operator`: a função cria utilizador + papel + 10 códigos; os eventos L1 têm ator `db`; uma 2.ª chamada com o mesmo email (também com maiúsculas) → 23505 e nada criado
- [ ] Validação: PHC que não é argon2id, segredo sem `v1:`, 9 ou 11 hashes, um hash com 31 B → 22023 e nada criado
- [ ] `ptmarket_app`, `ptmarket_worker` e `ptmarket_migrator` (sem SET ROLE) não conseguem EXECUTE; `ptmarket_bootstrap` não consegue inserir um papel que não seja `super_admin` nem um com tenant; a guarda de memberships cobre os dois papéis novos
- [ ] Nenhum DDL, nem NO FORCE RLS, no caminho do CLI; `run.sh` verde, incluindo a 2.ª passagem com a L2 ligada

## Prova (um comando)
`migrations/tests/run.sh` → esperado: todos os testes OK, incluindo `identity_bootstrap_superadmin`

## Re-provar
- `cd backend-rust && cargo test -p ptmarket-api --test totp --test rbac` (as migrations correm nos testes `sqlx::test`)
