//! CLI de operação (cartões 02/20 e 02/20c). Único comando:
//!
//! `ptmarket-admin create-superadmin --email <email> --name <nome>`
//!
//! - Ambiente: o mesmo da API (`Config::from_env`: `APP_ENV`, `TOTP_ENC_KEY`…; em staging/production
//!   tudo obrigatório) + `ADMIN_DATABASE_URL` = ligação do `ptmarket_migrator`. Recusa os papéis da
//!   API (`ptmarket_app`) e do worker. Sem DDL: a escrita é só a função
//!   `identity_create_superadmin` (0024; EXECUTE só para `ptmarket_operator`, via `SET LOCAL ROLE`).
//! - Password: do terminal sem eco, duas vezes (sem terminal: duas linhas do stdin). NUNCA por
//!   argumento. `Password::parse` + passwords vazadas (HIBP estrito: vazada ou serviço em baixo →
//!   recusa; só com `APP_ENV=test` fica desligado, com aviso no stderr) + Argon2id.
//! - Antes de pedir segredos: papel não superuser e com SET em `ptmarket_operator`.
//! - Depois do COMMIT, o passo TOTP do enroll fica marcado no Redis da API (`totp::mark_step`): o
//!   mesmo código não entra no `/verify`; Redis em baixo → aviso e espera de 150 s.
//! - TOTP no terminal: segredo de 20 bytes; mostra o `otpauth://` e o base32; pede um código (até 3
//!   tentativas, a mesma verificação da API); cifra-o com a `TOTP_ENC_KEY` (AAD = id gerado aqui).
//! - 10 códigos de recuperação (gerador da API; `recovery::hash_code` com o id); mostrados UMA vez,
//!   só depois do COMMIT. Nunca imprime a password, os hashes nem o segredo depois do enroll.
//! - Erros: 23505 → "email já existe"; 22023 → mensagem de validação da função.
//! - Caixa negra: a própria função grava os eventos (ator `db`) + pgaudit.

use std::io::{BufRead, IsTerminal, Write};

use ptmarket_api::{
    config::{AppEnv, Config},
    identity::{
        BreachChecker, HibpRange, NullBreachChecker, Password,
        crypto::EncKey,
        email, password,
        recovery::{self, RecoveryKey},
        totp,
    },
};
use rand::{TryRngCore, rngs::OsRng};
use secrecy::ExposeSecret;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "uso: ptmarket-admin create-superadmin --email <email> --name <nome>";
/// Tentativas do código TOTP no enroll.
const TOTP_TRIES: usize = 3;
/// Papéis que nunca servem para este comando.
const FORBIDDEN_ROLES: [&str; 2] = ["ptmarket_app", "ptmarket_worker"];

struct Args {
    email: String,
    name: String,
}

fn parse_args(argv: &[String]) -> anyhow::Result<Args> {
    let mut it = argv.iter();
    match it.next().map(String::as_str) {
        Some("create-superadmin") => {}
        _ => anyhow::bail!("{USAGE}"),
    }
    let (mut email, mut name) = (None, None);
    while let Some(flag) = it.next() {
        let value = it.next().cloned();
        match flag.as_str() {
            "--email" => email = value,
            "--name" => name = value,
            "--password" => {
                anyhow::bail!("a password nunca vai por argumento (é pedida no terminal)")
            }
            _ => anyhow::bail!("argumento desconhecido; {USAGE}"),
        }
    }
    let (Some(email), Some(name)) = (email, name) else {
        anyhow::bail!("{USAGE}");
    };
    let name = name.trim().to_owned();
    if name.is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        anyhow::bail!("--name: 1 a 255 caracteres, sem caracteres de controlo");
    }
    Ok(Args { email, name })
}

/// Entrada do operador: terminal (password sem eco) ou, sem terminal, linhas do stdin.
struct Input {
    tty: bool,
}

impl Input {
    fn line(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        let mut out = std::io::stdout();
        write!(out, "{prompt}")?;
        out.flush()?;
        let mut line = Zeroizing::new(String::new());
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            anyhow::bail!("entrada terminada");
        }
        Ok(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_owned(),
        ))
    }

    fn secret(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        if self.tty {
            Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
        } else {
            self.line(prompt)
        }
    }
}

/// Verificação de passwords vazadas: HIBP estrito (serviço em baixo → aborta) ou, SÓ com
/// `APP_ENV=test`, nenhuma (com aviso no stderr).
enum Breach {
    Strict(HibpRange),
    TestOnlyOff,
}

/// Password confirmada, validada, não vazada → PHC Argon2id.
async fn password_phc(input: &Input, breach: &Breach) -> anyhow::Result<String> {
    let a = input.secret("Password do super_admin: ")?;
    let b = input.secret("Repetir a password: ")?;
    if *a != *b {
        anyhow::bail!("as passwords não coincidem");
    }
    drop(b);
    let pw = Password::parse(&a)
        .map_err(|_| anyhow::anyhow!("password inválida (8 a 128 caracteres)"))?;
    drop(a);
    let breached = match breach {
        Breach::Strict(h) => h
            .check_strict(&pw)
            .await
            .map_err(|_| anyhow::anyhow!("HIBP indisponível: nada foi criado"))?,
        Breach::TestOnlyOff => NullBreachChecker.is_breached(&pw).await,
    };
    if breached {
        anyhow::bail!("esta password aparece em fugas de dados conhecidas; escolha outra");
    }
    password::hash(&pw)
        .await
        .map_err(|_| anyhow::anyhow!("hash da password falhou"))
}

/// Enroll no terminal: mostra o segredo e exige um código certo (até 3 tentativas).
/// Devolve o segredo e o passo TOTP aceite (para a marca anti-repetição).
fn enroll(
    input: &Input,
    account: &str,
) -> anyhow::Result<(Zeroizing<[u8; totp::SECRET_BYTES]>, u64)> {
    let mut secret = Zeroizing::new([0u8; totp::SECRET_BYTES]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|_| anyhow::anyhow!("CSPRNG do SO indisponível"))?;
    let b32 = Zeroizing::new(totp::base32_encode(secret.as_ref()));
    let uri = Zeroizing::new(totp::otpauth_uri(account, &b32));
    let mut out = std::io::stdout();
    writeln!(out, "Configure a app de autenticação (mostrado só agora):")?;
    writeln!(out, "otpauth: {}", uri.as_str())?;
    writeln!(out, "segredo: {}", b32.as_str())?;
    out.flush()?;
    for left in (0..TOTP_TRIES).rev() {
        let typed = input.line("Código de 6 dígitos: ")?;
        let now = totp::step_at(std::time::SystemTime::now());
        if let Some(step) =
            totp::parse_totp(&typed).and_then(|c| totp::matching_step(secret.as_ref(), now, c))
        {
            return Ok((secret, step));
        }
        writeln!(out, "Código errado ({left} tentativa(s) restante(s)).")?;
    }
    anyhow::bail!("TOTP não confirmado: nada foi criado")
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    match e {
        sqlx::Error::Database(db) => db.code().map(|c| c.into_owned()),
        _ => None,
    }
}

/// Marca o passo do enroll no Redis da API (o mesmo código não volta a entrar no `/verify`). Redis
/// em baixo → aviso e espera o TTL da marca antes de mostrar os códigos (o código já expirou).
async fn mark_enroll_step(cfg: &Config, user: Uuid, step: u64) {
    // Prefixo das chaves: vazio (o da API em produção); só com APP_ENV=test se aceita outro.
    let ns = if cfg.app_env == AppEnv::Test {
        std::env::var("PTMARKET_TEST_REDIS_NS").unwrap_or_default()
    } else {
        String::new()
    };
    let marked = match deadpool_redis::Config::from_url(cfg.redis_url.expose_secret())
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
    {
        Ok(pool) => totp::mark_step(&pool, &ns, user, step).await.is_ok(),
        Err(_) => false,
    };
    if !marked {
        let mut err = std::io::stderr();
        let _ = writeln!(
            err,
            "aviso: Redis indisponível; a aguardar {} s antes de mostrar os códigos (o código do enroll expira).",
            totp::REPLAY_TTL.as_secs()
        );
        tokio::time::sleep(totp::REPLAY_TTL).await;
    }
}

async fn create_superadmin(args: Args) -> anyhow::Result<Zeroizing<Vec<String>>> {
    let cfg = Config::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;
    let key = EncKey::from_base64(&cfg.totp_enc_key())
        .and_then(|k| k.with_old(&cfg.totp_enc_keys_old))
        .map_err(|_| anyhow::anyhow!("TOTP_ENC_KEY/TOTP_ENC_KEYS_OLD inválida"))?;
    let rec_key =
        RecoveryKey::from_enc_key(&key).map_err(|_| anyhow::anyhow!("subchave indisponível"))?;
    let url = Zeroizing::new(
        std::env::var("ADMIN_DATABASE_URL")
            .ok()
            .filter(|v| v.starts_with("postgres://") || v.starts_with("postgresql://"))
            .ok_or_else(|| anyhow::anyhow!("ADMIN_DATABASE_URL em falta ou inválida"))?,
    );
    let email = email::normalize(&args.email).map_err(|_| anyhow::anyhow!("--email inválido"))?;

    // Papel antes de pedir segredos: nunca o da API nem o do worker.
    let mut conn = PgConnection::connect(&url)
        .await
        .map_err(|_| anyhow::anyhow!("ligação à BD falhou (ADMIN_DATABASE_URL)"))?;
    let (session_user, current_user): (String, String) =
        sqlx::query_as("SELECT session_user::text, current_user::text")
            .fetch_one(&mut conn)
            .await?;
    if FORBIDDEN_ROLES.contains(&session_user.as_str())
        || FORBIDDEN_ROLES.contains(&current_user.as_str())
    {
        anyhow::bail!("ADMIN_DATABASE_URL é um papel da API/worker: recusado");
    }
    let operator: Option<bool> = sqlx::query_scalar(
        "SELECT (NOT r.rolsuper AND pg_has_role(session_user, 'ptmarket_operator', 'SET'))::boolean
         FROM pg_catalog.pg_roles r WHERE r.rolname = session_user",
    )
    .fetch_optional(&mut conn)
    .await
    .ok()
    .flatten();
    if operator != Some(true) {
        anyhow::bail!(
            "ADMIN_DATABASE_URL: o papel tem de poder assumir ptmarket_operator e não ser superuser: recusado"
        );
    }

    let input = Input {
        tty: std::io::stdin().is_terminal(),
    };
    let breach = if cfg.app_env == AppEnv::Test {
        let _ = writeln!(
            std::io::stderr(),
            "AVISO: APP_ENV=test — a verificação de passwords vazadas (HIBP) está DESLIGADA."
        );
        Breach::TestOnlyOff
    } else {
        Breach::Strict(HibpRange::new().map_err(|_| anyhow::anyhow!("HIBP indisponível"))?)
    };
    let phc = Zeroizing::new(password_phc(&input, &breach).await?);

    let id = Uuid::now_v7();
    let (secret, step) = enroll(&input, &email)?;
    let secret_enc = key
        .encrypt(secret.as_ref(), id.as_bytes())
        .map_err(|_| anyhow::anyhow!("cifra do segredo falhou"))?;
    drop(secret);
    let codes = Zeroizing::new(
        recovery::new_codes(recovery::CODES)
            .map_err(|_| anyhow::anyhow!("CSPRNG do SO indisponível"))?,
    );
    let hashes = Zeroizing::new(
        codes
            .iter()
            .map(|c| recovery::hash_code(&rec_key, id, c).map(|h| h.to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow::anyhow!("hash dos códigos falhou"))?,
    );

    let mut tx = conn.begin().await?;
    sqlx::query!("SET LOCAL ROLE ptmarket_operator")
        .execute(&mut *tx)
        .await?;
    let r = sqlx::query(
        "SELECT public.identity_create_superadmin($1::uuid, $2::text, $3::text, $4::text, $5::text, $6::bytea[])",
    )
    .bind(id)
    .bind(&email)
    .bind(&args.name)
    .bind(phc.as_str())
    .bind(&secret_enc)
    .bind(hashes.as_slice())
    .execute(&mut *tx)
    .await;
    match r {
        Ok(_) => {}
        Err(e) => {
            let msg = match sqlstate(&e).as_deref() {
                Some("23505") => "email já existe".to_owned(),
                Some("22023") => match &e {
                    sqlx::Error::Database(db)
                        if db.message().starts_with("identity_create_superadmin:") =>
                    {
                        format!("dados recusados: {}", db.message())
                    }
                    _ => "dados recusados".to_owned(),
                },
                _ => "a BD recusou a criação".to_owned(),
            };
            anyhow::bail!("{msg}");
        }
    }
    tx.commit().await?;
    mark_enroll_step(&cfg, id, step).await;
    Ok(codes)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let res = match parse_args(&argv) {
        Ok(args) => create_superadmin(args).await,
        Err(e) => Err(e),
    };
    let mut out = std::io::stdout();
    match res {
        Ok(codes) => {
            // Só depois do COMMIT, uma vez.
            let _ = writeln!(out, "super_admin criado com TOTP ativo.");
            let _ = writeln!(
                out,
                "Códigos de recuperação (mostrados só agora; guardar fora deste computador):"
            );
            for c in codes.iter() {
                let _ = writeln!(out, "  {c}");
            }
            let _ = out.flush();
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            // As mensagens acima nunca incluem a password, a URL, os hashes nem o segredo.
            let _ = writeln!(std::io::stderr(), "erro: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
