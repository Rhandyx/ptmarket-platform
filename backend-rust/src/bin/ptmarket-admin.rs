//! CLI de operação (cartão 02/20). Único comando:
//!
//! `ptmarket-admin create-superadmin --email <email> --name <nome>`
//!
//! - Liga com `ADMIN_DATABASE_URL` (papel DONO das tabelas, nunca o `ptmarket_app` da API; a API não
//!   tem INSERT em `users` nem escrita em `user_roles`).
//! - Password: pedida no terminal sem eco (duas vezes); NUNCA por argumento. Sem terminal (ex.:
//!   automação), lê uma linha do stdin.
//! - `Password::parse` + hash Argon2id; cria `users` + `user_roles('super_admin')` numa transação.
//!   Email já existente (sem distinção de maiúsculas) → recusa.
//! - TOTP por ativar: o 1.º login obriga ao enroll antes de qualquer rota `/api/v1/superadmin/*`.
//! - Caixa negra: ator `db` (L1, gatilho genérico) + pgaudit.

use std::io::{IsTerminal, Write};

use ptmarket_api::identity::{Password, email, password};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

const USAGE: &str = "uso: ptmarket-admin create-superadmin --email <email> --name <nome>";

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

/// Password do terminal (sem eco, confirmada) ou, sem terminal, uma linha do stdin.
fn read_password() -> anyhow::Result<Password> {
    let raw = if std::io::stdin().is_terminal() {
        let a = rpassword::prompt_password("Password do super_admin: ")?;
        let b = rpassword::prompt_password("Repetir a password: ")?;
        if a != b {
            anyhow::bail!("as passwords não coincidem");
        }
        a
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let pw = line.trim_end_matches(['\r', '\n']).to_owned();
        zeroize::Zeroize::zeroize(&mut line);
        pw
    };
    Password::parse(&raw).map_err(|_| anyhow::anyhow!("password inválida (8 a 128 caracteres)"))
}

async fn create_superadmin(args: Args) -> anyhow::Result<Uuid> {
    let url = std::env::var("ADMIN_DATABASE_URL")
        .ok()
        .filter(|v| v.starts_with("postgres://") || v.starts_with("postgresql://"))
        .ok_or_else(|| anyhow::anyhow!("ADMIN_DATABASE_URL em falta ou inválida"))?;
    let email = email::normalize(&args.email).map_err(|_| anyhow::anyhow!("--email inválido"))?;
    let pw = read_password()?;
    let phc = password::hash(&pw)
        .await
        .map_err(|_| anyhow::anyhow!("hash da password falhou"))?;
    drop(pw);

    let mut conn = PgConnection::connect(&url)
        .await
        .map_err(|_| anyhow::anyhow!("ligação à BD falhou (ADMIN_DATABASE_URL)"))?;
    let me = sqlx::query_scalar!(r#"SELECT current_user::text AS "u!""#)
        .fetch_one(&mut conn)
        .await?;
    if me == "ptmarket_app" {
        anyhow::bail!("ADMIN_DATABASE_URL é o papel da API (ptmarket_app): recusado");
    }
    let id = Uuid::now_v7();
    let mut tx = conn.begin().await?;
    // FORCE RLS: nem o dono escreve com ela. Desligada só dentro desta transação (DDL transacional;
    // o ROLLBACK repõe-na) e reposta antes do COMMIT.
    sqlx::query!("ALTER TABLE users NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles NO FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    let exists = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1)) AS "e!""#,
        email
    )
    .fetch_one(&mut *tx)
    .await?;
    if exists {
        tx.rollback().await?;
        anyhow::bail!("já existe uma conta com este email");
    }
    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, full_name) VALUES ($1, $2, $3, $4)",
        id,
        email,
        phc,
        args.name
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO user_roles (id, user_id, role) VALUES ($1, $2, 'super_admin')",
        Uuid::now_v7(),
        id
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("ALTER TABLE users FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    sqlx::query!("ALTER TABLE user_roles FORCE ROW LEVEL SECURITY")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let res = match parse_args(&argv) {
        Ok(args) => create_superadmin(args).await,
        Err(e) => Err(e),
    };
    match res {
        Ok(id) => {
            let mut out = std::io::stdout();
            let _ = writeln!(
                out,
                "super_admin criado: {id}. TOTP por ativar: no 1.º login, fazer o enroll."
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            // Nunca a password nem a URL (as mensagens acima não as incluem).
            let mut err = std::io::stderr();
            let _ = writeln!(err, "erro: {e}");
            let _ = std::io::stderr().flush();
            std::process::ExitCode::FAILURE
        }
    }
}
