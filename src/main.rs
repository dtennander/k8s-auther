use anyhow::{Context, Ok, Result, anyhow};
use chrono::{DateTime, Utc};
use clap::Parser;
use dirs::home_dir;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use k8s_auther::exec_credentials::ExecCredential;
use k8s_auther::issuer::Issuer;
use k8s_auther::token_data::{AsFetchStep, TokenData, TokenFetchStep};
use serde::Deserialize;
use std::borrow::Borrow;
use std::io::Write;
use std::path::PathBuf;

/// Authenticate to an OpenID Connect provider and print the id-token
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// OIDC Issuer URL
    #[arg(long)]
    issuer_url: String,

    /// OIDC Client ID
    #[arg(long)]
    client_id: String,

    /// OIDC Scopes
    #[arg(long, default_value = "openid")]
    scopes: String,
}

const REDIRECT_URL: &str = "http://localhost:8080/callback";

fn main() -> Result<()> {
    let args = Args::parse();
    let issuer = Issuer::new(
        args.issuer_url.clone(),
        args.client_id.clone(),
        REDIRECT_URL.to_string(),
    )
    .context("Create issuer")?;

    let existing_token = TokenData::from_path(get_token_path())?;
    let token_data = match existing_token.get_fetch_step(&args.client_id) {
        TokenFetchStep::UseAvailableToken(_) => {
            existing_token.ok_or(anyhow!("Failed to find token"))
        }
        TokenFetchStep::Refresh(refresh_token) => issuer
            .refresh(&refresh_token)
            .or_else(|_| issuer.reauth(args.scopes.split_whitespace().collect()))
            .and_then(save_token_data),
        TokenFetchStep::ReAuth => issuer
            .reauth(args.scopes.split_whitespace().collect())
            .and_then(save_token_data),
    }?;
    // Output id-token to stdout
    if let Some(id_token) = token_data.id_token {
        print_on_json_form(&id_token)?;
    } else {
        eprintln!("No id-token received");
    }
    Ok(())
}

fn get_token_path() -> PathBuf {
    home_dir()
        .expect("Unable to determine config directory")
        .join(".config")
        .join("k8s-auther")
        .join("tokens.json")
}

fn save_token_data<D: Borrow<TokenData>>(data: D) -> Result<D> {
    let json = serde_json::to_string_pretty(data.borrow())?;
    let token_path = get_token_path();
    let token_parent = token_path.parent().context("no parrent")?;
    std::fs::create_dir_all(token_parent).context("Failed to create config directory")?;
    let mut file = std::fs::File::create(&token_path).context("Failed to create tokens.json")?;
    file.write_all(json.as_bytes())
        .context("Failed to write tokens.json")?;
    Ok(data)
}

/// Should print on this format:
/// {
///     "kind": "ExecCredential",
///     "apiVersion": "client.authentication.k8s.io/v1beta1",
///     "spec": {
///         "interactive": false
///     },
///     "status": {
///         "expirationTimestamp": "2025-08-01T22:33:59Z",
///         "token": "<TOKEN>"
///     }
/// }
fn print_on_json_form(id_token: &str) -> Result<()> {
    let expiration =
        get_token_expiration(id_token).context("failed to get expirationTimestamp...")?;
    let credentials = ExecCredential::new(id_token.to_string(), expiration);
    let data =
        serde_json::to_string_pretty(&credentials).context("Failed to serialise credentials")?;
    println!("{}", data);
    Ok(())
}

#[derive(Deserialize, Debug)]
struct Claims {
    exp: i64,
}

fn get_token_expiration(token: &str) -> Result<DateTime<Utc>> {
    let mut validation = Validation::new(Algorithm::RS256); // or whatever algorithm
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.insecure_disable_signature_validation();
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(b""), &validation)?;
    Ok(DateTime::from_timestamp(token_data.claims.exp, 0).expect("Failed to format timestamp"))
}
