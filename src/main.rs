use chrono::DateTime;
use chrono::Utc;
use clap::Parser;
use dirs::home_dir;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use openidconnect::AuthorizationCode;
use openidconnect::PkceCodeChallenge;
use openidconnect::RefreshToken;
use openidconnect::TokenResponse;
use openidconnect::core::*;
use openidconnect::core::{CoreClient, CoreResponseType};
use openidconnect::reqwest;
use openidconnect::{
    AuthenticationFlow, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl,
    Scope,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TokenData {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    // Discover issuer metadata

    // Attempt token refresh
    let token_data = get_token_data(args.client_id, args.issuer_url, args.scopes).await;
    save_token_data(&token_data);
    // Output id-token to stdout
    if let Some(id_token) = &token_data.id_token {
        print_on_json_form(id_token);
    } else {
        eprintln!("No id-token received");
    }
}

async fn get_token_data(client_id: String, issuer_url: String, scopes: String) -> TokenData {
    let exisiting_token = get_existing_token();
    // Do we have a valid token?
    if let Some(TokenData {
        id_token: Some(id_token),
        ..
    }) = &exisiting_token
    {
        let mut validator = Validation::new(Algorithm::HS256);
        validator.insecure_disable_signature_validation();
        validator.validate_aud = false;
        if decode::<Value>(id_token, &DecodingKey::from_secret(b""), &validator).is_ok() {
            return exisiting_token.unwrap();
        }
    }
    //
    // Now we will need to talk to someone...
    let async_http_client = reqwest::Client::new();
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer_url.clone()).expect("Invalid issuer URL"),
        &async_http_client,
    )
    .await
    .expect("Failed to discover OIDC provider");
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.clone()),
        None,
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URL.to_string()).expect("Invalid redirect URI"));

    // Try to refresh:
    if let Some(TokenData {
        refresh_token: Some(refresh_token),
        ..
    }) = exisiting_token
    {
        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .expect("Refreshtoken is wrong")
            .request_async(&async_http_client)
            .await;
        if let Ok(token_response) = token_result {
            return TokenData {
                id_token: token_response.id_token().map(|t| t.to_string()),
                access_token: Some(token_response.access_token().secret().to_string()),
                refresh_token: token_response
                    .refresh_token()
                    .map(|t| t.secret().to_string()),
                expires_in: token_response.expires_in().map(|d| d.as_secs()),
                scope: token_response.scopes().map(|scopes| {
                    scopes
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
            };
        };
    }
    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Build the authorization URL
    let mut auth_req = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge);
    for scope in scopes.split_whitespace() {
        auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
    }
    let (auth_url, csrf_token, _) = auth_req.url();
    if open::that(auth_url.as_str()).is_ok() {
        eprintln!("Trying to open browser...");
    }

    // Listen for the redirect
    let code = await_callback(csrf_token);

    // Exchange the code for tokens
    let token_request = client
        .exchange_code(AuthorizationCode::new(code.clone()))
        .expect("Failed to start token exchange");
    let token_response = token_request
        .set_pkce_verifier(pkce_verifier)
        .request_async(&async_http_client)
        .await
        .expect("Failed to exchange code for token");

    // Store all token data

    TokenData {
        id_token: token_response.id_token().map(|t| t.to_string()),
        access_token: Some(token_response.access_token().secret().to_string()),
        refresh_token: token_response
            .refresh_token()
            .map(|t| t.secret().to_string()),
        expires_in: token_response.expires_in().map(|d| d.as_secs()),
        scope: token_response.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        }),
    }
}

fn get_token_path() -> PathBuf {
    home_dir()
        .expect("Unable to determine config directory")
        .join(".config")
        .join("k8s-auther")
        .join("tokens.json")
}

fn get_existing_token() -> Option<TokenData> {
    let token_path = get_token_path();
    if !token_path.exists() {
        return None;
    }
    let file = std::fs::File::open(&token_path).expect("Failed to open tokens.json");
    serde_json::from_reader(file).expect("Failed to parse tokens.json")
}

fn save_token_data(data: &TokenData) {
    let json = serde_json::to_string_pretty(&data).expect("Failed to serialize token data");
    let token_path = get_token_path();
    let token_parent = token_path.parent().expect("no parrent");
    std::fs::create_dir_all(token_parent).expect("Failed to create config directory");
    let mut file = std::fs::File::create(&token_path).expect("Failed to create tokens.json");
    file.write_all(json.as_bytes())
        .expect("Failed to write tokens.json");
}

fn await_callback(csrf_token: CsrfToken) -> String {
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port 8080");
    let mut stream = listener.accept().expect("Failed to accept connection").0;
    let mut req = [0; 1024];
    let len = stream.read(&mut req).expect("Failed to read stream");
    let req = String::from_utf8_lossy(&req[..len]);
    let url_line = req.lines().next().unwrap();
    let url_part = url_line.split_whitespace().nth(1).unwrap();
    let url = Url::parse(&format!("http://localhost:8080{}", url_part))
        .expect("Failed to parse redirect URL");
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();

    let code = params.get("code").expect("No code in callback");
    let state = params.get("state").expect("No state (CSRF) in callback");
    assert_eq!(state, csrf_token.secret(), "CSRF token mismatch!");
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nAuthentication complete. You can close this window.";
    let ok = stream.write(response.as_bytes());
    if ok.is_err() {
        eprintln!("Failed to write back: {:?}", ok);
    }
    code.to_owned()
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    kind: String,
    api_version: String,
    spec: ExecCredentialSpec,
    status: ExecCredentialsStatus,
}
impl ExecCredential {
    fn new(token: String, expiration_timestamp: DateTime<Utc>) -> Self {
        Self {
            kind: "ExecCredential".to_string(),
            api_version: "client.authentication.k8s.io/v1beta1".to_string(),
            spec: ExecCredentialSpec { interactive: false },
            status: ExecCredentialsStatus {
                token,
                expiration_timestamp: expiration_timestamp
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ExecCredentialSpec {
    interactive: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ExecCredentialsStatus {
    token: String,
    expiration_timestamp: String,
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
fn print_on_json_form(id_token: &str) {
    let expiration = get_token_expiration(id_token).expect("failed to get expirationTimestamp...");
    let credentials = ExecCredential::new(id_token.to_string(), expiration);
    let data = serde_json::to_string_pretty(&credentials).expect("Failed to serialise credentials");
    println!("{}", data);
}

#[derive(Deserialize, Debug)]
struct Claims {
    exp: i64,
}

fn get_token_expiration(token: &str) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    let mut validation = Validation::new(Algorithm::RS256); // or whatever algorithm
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.insecure_disable_signature_validation();
    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(b""), &validation)?;

    Ok(DateTime::from_timestamp(token_data.claims.exp, 0).expect("Failed to format timestamp"))
}
