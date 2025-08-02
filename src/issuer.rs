use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;

use anyhow::{Context, Result, anyhow};
use openidconnect::AuthenticationFlow;
use openidconnect::AuthorizationCode;
use openidconnect::CsrfToken;
use openidconnect::Nonce;
use openidconnect::OAuth2TokenResponse;
use openidconnect::PkceCodeChallenge;
use openidconnect::RefreshToken;
use openidconnect::Scope;
use openidconnect::TokenResponse;
use openidconnect::core::CoreResponseType;
use openidconnect::{
    ClientId, IssuerUrl, RedirectUrl,
    core::{CoreClient, CoreProviderMetadata},
};
use reqwest::Url;
use reqwest::blocking::Client;

use crate::token_data::TokenData;

pub struct Issuer {
    http_client: Client,
    issuer_url: IssuerUrl,
    client_id: ClientId,
    redirect_url: RedirectUrl,
}

impl Issuer {
    pub fn new(issuer_url: String, client_id: String, redirect_url: String) -> Result<Issuer> {
        let http_client: Client = Client::new();

        Ok(Self {
            http_client,
            issuer_url: IssuerUrl::new(issuer_url)?,
            client_id: ClientId::new(client_id),
            redirect_url: RedirectUrl::new(redirect_url)?,
        })
    }

    pub fn refresh(&self, refresh_token: &str) -> Result<TokenData> {
        let provider_metadata = CoreProviderMetadata::discover(&self.issuer_url, &self.http_client)
            .context("Failed to discover OIDC provider")?;
        let token_response =
            CoreClient::from_provider_metadata(provider_metadata, self.client_id.clone(), None)
                .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))?
                .request(&self.http_client)?;
        Ok(TokenData {
            id_token: token_response.id_token().map(|t| t.to_string()),
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    pub fn reauth(&self, scopes: Vec<&str>) -> Result<TokenData> {
        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let provider_metadata = CoreProviderMetadata::discover(&self.issuer_url, &self.http_client)
            .context("Failed to discover OIDC provider")?;
        let client =
            CoreClient::from_provider_metadata(provider_metadata, self.client_id.clone(), None)
                .set_redirect_uri(self.redirect_url.clone());
        let mut auth_req = client
            .authorize_url(
                AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge);
        for scope in scopes {
            auth_req = auth_req.add_scope(Scope::new(scope.to_string()));
        }
        let (auth_url, csrf_token, _) = auth_req.url();
        open::that(auth_url.as_str())?;
        // Listen for the redirect
        let (code, returned_token) = self.await_callback()?;
        if csrf_token.secret() != returned_token.secret() {
            return Err(anyhow!("CSRF Token mismatch!"));
        }
        let token_response = client
            .exchange_code(code)?
            .set_pkce_verifier(pkce_verifier)
            .request(&self.http_client)?;
        Ok(TokenData {
            id_token: token_response.id_token().map(|t| t.to_string()),
            access_token: Some(token_response.access_token().secret().to_string()),
            refresh_token: token_response
                .refresh_token()
                .map(|t| t.secret().to_string()),
            scope: token_response.scopes().map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    fn await_callback(&self) -> Result<(AuthorizationCode, CsrfToken)> {
        let (mut stream, _) = TcpListener::bind("127.0.0.1:8080")?.accept()?;
        let mut req = String::new();
        stream.read_to_string(&mut req)?;
        let url_line = req.lines().next().context("Tried to get url_line")?;
        let url = Url::parse(&format!(
            "http://127.0.0.1:8080{}",
            url_line
                .split_whitespace()
                .nth(1)
                .context("Should find path after first space")?
        ))?;
        let params: HashMap<_, _> = url.query_pairs().collect();
        let code = params.get("code").context("we should get a code")?;
        let state = params.get("state").context("we should get a state")?;
        stream.write_all(
            b"HTTP/1.1 200 OK
Content-Type: text/html

Authentication complete. You can close this window.
        ",
        )?;
        stream.flush()?;
        Ok((
            AuthorizationCode::new(code.to_string()),
            CsrfToken::new(state.to_string()),
        ))
    }
}
