use std::path::PathBuf;

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenData {
    pub id_token: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) refresh_token: Option<String>,
    pub(crate) scope: Option<String>,
}

impl TokenData {
    pub fn from_path(path: PathBuf) -> Result<Option<TokenData>> {
        if !path.exists() {
            return Ok(None);
        }
        let file = std::fs::File::open(path).context("Failed to open tokens.json")?;
        serde_json::from_reader(file).context("Failed to parse tokens.json")
    }
}

pub enum TokenFetchStep {
    UseAvailableToken(String),
    Refresh(String),
    ReAuth,
}

pub trait AsFetchStep {
    fn get_fetch_step(&self, audiance: &str) -> TokenFetchStep;
}

impl AsFetchStep for TokenData {
    fn get_fetch_step(&self, audiance: &str) -> TokenFetchStep {
        self.id_token
            .as_ref()
            .filter(|t| Self::is_insecure_valid_token(audiance, t))
            .map(|t| TokenFetchStep::UseAvailableToken(t.clone()))
            .or(self
                .refresh_token
                .as_ref()
                .map(|t| TokenFetchStep::Refresh(t.clone())))
            .unwrap_or(TokenFetchStep::ReAuth)
    }
}

impl TokenData {
    fn is_insecure_valid_token(audiance: &str, token: &str) -> bool {
        let mut validator = Validation::new(Algorithm::HS256);
        // Validation will be done on the reciving end, we just want to make sure it is valid
        validator.insecure_disable_signature_validation();
        validator.set_audience(&[audiance]);
        decode::<Value>(token, &DecodingKey::from_secret(b""), &validator).is_ok()
    }
}

impl AsFetchStep for Option<TokenData> {
    fn get_fetch_step(&self, audiance: &str) -> TokenFetchStep {
        self.as_ref()
            .map(|td| td.get_fetch_step(audiance))
            .unwrap_or(TokenFetchStep::ReAuth)
    }
}
