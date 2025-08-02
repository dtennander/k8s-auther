use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecCredential {
    kind: String,
    api_version: String,
    spec: ExecCredentialSpec,
    status: ExecCredentialsStatus,
}

impl ExecCredential {
    pub fn new(token: String, expiration_timestamp: DateTime<Utc>) -> Self {
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
