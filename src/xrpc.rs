use std::collections::HashMap;

use anyhow::{anyhow, Result};
use json_patch::merge;
use serde_json::json;

pub struct PdsClient {
    pub http_client: reqwest::Client,
    pub pds: String,
    pub access_jwt: String,
}

#[derive(serde::Deserialize)]
enum WrappedCredentialResponse {
    #[serde(untagged)]
    CredentialResponse {
        #[serde(rename = "accessJwt")]
        access_jwt: String,
        _handle: String,
        _did: String,
    },

    #[serde(untagged)]
    Other {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(serde::Deserialize)]
enum WrappedDescribeServerResponse {
    #[serde(untagged)]
    DescribeServerResponse {
        did: String,
        #[serde(rename = "inviteCodeRequired")]
        invite_code_required: bool,
        #[serde(rename = "availableUserDomains")]
        available_user_domains: Vec<String>,
    },

    #[serde(untagged)]
    Other {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(serde::Deserialize)]
enum WrappedCreateAccountResponse {
    #[serde(untagged)]
    CreateAccountResponse {
        did: String,
        handle: String,
        #[serde(rename = "accessJwt")]
        access_jwt: String,
    },

    #[serde(untagged)]
    Other {
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    },
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct WrappedOperation {
    pub operation: serde_json::Value,
}

impl PdsClient {
    pub async fn from_credentials(
        http_client: &reqwest::Client,
        pds: &str,
        did: &str,
        password: &str,
    ) -> Result<Self> {
        let create_session_uri = format!("{}/xrpc/com.atproto.server.createSession", pds);

        let mut body = HashMap::new();
        body.insert("identifier", did);
        body.insert("password", password);

        let response: WrappedCredentialResponse = http_client
            .post(create_session_uri)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let access_jwt = match response {
            WrappedCredentialResponse::CredentialResponse { access_jwt, .. } => Ok(access_jwt),
            WrappedCredentialResponse::Other { extra } => {
                Err(anyhow!("Unexpected response from PDS: {:?}", extra))
            }
        }?;

        Ok(Self {
            http_client: http_client.clone(),
            pds: pds.to_string(),
            access_jwt,
        })
    }

    pub async fn request_plc_op_sig(&self) -> Result<()> {
        let request_plc_op_sig_uri = format!(
            "{}/xrpc/com.atproto.identity.requestPlcOperationSignature",
            self.pds
        );

        self.http_client
            .post(request_plc_op_sig_uri)
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .send()
            .await
            .map(|_| ())
            .map_err(|err| err.into())
    }

    pub async fn sign_plc_op(
        &self,
        did_doc: &serde_json::Value,
        token: &str,
    ) -> Result<serde_json::Value> {
        let request_plc_op_sig_uri =
            format!("{}/xrpc/com.atproto.identity.signPlcOperation", self.pds);

        let token_patch = json!({
            "token": token,
        });
        let mut request_body = did_doc.clone();
        merge(&mut request_body, &token_patch);

        let wrapped_operation: WrappedOperation = self
            .http_client
            .post(request_plc_op_sig_uri)
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .json(&request_body)
            .send()
            .await?
            .json()
            .await?;
        Ok(wrapped_operation.operation)
    }

    pub async fn submit_plc_op(&self, operation: &serde_json::Value) -> Result<()> {
        let submit_plc_op_uri =
            format!("{}/xrpc/com.atproto.identity.submitPlcOperation", self.pds);

        let wrapped_operation = WrappedOperation {
            operation: operation.clone(),
        };

        self.http_client
            .post(submit_plc_op_uri)
            .header("Authorization", format!("Bearer {}", self.access_jwt))
            .json(&wrapped_operation)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| err.into())
    }
}

pub(crate) async fn describe_server(
    http_client: &reqwest::Client,
    pds_hostname: &str,
) -> Result<(String, bool, Vec<String>)> {
    let uri = format!(
        "https://{}/xrpc/com.atproto.server.describeServer",
        pds_hostname
    );
    let wrapped_response: WrappedDescribeServerResponse =
        http_client.get(uri).send().await?.json().await?;

    match wrapped_response {
        WrappedDescribeServerResponse::DescribeServerResponse {
            did,
            invite_code_required,
            available_user_domains,
        } => Ok((did, invite_code_required, available_user_domains)),
        WrappedDescribeServerResponse::Other { extra } => {
            println!("Unexpected response from PDS: {:?}", extra);
            Err(anyhow!("Unexpected response from PDS"))
        }
    }
}

#[derive(serde::Serialize)]
struct CreateAccountRequest {
    handle: String,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did: Option<String>,
    #[serde(rename = "inviteCode", skip_serializing_if = "Option::is_none")]
    invite_code: Option<String>,
    password: String,
    #[serde(rename = "recoveryKey")]
    recovery_key: String,
}

// TODO: Use a request object here.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_account(
    http_client: &reqwest::Client,
    pds_hostname: &str,
    handle: &str,
    password: &str,
    email: &str,
    recovery_key: &str,
    invite_code: Option<String>,
    did: Option<String>,
) -> Result<(String, String, String)> {
    let uri = format!(
        "https://{}/xrpc/com.atproto.server.createAccount",
        pds_hostname
    );

    let payload = CreateAccountRequest {
        handle: handle.to_string(),
        email: email.to_string(),
        did,
        invite_code,
        password: password.to_string(),
        recovery_key: recovery_key.to_string(),
    };

    let wrapped_response: WrappedCreateAccountResponse = http_client
        .post(uri)
        .json(&payload)
        .send()
        .await?
        .json()
        .await?;

    match wrapped_response {
        WrappedCreateAccountResponse::CreateAccountResponse {
            did,
            handle,
            access_jwt,
        } => Ok((did, handle, access_jwt)),
        WrappedCreateAccountResponse::Other { extra } => {
            println!("Unexpected response from PDS: {:?}", extra);
            Err(anyhow!("Unexpected response from PDS"))
        }
    }
}
