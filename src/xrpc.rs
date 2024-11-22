use std::collections::HashMap;

use anyhow::{anyhow, Result};
use json_patch::merge;
use serde_json::json;

pub struct PdsClient {
    pub http_client: reqwest::Client,
    pub pds: String,
    pub did: String,
    pub handle: String,
    pub access_jwt: String,
}

#[derive(serde::Deserialize)]
enum WrappedCredentialResponse {
    #[serde(untagged)]
    CredentialResponse {
        #[serde(rename = "accessJwt")]
        access_jwt: String,
        handle: String,
        did: String,
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

        if let WrappedCredentialResponse::Other { extra } = response {
            println!("Unexpected response from PDS: {:?}", extra);
            return Err(anyhow!("Unexpected response from PDS"));
        }

        let (handle, did, access_jwt) = match response {
            WrappedCredentialResponse::CredentialResponse {
                handle,
                did,
                access_jwt,
                ..
            } => (handle, did, access_jwt),
            _ => unreachable!(),
        };

        Ok(Self {
            http_client: http_client.clone(),
            pds: pds.to_string(),
            handle,
            did,
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
