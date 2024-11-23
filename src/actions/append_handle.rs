use anyhow::{Context, Result};
use async_trait::async_trait;
use json_patch::{patch, Patch};
use serde_json::{from_value, json};

use crate::{
    actions::{get_did_plc_input, get_handle_input, get_jwk_input, TandemAction, Theme},
    crypto::sign_operation,
    plc::{did_plc_last_operation, submit_operation},
};

pub(crate) struct ActionAppendHandle<'a> {
    theme: &'a Theme<'a>,
    http_client: reqwest::Client,
    plc: String,
}

impl<'a> ActionAppendHandle<'a> {
    pub(crate) fn new(theme: &'a Theme<'_>, http_client: &reqwest::Client, plc: &str) -> Self {
        Self {
            theme,
            http_client: http_client.clone(),
            plc: plc.to_string(),
        }
    }
}

#[async_trait]
impl TandemAction for ActionAppendHandle<'_> {
    async fn run(&self) -> Result<()> {
        println!(
        "{}",
            self.theme
                .white_dim
                .apply_to("The 'Append Handle' action appends an additional handle to the 'alsoKnownAs' field in your DID-PLC document. This action requires your tandem private key.")
        );

        let did = get_did_plc_input(self.theme.colorful_theme, "What is your DID?")?;
        let jwk = get_jwk_input(self.theme.colorful_theme)?;
        let new_handle = get_handle_input(
            self.theme.colorful_theme,
            "What is the new handle being added?",
        )?;

        let did_key = crate::crypto::p256::jwk_to_did_key(&jwk)?;
        println!(
            "{}",
            self.theme.green.apply_to("✔ Derived DID key")
        );
        println!(
            "{}",
            self.theme.white_dim.apply_to(&did_key)
        );


        let (last_commit, last_operation) =
            did_plc_last_operation(&self.http_client, &self.plc, &did).await?;
        println!(
            "{}",
            self.theme.green.apply_to("✔ Retreived last operation")
        );
        println!(
            "{}",
            self.theme.white_dim.apply_to(&last_commit)
        );
        println!(
            "{}",
            self.theme.white_dim.apply_to(
                serde_json::to_string_pretty(&last_operation)
                    .context("failed to serialize DID document")?
            )
        );

        let operation_patch: Patch = from_value(json!([
            { "op": "add", "path": "/alsoKnownAs/-", "value": format!("at://{}", new_handle) },
            { "op": "remove", "path": "/sig" },
            { "op": "replace", "path": "/prev", "value": last_commit },
        ]))
        .context("failed to create patch to append handle")?;

        let mut operation = last_operation.clone();

        patch(&mut operation, &operation_patch)?;
        println!(
            "{}",
            self.theme
                .green
                .apply_to("✔ Prepared operation for signing")
        );
        println!(
            "{}",
            self.theme.white_dim.apply_to(
                serde_json::to_string_pretty(&operation)
                    .context("failed to serialize DID document")?
            )
        );

        let signed_operation = sign_operation(&jwk, &operation)?;
        println!("{}", self.theme.green.apply_to("✔ Signed operation"));
        println!(
            "{}",
            self.theme.white_dim.apply_to(
                serde_json::to_string_pretty(&signed_operation)
                    .context("failed to serialize DID document")?
            )
        );

        submit_operation(&self.http_client, &self.plc, &did, &signed_operation).await?;
        println!("{}", self.theme.green.apply_to("✔ Operation submitted"));

        Ok(())
    }
}
