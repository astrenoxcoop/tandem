use anyhow::{Context, Result};
use async_trait::async_trait;
use dialoguer::{Input, Password, Select};
use json_patch::{patch, Patch};
use serde_json::{from_value, json};

use crate::{
    actions::{get_handle_input, TandemAction, Theme},
    plc::did_plc_data,
    resolve::resolve_handle,
    xrpc::PdsClient,
};

pub(crate) struct ActionPrepare<'a> {
    theme: &'a Theme<'a>,
    http_client: reqwest::Client,
    plc: String,
}

impl<'a> ActionPrepare<'a> {
    pub(crate) fn new(theme: &'a Theme<'_>, http_client: &reqwest::Client, plc: &str) -> Self {
        Self {
            theme,
            http_client: http_client.clone(),
            plc: plc.to_string(),
        }
    }
}

#[async_trait]
impl TandemAction for ActionPrepare<'_> {
    async fn run(&self) -> Result<()> {
        println!(
        "{}",
            self.theme
                .white_dim
                .apply_to("The 'Install Tandem Key' action will generate a rotation key and update your DID-PLC document with it.")
        );

        let handle = get_handle_input(self.theme.colorful_theme, "What is your handle?")?;

        println!(
            "{}",
            self.theme
                .yellow_bold
                .apply_to("Your password is required to authenticate with your PDS. This cannot be an application password or OAuth token.")
        );

        let password = Password::with_theme(self.theme.colorful_theme)
            .with_prompt("What is your password?")
            .interact()?;

        let key_types = &["p256", "k256"];

        let key_type = Select::with_theme(self.theme.colorful_theme)
            .with_prompt("Select key type")
            .default(0)
            .items(&key_types[..])
            .interact()?;

        let key_positions = &["first", "last"];

        let key_position = Select::with_theme(self.theme.colorful_theme)
            .with_prompt("Select key position")
            .default(0)
            .items(&key_positions[..])
            .interact()?;

        let resolved_handle = resolve_handle(&self.http_client, &self.plc, &handle)
            .await
            .context("failed to resolve handle")?;

        println!(
            "{}",
            self.theme.green.apply_to(format!(
                "✔ Resolved {} ({}) known as {}",
                resolved_handle.did,
                resolved_handle.pds,
                resolved_handle.handles.join(" ")
            )),
        );

        let pds_client = PdsClient::from_credentials(
            &self.http_client,
            &resolved_handle.pds,
            &resolved_handle.did,
            &password,
        )
        .await
        .context("failed to authenticate against PDS")?;

        let (secret_pem, encoded_public_key) = if key_type == 0 {
            crate::crypto::p256::gen_key()?
        } else {
            crate::crypto::k256::gen_key()?
        };

        println!(
            "{}",
            self.theme
                .yellow_bold
                .apply_to("Important! Securely store the following private key."),
        );
        println!("{}", self.theme.red_bold.apply_to(&secret_pem));

        let mut did_doc_data = did_plc_data(&self.http_client, &self.plc, &resolved_handle.did)
            .await
            .context("failed to get DID document")?;

        let key_path = if key_position == 0 {
            "/rotationKeys/0".to_string()
        } else {
            "/rotationKeys/-".to_string()
        };

        let did_doc_data_patch: Patch = from_value(json!([
          { "op": "add", "path": key_path, "value": format!("did:key:{}", encoded_public_key) }
        ]))
        .context("failed to create patch")?;

        patch(&mut did_doc_data, &did_doc_data_patch).context("failed to apply patch")?;

        println!("{}", self.theme.green.apply_to("✔ Created patch document"));
        println!(
            "{}",
            self.theme.white_dim.apply_to(
                serde_json::to_string_pretty(&did_doc_data)
                    .context("failed to serialize DID document")?
            )
        );

        pds_client
            .request_plc_op_sig()
            .await
            .context("failed to request PLC signing operation")?;

        println!(
            "{}",
            self.theme.yellow_bold.apply_to(
                "Important! Check your email for a confirmation code. Enter it below to continue."
            )
        );

        let token = Input::<String>::with_theme(self.theme.colorful_theme)
            .with_prompt("Confirmation code")
            .interact()
            .context("failed to get confirmation code")?;

        let plc_operation = pds_client
            .sign_plc_op(&did_doc_data, &token)
            .await
            .context("failed to request PLC signing operation")?;

        println!(
            "{}",
            self.theme.green.apply_to("✔ Acquired signed PLC operation")
        );
        println!(
            "{}",
            self.theme.white_dim.apply_to(
                serde_json::to_string_pretty(&plc_operation)
                    .context("failed to serialize PLC operation")?
            )
        );

        pds_client
            .submit_plc_op(&plc_operation)
            .await
            .context("failed to submit PLC operation")?;

        println!(
            "{}",
            self.theme
                .green
                .apply_to("✔ Submitted signed PLC operation")
        );

        Ok(())
    }
}
