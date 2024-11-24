use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use dialoguer::{Confirm, Input, Password, Select};

use crate::{
    actions::{get_handle_input, get_jwk_input, TandemAction, Theme},
    xrpc::{create_account, describe_server},
};

pub(crate) struct ActionCreateAccount<'a> {
    theme: &'a Theme<'a>,
    http_client: reqwest::Client,
}

impl<'a> ActionCreateAccount<'a> {
    pub(crate) fn new(theme: &'a Theme<'_>, http_client: &reqwest::Client) -> Self {
        Self {
            theme,
            http_client: http_client.clone(),
        }
    }
}

#[async_trait]
impl TandemAction for ActionCreateAccount<'_> {
    async fn run(&self) -> Result<()> {
        println!(
            "{}",
            self.theme
                .white_dim
                .apply_to("The 'Create Account' creates an account on a PDS.")
        );

        let pds_hostname = get_handle_input(
            self.theme.colorful_theme,
            "What is the hostname of the PDS?",
        )?;

        let (_pds_did, invite_required, available_domains) =
            describe_server(&self.http_client, &pds_hostname)
                .await
                .context("Unable to describe server.")?;
        println!(
            "{}",
            self.theme.green.apply_to("✔ Retrieved PDS information")
        );

        if available_domains.is_empty() {
            println!(
                "{}",
                self.theme.red_bold.apply_to(
                    "This PDS does not have any available domains. It is probably misconfigured."
                )
            );
            return Ok(());
        }

        let invite_code = if invite_required {
            println!(
                "{}",
                self.theme
                    .yellow_bold
                    .apply_to("This PDS requires an invite code.")
            );

            let invite_code = Input::<String>::with_theme(self.theme.colorful_theme)
                .with_prompt("Invite Code")
                .interact()?;
            Some(invite_code)
        } else {
            None
        };

        let random_handle =
            petname::petname(2, "-").ok_or_else(|| anyhow!("Failed to generate random handle"))?;

        let suggested_handle = format!("{}{}", random_handle, available_domains[0]);

        let handle = Input::<String>::with_theme(self.theme.colorful_theme)
            .with_prompt("Handle")
            .default(suggested_handle)
            .interact()?;

        let email = Input::<String>::with_theme(self.theme.colorful_theme)
            .with_prompt("Email")
            .interact()?;

        let password = Password::with_theme(self.theme.colorful_theme)
            .with_prompt("Password")
            .interact()?;

        let existing_did = {
            if Confirm::with_theme(self.theme.colorful_theme)
                .with_prompt("Are you creating an account for an existing DID?")
                .default(false)
                .show_default(true)
                .wait_for_newline(true)
                .interact()?
            {
                let did = Input::<String>::with_theme(self.theme.colorful_theme)
                    .with_prompt("Existing DID")
                    .interact()?;
                Some(did)
            } else {
                None
            }
        };

        let key_types = &["provided jwk", "generate p256", "generate k256"];

        let key_type = Select::with_theme(self.theme.colorful_theme)
            .with_prompt("Select key type")
            .default(0)
            .items(&key_types[..])
            .interact()?;

        let recovery_key = if key_type == 0 {
            let jwk = get_jwk_input(self.theme.colorful_theme)?;
            let did_key = crate::crypto::jwk_to_did_key(&jwk)?;

            println!("{}", self.theme.green.apply_to("✔ Derived DID key"));
            println!("{}", self.theme.white_dim.apply_to(&did_key));
            did_key
        } else {
            let (secret_jwk, encoded_public_key) = if key_type == 1 {
                crate::crypto::p256::gen_key()
            } else if key_type == 2 {
                crate::crypto::k256::gen_key()
            } else {
                Err(anyhow!("Invalid key type"))
            }?;
            println!(
                "{}",
                self.theme
                    .yellow_bold
                    .apply_to("Important! Securely store the following private key."),
            );
            println!("{}", self.theme.red_bold.apply_to(&secret_jwk));
            encoded_public_key
        };
        let recovery_key = format!("did:key:{}", recovery_key);

        let (new_did, new_handle, _new_access_jwt) = create_account(
            &self.http_client,
            &pds_hostname,
            &handle,
            &password,
            &email,
            &recovery_key,
            invite_code,
            existing_did,
        )
        .await?;

        println!(
            "{}",
            self.theme
                .green
                .apply_to(format!("✔ Account created: {} ({})", new_did, new_handle))
        );

        Ok(())
    }
}
