use anyhow::Result;
use async_trait::async_trait;

use crate::actions::{TandemAction, Theme};

pub(crate) struct ActionMigrate<'a> {
    theme: &'a Theme<'a>,
    #[allow(dead_code)]
    http_client: reqwest::Client,
    #[allow(dead_code)]
    plc: String,
}

impl<'a> ActionMigrate<'a> {
    pub(crate) fn new(theme: &'a Theme<'_>, http_client: &reqwest::Client, plc: &str) -> Self {
        Self {
            theme,
            http_client: http_client.clone(),
            plc: plc.to_string(),
        }
    }
}

#[async_trait]
impl TandemAction for ActionMigrate<'_> {
    async fn run(&self) -> Result<()> {
        println!(
        "{}",
            self.theme
                .white_dim
                .apply_to("The 'Migrate' action performs a migration of your DID-PLC identity to a different PDS.")
        );

        // TODO: User input DID
        // TODO: User input jwk
        // TODO: User input destination_pds
        // TODO: User input destination_password
        // TODO: Create session with destination_pds
        // TODO: Get the PLC credentails from the destination PDS /xrpc/com.atproto.identity.getRecommendedDidCredentials
        // TODO: Get last PLC operation for DID
        // TODO: Create operation with updated PDS keys and service endpoints
        // TODO: Sign operation with jwk
        // TODO: Submit operation to PLC
        Ok(())
    }
}
