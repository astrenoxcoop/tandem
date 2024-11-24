use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlcService {
    #[serde(rename = "type")]
    service_type: String,

    service_endpoint: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolveDid {
    also_known_as: Vec<String>,
    service: Vec<PlcService>,
}

#[derive(Clone, Deserialize)]
struct AuditEntry {
    operation: serde_json::Value,
    cid: String,
    #[serde(rename = "createdAt")]
    created_at: DateTime<Utc>,
}

pub(crate) async fn plc_query(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let url = format!("https://{}/{}", plc_hostname, did);

    let resolved_did: ResolveDid = http_client.get(url).send().await?.json().await?;

    let handles = resolved_did
        .also_known_as
        .iter()
        .map(|value| {
            if let Some(handle) = value.strip_prefix("at://") {
                handle.to_string()
            } else {
                value.to_string()
            }
        })
        .collect::<Vec<String>>();

    let pds = resolved_did
        .service
        .iter()
        .filter_map(|value| {
            if value.service_type == "AtprotoPersonalDataServer" {
                Some(value.service_endpoint.clone())
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    Ok((pds, handles))
}

pub(crate) async fn did_plc_data(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
) -> Result<serde_json::Value> {
    let url = format!("https://{}/{}/data", plc_hostname, did);

    http_client
        .get(url)
        .send()
        .await
        .context("unable to get DID document")?
        .json()
        .await
        .context("unable to deserialize DID document")
}

pub(crate) async fn did_plc_last_operation(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
) -> Result<(String, serde_json::Value)> {
    let url = format!("https://{}/{}/log/audit", plc_hostname, did);

    println!("url: {}", url);

    let mut operations: Vec<AuditEntry> = http_client
        .get(url)
        .send()
        .await
        .context("unable to get DID audit log")?
        .json()
        .await
        .context("unable to deserialize DID audit log")?;

    operations.sort_by_key(|entry| entry.created_at);

    let selected = operations
        .last()
        .cloned()
        .ok_or_else(|| anyhow!("no operations found"))?;

    Ok((selected.cid, selected.operation))
}

pub(crate) async fn submit_operation(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    did: &str,
    operation: &serde_json::Value,
) -> Result<()> {
    let url = format!("https://{}/{}", plc_hostname, did);

    http_client
        .post(url)
        .json(operation)
        .send()
        .await
        .context("unable to submit operation")
        .and_then(|response| {
            let status = response.status();
            if status.is_success() {
                Ok(())
            } else {
                Err(anyhow!("response {}", status))
            }
        })
}
