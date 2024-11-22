use anyhow::{anyhow, Context, Result};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    AsyncResolver,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Clone, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcService {
    pub id: String,

    #[serde(rename = "type")]
    pub service_type: String,

    pub service_endpoint: String,
}

#[derive(Clone, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveDid {
    pub id: String,
    pub also_known_as: Vec<String>,
    pub service: Vec<PlcService>,
}

pub async fn resolve_handle_dns(handle: &str) -> Result<String> {
    let lookup_dns = format!("_atproto.{}", handle);
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let lookup = resolver.txt_lookup(lookup_dns.clone()).await?;

    let dids = lookup
        .iter()
        .filter_map(|record| {
            record
                .to_string()
                .strip_prefix("did=")
                .map(|did| did.to_string())
        })
        .collect::<HashSet<String>>();

    if dids.len() > 1 {
        return Err(anyhow!("Multiple records found for handle {}", handle));
    }

    dids.iter()
        .next()
        .cloned()
        .ok_or(anyhow!("No records found for handle {}", handle))
}

pub async fn resolve_handle_http(http_client: &reqwest::Client, handle: &str) -> Result<String> {
    let lookup_url = format!("https://{}/.well-known/atproto-did", handle);

    http_client
        .get(lookup_url.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .text()
        .await
        .map_err(|err| err.into())
        .and_then(|body| {
            if body.starts_with("did:") {
                Ok(body.to_string())
            } else {
                Err(anyhow!("Invalid response from {}", lookup_url))
            }
        })
}

pub async fn plc_query(
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

pub async fn did_plc_data(
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

pub struct ResolvedHandle {
    pub did: String,
    pub pds: String,
    pub handles: Vec<String>,
}

pub async fn resolve_handle(
    http_client: &reqwest::Client,
    plc_hostname: &str,
    subject: &str,
) -> Result<ResolvedHandle> {
    let mut resolved_dids: HashSet<String> = HashSet::new();
    let mut unresolved_dids: HashSet<String> = HashSet::new();
    let mut resolved_handles: HashSet<String> = HashSet::new();
    let mut unresolved_handles: HashSet<String> = HashSet::new();

    let mut found_pds: HashSet<String> = HashSet::new();
    let mut found_handles: HashSet<String> = HashSet::new();
    let mut found_dids: HashSet<String> = HashSet::new();

    if subject.starts_with("did:") {
        unresolved_dids.insert(subject.to_string());
    } else {
        unresolved_handles.insert(subject.to_string());
    }

    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 10 {
            return Err(anyhow!("resolve_handle exceeded max iteration depth"));
        }

        let next_did = unresolved_dids.difference(&resolved_dids).next().cloned();
        let next_handle = &unresolved_handles
            .difference(&resolved_handles)
            .next()
            .cloned();
        if next_did.is_none() && next_handle.is_none() {
            break;
        }

        if let Some(next_did) = next_did {
            resolved_dids.insert(next_did.to_string());
            let query_res = plc_query(http_client, plc_hostname, &next_did).await;
            if let Ok((pds, handles)) = query_res {
                found_pds.extend(pds.clone());
                found_handles.extend(handles.clone());
                unresolved_handles.extend(handles);
            }
        }

        if let Some(next_handle) = next_handle {
            resolved_handles.insert(next_handle.to_string());
            let http_resolve = resolve_handle_http(http_client, next_handle).await;
            if let Ok(resolved_did) = http_resolve {
                unresolved_dids.insert(resolved_did.clone());
                found_dids.insert(resolved_did);
            }

            let dns_resolve = resolve_handle_dns(next_handle).await;
            if let Ok(resolved_did) = dns_resolve {
                unresolved_dids.insert(resolved_did.clone());
                found_dids.insert(resolved_did);
            }
        }
    }

    if found_dids.len() > 1 {
        return Err(anyhow!("Multiple DIDs found for subject {}", subject));
    }
    if found_handles.is_empty() {
        return Err(anyhow!("No handles found for subject {}", subject));
    }
    if found_pds.len() > 1 {
        return Err(anyhow!("Multiple PDSs found for subject {}", subject));
    }

    let found_did = found_dids
        .iter()
        .next()
        .cloned()
        .ok_or(anyhow!("No DIDs found for subject {}", subject))?;
    let found_pds = found_pds
        .iter()
        .next()
        .cloned()
        .ok_or(anyhow!("No PDSs found for subject {}", subject))?;

    Ok(ResolvedHandle {
        did: found_did,
        pds: found_pds,
        handles: found_handles.iter().cloned().collect(),
    })
}
