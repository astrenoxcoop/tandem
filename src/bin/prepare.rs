use anyhow::{anyhow, Context, Result};
use dialoguer::{console::Style, theme::ColorfulTheme, Confirm, Input, Password, Select};
use json_patch::{patch, Patch};
use serde_json::{from_value, json};
use std::{env, process::ExitCode};
use tandem::{
    resolve::{did_plc_data, resolve_handle},
    xrpc::PdsClient,
};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = real_main().await {
        let red_bold = Style::new().red().bold();
        println!("{}: {}", red_bold.apply_to("Error"), err);
        return ExitCode::FAILURE;
    }

    let green_bold = Style::new().green().bold();
    println!("{}", green_bold.apply_to("Success"));
    ExitCode::SUCCESS
}

async fn real_main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();

    let display_help = args.iter().any(|arg| arg == "--help");

    if display_help {
        println!("Usage: prepare [options] <plc> <handle> <password>");
        println!("Options:");
        println!("\t--help\t\t\tDisplays this message.");
        println!("\t--ca-certificate=FILE\tAllows one or more CA certificate to be used for HTTPS connections.");
        return Ok(());
    }

    let yellow_bold = Style::new().yellow().bold();
    let red_bold = Style::new().red().bold();
    let green = Style::new().green();
    let white_dim = Style::new().white().dim();

    println!("{} This tool will perform potentially dangerous operations on your behalf. Do not proceed unless you know what you are doing.", red_bold.apply_to("Warning!"));

    if !Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Do you want to proceed?")
        .default(false)
        .show_default(true)
        .wait_for_newline(true)
        .interact()?
    {
        return Ok(());
    }

    let mut client_builder = reqwest::Client::builder();

    for arg in &args {
        if let Some(ca_certificate) = arg.strip_prefix("--ca-certificate=") {
            let cert_data = std::fs::read(ca_certificate)
                .with_context(|| format!("failed to read CA certificate: {}", ca_certificate))?;
            let cert = reqwest::Certificate::from_pem(&cert_data)
                .with_context(|| format!("failed to parse CA certificate: {}", ca_certificate))?;
            client_builder = client_builder.add_root_certificate(cert);
        }
    }

    let http_client = client_builder
        .build()
        .context("failed to create HTTP client")?;

    let theme = ColorfulTheme {
        values_style: Style::new().white().bold(),
        ..ColorfulTheme::default()
    };

    println!(
        "{}",
        yellow_bold.apply_to("Please provide your @handle and password.")
    );

    let handle = Input::<String>::with_theme(&theme)
        .with_prompt("Handle")
        .interact()?;

    let password = Password::with_theme(&theme)
        .with_prompt("Password")
        .interact()?;

    let plc = Input::<String>::with_theme(&theme)
        .with_prompt("PLC Directory")
        .default("plc.directory".parse().unwrap())
        .interact()?;

    let key_types = &["p256", "k256"];

    let key_type = Select::with_theme(&theme)
        .with_prompt("Select key type")
        .default(0)
        .items(&key_types[..])
        .interact()?;

    if key_type != 0 {
        return Err(anyhow!("Unsupported key type"));
    }

    let key_positions = &["first", "last"];

    let key_position = Select::with_theme(&theme)
        .with_prompt("Select key position")
        .default(0)
        .items(&key_positions[..])
        .interact()?;

    let resolved_handle = resolve_handle(&http_client, &plc, &handle)
        .await
        .context("failed to resolve handle")?;

    println!(
        "{}",
        green.apply_to(format!(
            "✔ Resolved {} ({}) known as {}",
            resolved_handle.did,
            resolved_handle.pds,
            resolved_handle.handles.join(" ")
        )),
    );

    let pds_client = PdsClient::from_credentials(
        &http_client,
        &resolved_handle.pds,
        &resolved_handle.did,
        &password,
    )
    .await
    .context("failed to authenticate against PDS")?;

    let (secret_pem, encoded_public_key) = tandem::crypto::p256::gen_key()?;

    println!(
        "{}",
        yellow_bold.apply_to("Important! Securely store the following private key."),
    );
    println!("{}", red_bold.apply_to(&secret_pem));

    let mut did_doc_data = did_plc_data(&http_client, &plc, &resolved_handle.did)
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

    println!("{}", green.apply_to("✔ Created patch document"));
    println!(
        "{}",
        white_dim.apply_to(
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
        yellow_bold.apply_to(
            "Important! Check your email for a confirmation code. Enter it below to continue."
        )
    );

    let token = Input::<String>::with_theme(&theme)
        .with_prompt("Confirmation code")
        .interact()
        .context("failed to get confirmation code")?;

    let plc_operation = pds_client
        .sign_plc_op(&did_doc_data, &token)
        .await
        .context("failed to request PLC signing operation")?;

    println!("{}", green.apply_to("✔ Acquired signed PLC operation"));
    println!(
        "{}",
        white_dim.apply_to(
            serde_json::to_string_pretty(&plc_operation)
                .context("failed to serialize PLC operation")?
        )
    );

    pds_client
        .submit_plc_op(&plc_operation)
        .await
        .context("failed to submit PLC operation")?;

    println!("{}", green.apply_to("✔ Submitted signed PLC operation"));

    Ok(())
}
