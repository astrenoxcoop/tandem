use anyhow::{Context, Result};
use dialoguer::{console::Style, theme::ColorfulTheme, Confirm, Input, Select};
use elliptic_curve::JwkEcKey;
use json_patch::Patch;
use serde_json::{from_value, json};
use std::str::FromStr;
use std::{env, process::ExitCode};
use tandem::actions::{get_action, Theme};

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
        println!("Usage: tandem [options]");
        println!("Options:");
        println!("\t--help\t\t\tDisplays this message.");
        println!("\t--ca-certificate=FILE\tAllows one or more CA certificate to be used for HTTPS connections.");
        return Ok(());
    }

    let colorful_theme = ColorfulTheme {
        values_style: Style::new().white().bold(),
        ..ColorfulTheme::default()
    };
    let theme = Theme {
        colorful_theme: &colorful_theme,
        red_bold: Style::new().red().bold(),
        yellow_bold: Style::new().yellow().bold(),
        green: Style::new().green(),
        white_dim: Style::new().white().dim(),
    };

    println!("{} This tool will perform potentially dangerous operations on your behalf. Do not proceed unless you know what you are doing.", theme.red_bold.apply_to("Warning!"));

    if !Confirm::with_theme(theme.colorful_theme)
        .with_prompt("Do you want to proceed?")
        .default(true)
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

    println!(
        "{}",
        theme
            .yellow_bold
            .apply_to("Please provide your @handle and password.")
    );

    let plc = Input::<String>::with_theme(theme.colorful_theme)
        .with_prompt("PLC Directory")
        .default("plc.pyroclastic.cloud".parse().unwrap())
        .interact()?;

    let supported_operations = &["Install Tandem Key", "Append Handle"];

    let selected_operation = Select::with_theme(theme.colorful_theme)
        .with_prompt("Supported Operations")
        .default(0)
        .items(&supported_operations[..])
        .interact()?;

    let action = get_action(selected_operation, &theme, &http_client, &plc)?;

    action.run().await
}
