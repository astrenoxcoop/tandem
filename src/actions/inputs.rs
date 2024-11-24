use anyhow::{anyhow, Context, Result};
use dialoguer::{theme::ColorfulTheme, Input};
use elliptic_curve::JwkEcKey;
use std::str::FromStr;

pub(crate) fn get_jwk_input(theme: &ColorfulTheme) -> Result<JwkEcKey> {
    let secret_jwk = Input::<String>::with_theme(theme)
        .with_prompt("JWK")
        .interact()?;

    JwkEcKey::from_str(&secret_jwk).context("failed to parse JWK")
}

pub(crate) fn get_handle_input(theme: &ColorfulTheme, prompt: &str) -> Result<String> {
    let handle = Input::<String>::with_theme(theme)
        .with_prompt(prompt)
        .interact()?;

    is_valid_handle(&handle).ok_or(anyhow!("invalid handle"))
}

pub(crate) fn get_did_plc_input(theme: &ColorfulTheme, prompt: &str) -> Result<String> {
    let handle = Input::<String>::with_theme(theme)
        .with_prompt(prompt)
        .interact()?;

    is_valid_did_plc(&handle).ok_or(anyhow!("invalid DID-PLC"))
}

fn is_valid_hostname(hostname: &str) -> bool {
    fn is_valid_char(byte: u8) -> bool {
        byte.is_ascii_lowercase()
            || byte.is_ascii_uppercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || byte == b'.'
    }
    !(hostname.ends_with(".localhost")
        || hostname.ends_with(".internal")
        || hostname.ends_with(".arpa")
        || hostname.ends_with(".local")
        || hostname.bytes().any(|byte| !is_valid_char(byte))
        || hostname.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
        || hostname.is_empty()
        || hostname.len() > 253)
}

fn is_valid_handle(handle: &str) -> Option<String> {
    let trimmed = {
        if let Some(value) = handle.strip_prefix("at://") {
            value
        } else if let Some(value) = handle.strip_prefix('@') {
            value
        } else {
            handle
        }
    };
    let trimmed = trimmed.to_lowercase();
    if is_valid_hostname(&trimmed) && trimmed.chars().any(|c| c == '.') {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn is_valid_did_plc(input: &str) -> Option<String> {
    let trimmed = {
        if let Some(value) = input.strip_prefix("at://") {
            value
        } else {
            input
        }
    };
    if trimmed.starts_with("did:plc:") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_hostnames() {
        for hostname in &[
            "VaLiD-HoStNaMe",
            "50-name",
            "235235",
            "example.com",
            "VaLid.HoStNaMe",
            "123.456",
        ] {
            assert!(
                is_valid_hostname(hostname),
                "{} is not valid hostname",
                hostname
            );
        }
    }

    #[test]
    fn invalid_hostnames() {
        for hostname in &[
            "-invalid-name",
            "also-invalid-",
            "asdf@fasd",
            "@asdfl",
            "asd f@",
            ".invalid",
            "invalid.name.",
            "foo.label-is-way-to-longgggggggggggggggggggggggggggggggggggggggggggg.org",
            "invalid.-starting.char",
            "invalid.ending-.char",
            "empty..label",
        ] {
            assert!(
                !is_valid_hostname(hostname),
                "{} should not be valid hostname",
                hostname
            );
        }
    }
}
