use anyhow::{anyhow, Result};
use elliptic_curve::JwkEcKey;
use serde_json::json;

#[allow(dead_code)]
pub(crate) fn validate(multibase_key: &str, signature: &[u8], content: &str) -> Result<()> {
    let (_, decoded_multibase_key) = multibase::decode(multibase_key)?;
    match &decoded_multibase_key[..2] {
        // secp256k1
        [0xe7, 0x01] => {
            let signature = ecdsa::Signature::from_slice(signature)?;
            let verifying_key =
                ::k256::ecdsa::VerifyingKey::from_sec1_bytes(&decoded_multibase_key[2..])?;
            ecdsa::signature::Verifier::verify(&verifying_key, content.as_bytes(), &signature)?;
            Ok(())
        }
        // p256
        [0x80, 0x24] => {
            let signature = ecdsa::Signature::from_slice(signature)?;
            let verifying_key =
                ::p256::ecdsa::VerifyingKey::from_sec1_bytes(&decoded_multibase_key[2..])?;
            ecdsa::signature::Verifier::verify(&verifying_key, content.as_bytes(), &signature)?;
            Ok(())
        }
        _ => Err(anyhow!(
            "invalid multibase: {:?}",
            &decoded_multibase_key[..2]
        )),
    }
}

pub fn sign_operation(jwk: &JwkEcKey, operation: &serde_json::Value) -> Result<serde_json::Value> {
    let serialized_operation = serde_ipld_dagcbor::to_vec(operation)?;

    let signature_str = match jwk.crv() {
        "P-256" => p256::sign_operation(jwk, &serialized_operation),
        "secp256k1" => k256::sign_operation(jwk, &serialized_operation),
        _ => Err(anyhow!("unsupported curve")),
    }?;

    let mut signed_operation = operation
        .as_object()
        .expect("operation is an object")
        .clone();

    signed_operation.insert(
        "sig".to_string(),
        serde_json::Value::String(signature_str.to_string()),
    );

    Ok(json!(signed_operation))
}
pub(crate) fn jwk_to_did_key(jwk: &JwkEcKey) -> Result<String> {
    match jwk.crv() {
        "P-256" => p256::jwk_to_did_key(jwk),
        "secp256k1" => k256::jwk_to_did_key(jwk),
        _ => Err(anyhow!("unsupported curve")),
    }
}

pub(crate) mod p256 {

    use anyhow::Result;
    use base64::{engine::general_purpose, Engine as _};
    use elliptic_curve::{sec1::ToEncodedPoint, JwkEcKey};
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        SecretKey,
    };

    pub(crate) fn gen_key() -> Result<(String, String)> {
        let secret_key: SecretKey = SecretKey::random(&mut rand::thread_rng());

        let secret_jwk = secret_key.to_jwk_string().to_string();

        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(true);

        let full = [&[0x80, 0x24], encoded_point.as_bytes()].concat();

        let encoded_public_key = multibase::encode(multibase::Base::Base58Btc, full);

        Ok((secret_jwk, encoded_public_key))
    }

    pub(crate) fn jwk_to_did_key(jwk: &JwkEcKey) -> Result<String> {
        let secret_key: SecretKey = jwk.try_into()?;
        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(true);

        let full = [&[0x80, 0x24], encoded_point.as_bytes()].concat();

        let encoded_public_key = multibase::encode(multibase::Base::Base58Btc, full);

        Ok(encoded_public_key)
    }

    pub(crate) fn sign_operation(jwk: &JwkEcKey, payload: &[u8]) -> Result<String> {
        let secret_key: SecretKey = jwk.try_into()?;
        let signing_key: SigningKey = secret_key.into();
        let signature: Signature = signing_key.try_sign(payload)?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

pub(crate) mod k256 {

    use anyhow::Result;
    use base64::{engine::general_purpose, Engine as _};
    use elliptic_curve::{sec1::ToEncodedPoint, JwkEcKey};
    use k256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        SecretKey,
    };

    pub(crate) fn gen_key() -> Result<(String, String)> {
        let secret_key: k256::SecretKey = k256::SecretKey::random(&mut rand::thread_rng());

        let secret_jwk = secret_key.to_jwk_string().to_string();

        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(true);

        let full = [&[0xe7, 0x01], encoded_point.as_bytes()].concat();

        let encoded_public_key = multibase::encode(multibase::Base::Base58Btc, full);

        Ok((secret_jwk, encoded_public_key))
    }

    pub(crate) fn jwk_to_did_key(jwk: &JwkEcKey) -> Result<String> {
        let secret_key: SecretKey = jwk.try_into()?;
        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(true);

        let full = [&[0xe7, 0x01], encoded_point.as_bytes()].concat();

        let encoded_public_key = multibase::encode(multibase::Base::Base58Btc, full);

        Ok(encoded_public_key)
    }

    pub(crate) fn sign_operation(jwk: &JwkEcKey, payload: &[u8]) -> Result<String> {
        let secret_key: SecretKey = jwk.try_into()?;
        let signing_key: SigningKey = secret_key.into();
        let signature: Signature = signing_key.try_sign(payload)?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use chrono::Utc;
    use ecdsa::signature::Signer;

    #[tokio::test]
    async fn test_validate_p256() -> Result<()> {
        let (secret_pem, encoded_public_key) = super::p256::gen_key()?;

        let secret_key: p256::SecretKey = elliptic_curve::SecretKey::from_sec1_pem(&secret_pem)?;

        let now = Utc::now();
        let content = format!("hello world {}", now);

        let signing_key: p256::ecdsa::SigningKey = p256::ecdsa::SigningKey::from(secret_key);

        let signature: p256::ecdsa::Signature = signing_key.try_sign(content.as_bytes())?;

        super::validate(&encoded_public_key, &signature.to_bytes(), &content)?;

        Ok(())
    }
}
