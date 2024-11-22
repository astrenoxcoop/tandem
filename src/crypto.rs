use anyhow::{anyhow, Result};

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

pub mod p256 {

    use anyhow::Result;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256;

    pub fn gen_key() -> Result<(String, String)> {
        let secret_key: p256::SecretKey = p256::SecretKey::random(&mut rand::thread_rng());

        let secret_pem = secret_key.to_sec1_pem(Default::default())?.to_string();

        let public_key = secret_key.public_key();
        let encoded_point = public_key.to_encoded_point(true);

        let full = [&[0x80, 0x24], encoded_point.as_bytes()].concat();

        let encoded_public_key = multibase::encode(multibase::Base::Base58Btc, full);

        Ok((secret_pem, encoded_public_key))
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
