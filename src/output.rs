use crate::message::{ParseError, SiwsMessage, ValidateError, ValidateOptions};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwsOutput {
    pub account: SolAccount,
    #[serde(with = "serde_base64")]
    pub signed_message: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolAccount {
    #[serde(with = "serde_base58")]
    pub public_key: Vec<u8>,
}

impl SiwsOutput {
    pub fn verify(&self) -> Result<bool, VerifyError> {
        let pubkey_bytes: [u8; 32] = self
            .account
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| SiwsOutputError::InvalidPubkey)?;
        let pubkey =
            VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SiwsOutputError::InvalidPubkey)?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SiwsOutputError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);

        pubkey
            .verify_strict(&self.signed_message, &signature)
            .map_err(|_| VerifyError::VerificationFailure)?;

        Ok(true)
    }

    /// Verify the Ed25519 signature, parse the SIWS message, check that the
    /// address matches the public key, and validate fields against the given options.
    pub fn authenticate(&self, options: ValidateOptions) -> Result<SiwsMessage, VerifyError> {
        self.verify()?;

        let message = SiwsMessage::try_from(&self.signed_message)?;

        let address = bs58::encode(&self.account.public_key).into_string();
        if message.address != address {
            return Err(VerifyError::AddressMismatch);
        }

        message.validate(options)?;

        Ok(message)
    }
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Message Parse Error: {0}")]
    MessageParse(#[from] ParseError),

    #[error("Invalid Message: {0}")]
    MessageValidate(#[from] ValidateError),

    #[error("Signature Parse Error: {0}")]
    SignatureParse(&'static str),

    #[error("Solana Error: {0}")]
    SiwsOutput(#[from] SiwsOutputError),

    #[error("Signature verification failed")]
    VerificationFailure,

    #[error("Address does not match public key")]
    AddressMismatch,

    #[error("")]
    Infallible,
}

#[derive(Debug, Error)]
pub enum SiwsOutputError {
    #[error("Invalid public key")]
    InvalidPubkey,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Serializes as base64 string, deserializes from either base64 string or u8 array.
mod serde_base64 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(Base64OrArrayVisitor)
    }

    struct Base64OrArrayVisitor;

    impl<'de> Visitor<'de> for Base64OrArrayVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a base64 string or a u8 array")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            STANDARD.decode(v).map_err(de::Error::custom)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(byte) = seq.next_element()? {
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
}

/// Serializes as base58 string, deserializes from either base58 string or u8 array.
mod serde_base58 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        bs58::encode(bytes).into_string().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(Base58OrArrayVisitor)
    }

    struct Base58OrArrayVisitor;

    impl<'de> Visitor<'de> for Base58OrArrayVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a base58 string or a u8 array")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
            bs58::decode(v).into_vec().map_err(de::Error::custom)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(byte) = seq.next_element()? {
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
}
