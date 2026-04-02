use crate::message::{ParseError, SiwsMessage, ValidateError, ValidateOptions};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwsOutput {
    pub account: SolAccount,
    pub signed_message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SolAccount {
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
    pub fn authenticate(
        &self,
        options: ValidateOptions,
    ) -> Result<SiwsMessage, VerifyError> {
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
