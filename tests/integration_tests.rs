use std::str::FromStr;

use ed25519_dalek::{Signer, SigningKey};
use iri_string::types::UriString;
use siws::{
    message::{SiwsMessage, ValidateOptions},
    output::{SiwsOutput, SolAccount, VerifyError},
    timestamp::TimeStamp,
};
use time::OffsetDateTime;

#[test]
fn verify_from_hardcoded_message() -> Result<(), VerifyError> {
    let secret: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret);

    let address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

    let siws_message = SiwsMessage {
        domain: String::from("www.example.com"),
        address,
        statement: Some("test_statement".into()),
        uri: Some("test_uri".into()),
        version: Some("test_version".into()),
        chain_id: Some("mainnet".into()),
        nonce: Some("test_nonce".into()),
        issued_at: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        expiration_time: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        not_before: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        request_id: Some("test_rid".into()),
        resources: vec![
            UriString::from_str("https://www.example1.com").map_err(|_| VerifyError::Infallible)?,
            UriString::from_str("https://www.example2.com").map_err(|_| VerifyError::Infallible)?,
        ],
    };

    let siws_message_as_string = String::from(&siws_message);
    let message_bytes = siws_message_as_string.as_bytes();

    let signature = signing_key.sign(message_bytes);

    let output = SiwsOutput {
        account: SolAccount {
            public_key: Vec::from(signing_key.verifying_key().to_bytes()),
        },
        signature: Vec::from(signature.to_bytes()),
        signed_message: Vec::from(message_bytes),
    };

    let result = output.verify()?;

    assert!(result);

    Ok(())
}

#[test]
fn verify_from_json_message() -> Result<(), VerifyError> {
    let json = include_str!("test_message.json");

    let output: SiwsOutput = serde_json::from_str(json).unwrap();

    output.verify()?;

    Ok(())
}

#[test]
fn authenticate_meteora_mainnet() -> Result<(), VerifyError> {
    let secret: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret);
    let address = bs58::encode(signing_key.verifying_key().to_bytes()).into_string();

    let siws_message = SiwsMessage {
        domain: "meteora.ag".into(),
        address,
        statement: Some("Sign in to access your Meteora referral dashboard.".into()),
        uri: Some("https://meteora.ag".into()),
        version: Some("1".into()),
        chain_id: Some("mainnet".into()),
        nonce: Some("server-nonce-123".into()),
        issued_at: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        expiration_time: Some(TimeStamp::from(
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )),
        not_before: None,
        request_id: None,
        resources: vec![],
    };

    let message_str = String::from(&siws_message);
    let message_bytes = message_str.as_bytes();
    let signature = signing_key.sign(message_bytes);

    let output = SiwsOutput {
        account: SolAccount {
            public_key: Vec::from(signing_key.verifying_key().to_bytes()),
        },
        signature: Vec::from(signature.to_bytes()),
        signed_message: Vec::from(message_bytes),
    };

    let options = ValidateOptions {
        domain: Some("meteora.ag".into()),
        nonce: Some("server-nonce-123".into()),
        time: Some(OffsetDateTime::now_utc()),
    };

    let parsed = output.authenticate(options)?;

    assert_eq!("meteora.ag", parsed.domain);
    assert_eq!(Some("mainnet".into()), parsed.chain_id);
    assert_eq!(Some("server-nonce-123".into()), parsed.nonce);
    assert_eq!(
        Some("Sign in to access your Meteora referral dashboard.".into()),
        parsed.statement,
    );

    Ok(())
}

#[test]
fn authenticate_rejects_address_mismatch() {
    let secret: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret);

    // Use a different address than the signing key
    let siws_message = SiwsMessage {
        domain: "meteora.ag".into(),
        address: "SomeOtherWa11etAddressNotMatchingTheKey1111111".into(),
        statement: Some("Sign in to access your Meteora referral dashboard.".into()),
        uri: Some("https://meteora.ag".into()),
        version: Some("1".into()),
        chain_id: Some("mainnet".into()),
        nonce: Some("nonce1".into()),
        issued_at: Some(TimeStamp::from(OffsetDateTime::now_utc())),
        expiration_time: Some(TimeStamp::from(
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )),
        not_before: None,
        request_id: None,
        resources: vec![],
    };

    let message_str = String::from(&siws_message);
    let message_bytes = message_str.as_bytes();
    let signature = signing_key.sign(message_bytes);

    let output = SiwsOutput {
        account: SolAccount {
            public_key: Vec::from(signing_key.verifying_key().to_bytes()),
        },
        signature: Vec::from(signature.to_bytes()),
        signed_message: Vec::from(message_bytes),
    };

    let result = output.authenticate(ValidateOptions::default());
    assert!(matches!(result, Err(VerifyError::AddressMismatch)));
}
