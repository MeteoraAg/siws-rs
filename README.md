# SIWS - Sign in With Solana Rust Library

A lightweight Rust implementation of [CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md) (Sign in With X) for Solana, following the [Solana Wallet Standard](https://github.com/anza-xyz/wallet-standard?tab=readme-ov-file) and [Phantom Wallet's Sign In With Solana](https://github.com/phantom/sign-in-with-solana) protocol.

No Solana SDK dependency -- uses `ed25519-dalek` 2.x, `bs58`, and `time` to keep it lightweight.

## Installation

Add `siws` to your `Cargo.toml`:

```toml
[dependencies]
siws = { git = "ssh://git@github.com/MeteoraAg/siws-rs.git" }
```

## Usage

SIWS exposes two main structs:

- `SiwsMessage` -- parse, construct, and validate CAIP-122 / EIP-4361 formatted messages
- `SiwsOutput` -- verify Ed25519 signatures and validate sign-in outputs

`SiwsMessage` is analogous to Solana Wallet Standard's `SolanaSignInInput`, while `SiwsOutput` is analogous to `SolanaSignInOutput`.

### Verify and validate in one step

`authenticate` combines signature verification, message parsing, address-public key matching, and field validation:

```rust
use siws::message::ValidateOptions;
use siws::output::SiwsOutput;
use time::OffsetDateTime;

fn handle_sign_in(output: SiwsOutput) -> Result<(), Box<dyn std::error::Error>> {
    let message = output.authenticate(ValidateOptions {
        domain: Some("meteora.ag".into()),
        nonce: Some("server-generated-nonce".into()),
        time: Some(OffsetDateTime::now_utc()),
    })?;

    println!("Authenticated wallet: {}", message.address);
    println!("Chain: {:?}", message.chain_id);

    Ok(())
}
```

This will:

1. Verify the Ed25519 signature
2. Parse the signed message into a `SiwsMessage`
3. Check that the message address matches the signer's public key
4. Validate domain, nonce, and timestamps against the provided options

### Verify signature only

If you want to handle parsing and validation separately:

```rust
use siws::message::{SiwsMessage, ValidateOptions};
use siws::output::SiwsOutput;
use time::OffsetDateTime;

fn handle_sign_in(output: SiwsOutput) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Verify the Ed25519 signature
    output.verify()?;

    // 2. Parse the message
    let message = SiwsMessage::try_from(&output.signed_message)?;

    // 3. Validate fields
    message.validate(ValidateOptions {
        domain: Some("meteora.ag".into()),
        nonce: Some("server-generated-nonce".into()),
        time: Some(OffsetDateTime::now_utc()),
    })?;

    Ok(())
}
```

### Axum example

```rust
use axum::{http::StatusCode, Json};
use siws::message::ValidateOptions;
use siws::output::SiwsOutput;
use time::OffsetDateTime;

async fn verify_handler(
    Json(output): Json<SiwsOutput>,
) -> Result<String, (StatusCode, String)> {
    let message = output
        .authenticate(ValidateOptions {
            domain: Some("meteora.ag".into()),
            nonce: Some("expected-nonce".into()),
            time: Some(OffsetDateTime::now_utc()),
        })
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    Ok(format!("Authenticated: {}", message.address))
}
```

### Parse SIWS message from string

Parse a CAIP-122 / EIP-4361 ABNF formatted message:

```rust
use std::str::FromStr;
use siws::message::SiwsMessage;

let message = SiwsMessage::from_str(
    "meteora.ag wants you to sign in with your Solana account:\n\
     7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n\
     \n\
     Sign in to access your Meteora referral dashboard.\n\
     \n\
     URI: https://meteora.ag\n\
     Version: 1\n\
     Chain ID: mainnet\n\
     Nonce: abc123\n\
     Issued At: 2026-04-02T10:30:00.000Z\n\
     Expiration Time: 2026-04-02T10:35:00.000Z",
).unwrap();

assert_eq!(message.domain, "meteora.ag");
assert_eq!(message.chain_id, Some("mainnet".into()));
```

### Construct a SIWS message

Build an ABNF-formatted message from structured input:

```rust
use siws::message::SiwsMessage;

let message = SiwsMessage {
    domain: "meteora.ag".into(),
    address: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
    statement: Some("Sign in to access your Meteora referral dashboard.".into()),
    version: Some("1".into()),
    chain_id: Some("mainnet".into()),
    ..Default::default()
};

let message_string = String::from(&message);
```

### ValidateOptions

| Field | Purpose |
|---|---|
| `domain` | Reject if message domain doesn't match |
| `nonce` | Reject if message nonce doesn't match |
| `time` | Reject if message is expired, issued in the future, or not yet valid |

All fields are optional. Omitted fields skip that check.

### Error types

`ValidateError` variants:

| Variant | Meaning |
|---|---|
| `DomainMismatch` | Message domain doesn't match expected domain |
| `NonceMismatch` | Message nonce doesn't match expected nonce |
| `Expired` | Message expiration time has passed |
| `IssuedInFuture` | Message `issuedAt` is after the check time |
| `NotYetValid` | Message `notBefore` is after the check time |

`VerifyError` variants:

| Variant | Meaning |
|---|---|
| `VerificationFailure` | Ed25519 signature verification failed |
| `AddressMismatch` | Message address doesn't match the signer's public key |
| `MessageParse` | Failed to parse the signed message |
| `MessageValidate` | Field validation failed |
| `SiwsOutput` | Invalid public key or signature bytes |

## SiwsOutput JSON format

`SiwsOutput` derives serde `Serialize`/`Deserialize` with `camelCase` field names for Solana Wallet Standard compatibility:

```json
{
  "account": { "publicKey": [/* 32 bytes */] },
  "signedMessage": [/* UTF-8 message bytes */],
  "signature": [/* 64 bytes */]
}
```

## Security

This library has not undergone a security audit. Use at your own risk.

If you discover a vulnerability, please report it privately to the maintainers.

## License

MIT
