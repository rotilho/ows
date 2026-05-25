use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ows_signer::chains::atto::{
    atto_address, atto_block_hash, atto_pubkey_from_address, AttoSigner,
};
use ows_signer::{ChainSigner, Curve, HdDeriver, Mnemonic};
use serde::Deserialize;

const FIXTURES: &str = include_str!("fixtures/atto/signer_vectors.json");

#[derive(Debug, Deserialize)]
struct SignerFixtures {
    mnemonic: String,
    passphrase: String,
    message_hex: String,
    derived_accounts: Vec<DerivedAccount>,
    address_codec: AddressCodec,
    block_hash_signatures: Vec<BlockHashSignature>,
}

#[derive(Debug, Deserialize)]
struct DerivedAccount {
    index: u32,
    path: String,
    private_key_hex: String,
    public_key_hex: String,
    address: String,
    message_signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct AddressCodec {
    public_key_hex: String,
    address: String,
    invalid_cases: Vec<InvalidAddressCase>,
}

#[derive(Debug, Deserialize)]
struct InvalidAddressCase {
    address: String,
    error_contains: String,
}

#[derive(Debug, Deserialize)]
struct BlockHashSignature {
    #[serde(rename = "type")]
    block_type: String,
    block_bytes_hex: String,
    hash_hex: String,
    signature_hex: String,
}

fn fixtures() -> SignerFixtures {
    serde_json::from_str(FIXTURES).expect("valid Atto signer fixture JSON")
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex strings must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex is valid"))
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn mnemonic_indices_derive_expected_ed25519_keys_and_atto_addresses() {
    let fixtures = fixtures();
    let mnemonic = Mnemonic::from_phrase(&fixtures.mnemonic).unwrap();
    let signer = AttoSigner;

    for account in fixtures.derived_accounts {
        assert_eq!(
            signer.default_derivation_path(account.index),
            account.path,
            "fixture path should match the Atto signer path"
        );
        let key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            &fixtures.passphrase,
            &account.path,
            Curve::Ed25519,
        )
        .unwrap();
        assert_eq!(hex_lower(key.expose()), account.private_key_hex);
        assert_eq!(
            signer.derive_address(key.expose()).unwrap(),
            account.address
        );

        let signature = signer
            .sign_message(key.expose(), &hex_to_vec(&fixtures.message_hex))
            .unwrap();
        assert_eq!(
            hex_lower(signature.public_key.as_ref().unwrap()),
            account.public_key_hex
        );
        assert_eq!(
            hex_lower(&signature.signature),
            account.message_signature_hex
        );

        let public_key_bytes: [u8; 32] = signature.public_key.unwrap().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
        let signature_bytes: [u8; 64] = signature.signature.try_into().unwrap();
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&hex_to_vec(&fixtures.message_hex), &signature)
            .unwrap();
    }
}

#[test]
fn address_codec_accepts_fixture_and_rejects_invalid_checksum_cases() {
    let fixtures = fixtures();
    let public_key: [u8; 32] = hex_to_vec(&fixtures.address_codec.public_key_hex)
        .try_into()
        .unwrap();

    assert_eq!(atto_address(&public_key), fixtures.address_codec.address);
    assert_eq!(
        atto_pubkey_from_address(&fixtures.address_codec.address).unwrap(),
        public_key
    );

    for case in fixtures.address_codec.invalid_cases {
        let err = atto_pubkey_from_address(&case.address).unwrap_err();
        assert!(
            err.to_string().contains(&case.error_contains),
            "expected {:?} in error {err} for {}",
            case.error_contains,
            case.address
        );
    }
}

#[test]
fn block_hash_signatures_cover_send_receive_open_and_change_serialization_inputs() {
    let fixtures = fixtures();
    let account = fixtures
        .derived_accounts
        .first()
        .expect("fixture has index 0 account");
    let private_key = hex_to_vec(&account.private_key_hex);
    let public_key: [u8; 32] = hex_to_vec(&account.public_key_hex).try_into().unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
    let signer = AttoSigner;
    let mut seen = Vec::new();

    for fixture in fixtures.block_hash_signatures {
        let block_bytes = hex_to_vec(&fixture.block_bytes_hex);
        let hash = atto_block_hash(&block_bytes);
        assert_eq!(hex_lower(&hash), fixture.hash_hex);

        let output = signer.sign_transaction(&private_key, &block_bytes).unwrap();
        assert_eq!(hex_lower(&output.signature), fixture.signature_hex);
        let signature = Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key.verify(&hash, &signature).unwrap();
        seen.push(fixture.block_type);
    }

    assert_eq!(seen, ["SEND", "RECEIVE", "OPEN", "CHANGE"]);
}

#[test]
fn sign_transaction_rejects_non_canonical_block_payloads() {
    let fixtures = fixtures();
    let private_key = hex_to_vec(&fixtures.derived_accounts[0].private_key_hex);
    let mut truncated_send = vec![2u8; 32];
    truncated_send[0] = 2;
    let err = AttoSigner
        .sign_transaction(&private_key, &truncated_send)
        .unwrap_err();
    assert!(err.to_string().contains("invalid Atto payload length"));
}
