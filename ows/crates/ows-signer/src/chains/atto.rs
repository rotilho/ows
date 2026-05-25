use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use blake2::digest::{consts::U5, Digest};
use blake2::Blake2b;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;

const ATTO_COIN_TYPE: u32 = 1_869_902_945;
const ATTO_ADDRESS_ALGORITHM_V1: u8 = 0;
const RFC4648_BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes using RFC 4648 base32 without padding, lowercased.
fn encode_base32_lower_no_pad(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            let shift = bits - 5;
            let index = ((buffer >> shift) & 0x1f) as usize;
            out.push(RFC4648_BASE32_LOWER[index] as char);
            bits -= 5;
            buffer &= (1 << bits) - 1;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(RFC4648_BASE32_LOWER[index] as char);
    }

    out
}

fn atto_checksum(payload: &[u8; 33]) -> [u8; 5] {
    let mut hasher = Blake2b::<U5>::new();
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn atto_address(pubkey: &[u8; 32]) -> String {
    let mut bytes = [0u8; 38];
    bytes[0] = ATTO_ADDRESS_ALGORITHM_V1;
    bytes[1..33].copy_from_slice(pubkey);

    let payload: [u8; 33] = bytes[..33].try_into().expect("payload length is fixed");
    bytes[33..].copy_from_slice(&atto_checksum(&payload));

    format!("atto://{}", encode_base32_lower_no_pad(&bytes))
}

/// Atto chain signer metadata and local Ed25519 primitives.
///
/// Transaction construction/broadcasting is intentionally out of scope for this
/// registry slice. Atto transaction signing expects callers to pass the
/// canonical 32-byte BLAKE2b block hash from Atto Commons serialization.
pub struct AttoSigner;

impl AttoSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for AttoSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Atto
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        ATTO_COIN_TYPE
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(atto_address(verifying_key.as_bytes()))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.to_bytes().to_vec()),
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if tx_bytes.len() != 32 {
            return Err(SignerError::InvalidTransaction(format!(
                "Atto transaction signing expects a 32-byte canonical block hash, got {} bytes",
                tx_bytes.len()
            )));
        }
        self.sign(private_key, tx_bytes)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/{ATTO_COIN_TYPE}'/{index}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::Verifier;

    const ABANDON_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn derive_key(index: u32) -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = AttoSigner;
        let key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &signer.default_derivation_path(index),
            Curve::Ed25519,
        )
        .unwrap();
        key.expose().to_vec()
    }

    #[test]
    fn chain_properties() {
        let signer = AttoSigner;
        assert_eq!(signer.chain_type(), ChainType::Atto);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), ATTO_COIN_TYPE);
        assert_eq!(signer.default_derivation_path(0), "m/44'/1869902945'/0'");
    }

    #[test]
    fn address_has_atto_uri_shape() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let address = signer.derive_address(&key).unwrap();
        assert!(address.starts_with("atto://"));
        assert_eq!(address.len(), "atto://".len() + 61);
        assert!(address["atto://".len()..]
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn sign_transaction_requires_block_hash() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let err = signer.sign_transaction(&key, b"not a hash").unwrap_err();
        assert!(err.to_string().contains("32-byte canonical block hash"));

        let hash = [7u8; 32];
        let signature = signer.sign_transaction(&key, &hash).unwrap();
        assert_eq!(signature.signature.len(), 64);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = derive_key(0);
        let signer = AttoSigner;
        let message = b"atto message";
        let output = signer.sign_message(&key, message).unwrap();
        let public_key =
            VerifyingKey::from_bytes(&output.public_key.unwrap().try_into().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        public_key.verify(message, &signature).unwrap();
    }
}
