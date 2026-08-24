//! CRYSTALS-Dilithium digital signature wrapper.
//!
//! Dilithium is a lattice-based digital signature scheme selected by NIST
//! as the primary post-quantum signature standard (FIPS 204 / ML-DSA).
//!
//! We use Dilithium3 (NIST Security Level 3, ~128-bit quantum security).
//!
//! Key sizes:
//!   - Public key:  1952 bytes
//!   - Secret key:  4032 bytes
//!   - Signature:   3309 bytes
//!
//! Compare with Ed25519: pk=32B, sk=64B, sig=64B
//! The size increase is the cost of quantum resistance.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum DilithiumError {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid public key length")]
    InvalidPublicKey,
    #[error("invalid secret key length")]
    InvalidSecretKey,
    #[error("invalid signature length")]
    InvalidSignature,
}

/// A Dilithium3 keypair for signing.
///
/// The secret key is zeroized when the keypair is dropped.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    pub public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub secret_key: Vec<u8>,
}

impl Keypair {
    /// Generate a new Dilithium3 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    /// Sign a message, returning the detached signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DilithiumError> {
        let sk = dilithium3::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| DilithiumError::InvalidSecretKey)?;
        let sig = dilithium3::detached_sign(message, &sk);
        Ok(sig.as_bytes().to_vec())
    }

    /// Verify a detached signature against this keypair's public key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), DilithiumError> {
        verify_detached(&self.public_key, message, signature)
    }
}

/// Verify a detached Dilithium3 signature with a public key.
pub fn verify_detached(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), DilithiumError> {
    let pk = dilithium3::PublicKey::from_bytes(public_key)
        .map_err(|_| DilithiumError::InvalidPublicKey)?;
    let sig = dilithium3::DetachedSignature::from_bytes(signature)
        .map_err(|_| DilithiumError::InvalidSignature)?;

    dilithium3::verify_detached_signature(&sig, message, &pk)
        .map_err(|_| DilithiumError::VerificationFailed)
}

/// Key size information for Dilithium3.
pub struct KeySizes;

impl KeySizes {
    pub const PUBLIC_KEY: usize = 1952;
    pub const SECRET_KEY: usize = 4032;
    pub const SIGNATURE: usize = 3309;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = Keypair::generate();
        assert_eq!(kp.public_key.len(), KeySizes::PUBLIC_KEY);
        assert_eq!(kp.secret_key.len(), KeySizes::SECRET_KEY);
    }

    #[test]
    fn test_sign_verify() {
        let kp = Keypair::generate();
        let msg = b"authenticate me";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), KeySizes::SIGNATURE);
        assert!(kp.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"original").unwrap();
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"message").unwrap();
        assert!(kp2.verify(b"message", &sig).is_err());
    }

    #[test]
    fn test_deterministic_verification() {
        let kp = Keypair::generate();
        let msg = b"test";
        let sig = kp.sign(msg).unwrap();
        // Multiple verifications should all succeed
        for _ in 0..10 {
            assert!(kp.verify(msg, &sig).is_ok());
        }
    }

    #[test]
    fn test_different_messages_different_sigs() {
        let kp = Keypair::generate();
        let sig1 = kp.sign(b"msg1").unwrap();
        let sig2 = kp.sign(b"msg2").unwrap();
        assert_ne!(sig1, sig2);
    }
}
