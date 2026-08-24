//! Hybrid Signature Scheme: Ed25519 + Dilithium3.
//!
//! Combines a classical (Ed25519) and post-quantum (Dilithium3) signature
//! into a single composite signature. Both must verify for the signature
//! to be considered valid.
//!
//! This provides security during the quantum transition period:
//! - If quantum computers arrive: Ed25519 breaks, but Dilithium holds.
//! - If Dilithium has a classical flaw: Ed25519 still protects.
//!
//! Composite signature format:
//!   [ed25519_sig (64 bytes)] || [dilithium3_sig (3309 bytes)]
//!
//! Total hybrid signature: 3373 bytes.

use crate::dilithium::{self, DilithiumError};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ed25519 signature size.
pub const ED25519_SIG_SIZE: usize = 64;

/// Total hybrid signature size.
pub const HYBRID_SIG_SIZE: usize = ED25519_SIG_SIZE + dilithium::KeySizes::SIGNATURE;

#[derive(Error, Debug)]
pub enum HybridError {
    #[error("Ed25519 verification failed")]
    Ed25519Failed,
    #[error("Dilithium verification failed: {0}")]
    DilithiumFailed(#[from] DilithiumError),
    #[error("invalid hybrid signature length (expected {expected}, got {got})")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("invalid Ed25519 public key")]
    InvalidEd25519PublicKey,
    #[error("invalid Ed25519 secret key")]
    InvalidEd25519SecretKey,
}

/// A hybrid keypair containing both Ed25519 and Dilithium3 keys.
///
/// Secret key material is zeroized when the keypair is dropped.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeypair {
    /// Ed25519 public key (32 bytes).
    pub ed25519_public: Vec<u8>,
    /// Ed25519 secret key (32 bytes seed).
    #[serde(skip_serializing)]
    pub ed25519_secret: Vec<u8>,
    /// Dilithium3 public key (1952 bytes).
    pub dilithium_public: Vec<u8>,
    /// Dilithium3 secret key (4032 bytes).
    #[serde(skip_serializing)]
    pub dilithium_secret: Vec<u8>,
}

/// A hybrid public key (no secrets).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HybridPublicKey {
    pub ed25519: Vec<u8>,
    pub dilithium: Vec<u8>,
}

impl HybridKeypair {
    /// Generate a new hybrid keypair.
    pub fn generate() -> Self {
        let ed_signing = SigningKey::generate(&mut OsRng);
        let ed_verifying = ed_signing.verifying_key();

        let dil = dilithium::Keypair::generate();

        Self {
            ed25519_public: ed_verifying.to_bytes().to_vec(),
            ed25519_secret: ed_signing.to_bytes().to_vec(),
            dilithium_public: dil.public_key.clone(),
            dilithium_secret: dil.secret_key.clone(),
        }
    }

    /// Extract the public key portion.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519_public.clone(),
            dilithium: self.dilithium_public.clone(),
        }
    }

    /// Sign a message with both Ed25519 and Dilithium3.
    /// Returns a composite signature: ed25519_sig || dilithium_sig.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
        // Ed25519 sign
        let ed_secret: [u8; 32] = self
            .ed25519_secret
            .as_slice()
            .try_into()
            .map_err(|_| HybridError::InvalidEd25519SecretKey)?;
        let ed_signing = SigningKey::from_bytes(&ed_secret);
        let ed_sig = ed_signing.sign(message);

        // Dilithium sign
        let dil_kp = dilithium::Keypair {
            public_key: self.dilithium_public.clone(),
            secret_key: self.dilithium_secret.clone(),
        };
        let dil_sig = dil_kp.sign(message)?;

        // Composite: ed25519 || dilithium
        let mut composite = Vec::with_capacity(HYBRID_SIG_SIZE);
        composite.extend_from_slice(&ed_sig.to_bytes());
        composite.extend_from_slice(&dil_sig);
        Ok(composite)
    }

    /// Verify a hybrid signature against this keypair's public keys.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), HybridError> {
        verify_hybrid(&self.public_key(), message, signature)
    }
}

/// Verify a hybrid signature against a public key.
pub fn verify_hybrid(
    public_key: &HybridPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), HybridError> {
    if signature.len() != HYBRID_SIG_SIZE {
        return Err(HybridError::InvalidSignatureLength {
            expected: HYBRID_SIG_SIZE,
            got: signature.len(),
        });
    }

    let (ed_sig_bytes, dil_sig_bytes) = signature.split_at(ED25519_SIG_SIZE);

    // Verify Ed25519
    let ed_pub_bytes: [u8; 32] = public_key
        .ed25519
        .as_slice()
        .try_into()
        .map_err(|_| HybridError::InvalidEd25519PublicKey)?;
    let ed_verifying = VerifyingKey::from_bytes(&ed_pub_bytes)
        .map_err(|_| HybridError::InvalidEd25519PublicKey)?;
    let ed_sig_arr: [u8; 64] = ed_sig_bytes
        .try_into()
        .map_err(|_| HybridError::Ed25519Failed)?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_arr);
    ed_verifying
        .verify(message, &ed_sig)
        .map_err(|_| HybridError::Ed25519Failed)?;

    // Verify Dilithium
    dilithium::verify_detached(&public_key.dilithium, message, dil_sig_bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keygen() {
        let kp = HybridKeypair::generate();
        assert_eq!(kp.ed25519_public.len(), 32);
        assert_eq!(kp.ed25519_secret.len(), 32);
        assert_eq!(kp.dilithium_public.len(), dilithium::KeySizes::PUBLIC_KEY);
        assert_eq!(kp.dilithium_secret.len(), dilithium::KeySizes::SECRET_KEY);
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let kp = HybridKeypair::generate();
        let msg = b"hybrid authentication test";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), HYBRID_SIG_SIZE);
        assert!(kp.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_wrong_message() {
        let kp = HybridKeypair::generate();
        let sig = kp.sign(b"original").unwrap();
        assert!(kp.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn test_hybrid_wrong_key() {
        let kp1 = HybridKeypair::generate();
        let kp2 = HybridKeypair::generate();
        let sig = kp1.sign(b"message").unwrap();
        assert!(verify_hybrid(&kp2.public_key(), b"message", &sig).is_err());
    }

    #[test]
    fn test_hybrid_truncated_sig() {
        let kp = HybridKeypair::generate();
        let sig = kp.sign(b"msg").unwrap();
        assert!(kp.verify(b"msg", &sig[..sig.len() - 1]).is_err());
    }

    #[test]
    fn test_hybrid_corrupted_ed25519_portion() {
        let kp = HybridKeypair::generate();
        let mut sig = kp.sign(b"msg").unwrap();
        sig[0] ^= 0xff; // corrupt ed25519 portion
        assert!(kp.verify(b"msg", &sig).is_err());
    }

    #[test]
    fn test_hybrid_corrupted_dilithium_portion() {
        let kp = HybridKeypair::generate();
        let mut sig = kp.sign(b"msg").unwrap();
        sig[ED25519_SIG_SIZE + 10] ^= 0xff; // corrupt dilithium portion
        assert!(kp.verify(b"msg", &sig).is_err());
    }

    #[test]
    fn test_hybrid_public_key_extraction() {
        let kp = HybridKeypair::generate();
        let pk = kp.public_key();
        assert_eq!(pk.ed25519, kp.ed25519_public);
        assert_eq!(pk.dilithium, kp.dilithium_public);
    }
}
