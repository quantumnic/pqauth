//! CRYSTALS-Kyber Key Encapsulation Mechanism (KEM).
//!
//! Kyber is a lattice-based KEM selected by NIST as the primary post-quantum
//! key encapsulation standard (FIPS 203 / ML-KEM).
//!
//! We use Kyber768 (NIST Security Level 3, ~128-bit quantum security).
//!
//! Key sizes:
//!   - Public key:    1184 bytes
//!   - Secret key:    2400 bytes
//!   - Ciphertext:    1088 bytes
//!   - Shared secret: 32 bytes
//!
//! Used in pqauth for:
//!   - Enrollment: Server generates Kyber keypair, client encapsulates shared secret
//!   - The shared secret becomes the seed for PQ-TOTP

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum KyberError {
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("decapsulation failed")]
    DecapsulationFailed,
}

/// Key sizes for Kyber768.
pub struct KeySizes;

impl KeySizes {
    pub const PUBLIC_KEY: usize = 1184;
    pub const SECRET_KEY: usize = 2400;
    pub const CIPHERTEXT: usize = 1088;
    pub const SHARED_SECRET: usize = 32;
}

/// A Kyber768 keypair for key encapsulation.
///
/// The secret key is zeroized when the keypair is dropped.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberKeypair {
    pub public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub secret_key: Vec<u8>,
}

/// Result of encapsulation: ciphertext + shared secret.
///
/// The shared secret is zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Encapsulated {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl KyberKeypair {
    /// Generate a new Kyber768 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    /// Decapsulate: recover the shared secret from a ciphertext.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KyberError> {
        let sk = kyber768::SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| KyberError::InvalidSecretKey)?;
        let ct = kyber768::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| KyberError::InvalidCiphertext)?;
        let ss = kyber768::decapsulate(&ct, &sk);
        Ok(ss.as_bytes().to_vec())
    }
}

/// Encapsulate: generate a shared secret for the given public key.
/// Returns ciphertext (to send to key owner) and shared secret.
pub fn encapsulate(public_key: &[u8]) -> Result<Encapsulated, KyberError> {
    let pk =
        kyber768::PublicKey::from_bytes(public_key).map_err(|_| KyberError::InvalidPublicKey)?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    Ok(Encapsulated {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sizes() {
        let kp = KyberKeypair::generate();
        assert_eq!(kp.public_key.len(), KeySizes::PUBLIC_KEY);
        assert_eq!(kp.secret_key.len(), KeySizes::SECRET_KEY);
    }

    #[test]
    fn test_encapsulate_decapsulate() {
        let kp = KyberKeypair::generate();
        let enc = encapsulate(&kp.public_key).unwrap();
        assert_eq!(enc.ciphertext.len(), KeySizes::CIPHERTEXT);
        assert_eq!(enc.shared_secret.len(), KeySizes::SHARED_SECRET);

        let recovered = kp.decapsulate(&enc.ciphertext).unwrap();
        assert_eq!(enc.shared_secret, recovered);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let kp1 = KyberKeypair::generate();
        let kp2 = KyberKeypair::generate();

        let enc1 = encapsulate(&kp1.public_key).unwrap();
        let enc2 = encapsulate(&kp2.public_key).unwrap();

        assert_ne!(enc1.shared_secret, enc2.shared_secret);
    }

    #[test]
    fn test_wrong_key_decapsulation() {
        let kp1 = KyberKeypair::generate();
        let kp2 = KyberKeypair::generate();

        let enc = encapsulate(&kp1.public_key).unwrap();
        // Decapsulating with wrong key yields a different shared secret (implicit reject)
        let wrong_ss = kp2.decapsulate(&enc.ciphertext).unwrap();
        assert_ne!(enc.shared_secret, wrong_ss);
    }

    #[test]
    fn test_invalid_public_key() {
        let result = encapsulate(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let kp = KyberKeypair::generate();
        let result = kp.decapsulate(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encapsulations_different() {
        let kp = KyberKeypair::generate();
        let enc1 = encapsulate(&kp.public_key).unwrap();
        let enc2 = encapsulate(&kp.public_key).unwrap();

        // Each encapsulation should produce different ciphertext/shared secret
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.shared_secret, enc2.shared_secret);

        // But both should decapsulate correctly
        let ss1 = kp.decapsulate(&enc1.ciphertext).unwrap();
        let ss2 = kp.decapsulate(&enc2.ciphertext).unwrap();
        assert_eq!(enc1.shared_secret, ss1);
        assert_eq!(enc2.shared_secret, ss2);
    }
}
