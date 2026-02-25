//! Secure Key Storage with Argon2id + AES-256-GCM encryption.
//!
//! Protects PQ private keys at rest. The flow:
//!   1. User provides a password/passphrase
//!   2. Argon2id derives a 256-bit encryption key (with random salt)
//!   3. AES-256-GCM encrypts the private key material
//!   4. Salt + nonce + ciphertext stored together
//!
//! Argon2id parameters (OWASP recommendations):
//!   - Memory: 64 MiB
//!   - Iterations: 3
//!   - Parallelism: 4

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// Argon2id parameters.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12; // AES-GCM standard nonce

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed (wrong password or corrupted data)")]
    Decrypt,
    #[error("invalid keystore format")]
    InvalidFormat,
}

/// Encrypted key bundle stored on disk.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedKeystore {
    /// Argon2id salt (32 bytes, hex).
    pub salt: String,
    /// AES-GCM nonce (12 bytes, hex).
    pub nonce: String,
    /// Encrypted key material (hex).
    pub ciphertext: String,
    /// Key type identifier.
    pub key_type: String,
    /// Version for future format changes.
    pub version: u32,
}

/// Derive a 256-bit key from password using Argon2id.
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], KeystoreError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Encrypt key material with a password.
pub fn encrypt(
    key_material: &[u8],
    password: &[u8],
    key_type: &str,
) -> Result<EncryptedKeystore, KeystoreError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let mut derived = derive_key(password, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&derived).map_err(|e| KeystoreError::Encrypt(e.to_string()))?;
    derived.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, key_material)
        .map_err(|e| KeystoreError::Encrypt(e.to_string()))?;

    Ok(EncryptedKeystore {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
        key_type: key_type.to_string(),
        version: 1,
    })
}

/// Decrypt key material with a password.
pub fn decrypt(keystore: &EncryptedKeystore, password: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if keystore.version != 1 {
        return Err(KeystoreError::InvalidFormat);
    }

    let salt = hex::decode(&keystore.salt).map_err(|_| KeystoreError::InvalidFormat)?;
    let nonce_bytes = hex::decode(&keystore.nonce).map_err(|_| KeystoreError::InvalidFormat)?;
    let ciphertext = hex::decode(&keystore.ciphertext).map_err(|_| KeystoreError::InvalidFormat)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidFormat);
    }

    let mut derived = derive_key(password, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&derived).map_err(|e| KeystoreError::Encrypt(e.to_string()))?;
    derived.zeroize();

    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| KeystoreError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = b"this is a secret dilithium key!!";
        let password = b"hunter2";

        let keystore = encrypt(secret, password, "dilithium3").unwrap();
        assert_eq!(keystore.version, 1);
        assert_eq!(keystore.key_type, "dilithium3");

        let recovered = decrypt(&keystore, password).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_wrong_password() {
        let secret = b"secret key material";
        let keystore = encrypt(secret, b"correct", "test").unwrap();

        let result = decrypt(&keystore, b"wrong");
        assert!(result.is_err());
        assert!(matches!(result, Err(KeystoreError::Decrypt)));
    }

    #[test]
    fn test_different_salts() {
        let secret = b"same secret";
        let password = b"same password";

        let ks1 = encrypt(secret, password, "test").unwrap();
        let ks2 = encrypt(secret, password, "test").unwrap();

        // Different random salts → different ciphertexts
        assert_ne!(ks1.salt, ks2.salt);
        assert_ne!(ks1.ciphertext, ks2.ciphertext);

        // Both decrypt correctly
        assert_eq!(decrypt(&ks1, password).unwrap(), secret);
        assert_eq!(decrypt(&ks2, password).unwrap(), secret);
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let secret = b"secret";
        let password = b"pass";

        let mut keystore = encrypt(secret, password, "test").unwrap();
        // Corrupt one byte
        let mut ct = hex::decode(&keystore.ciphertext).unwrap();
        ct[0] ^= 0xFF;
        keystore.ciphertext = hex::encode(ct);

        assert!(matches!(
            decrypt(&keystore, password),
            Err(KeystoreError::Decrypt)
        ));
    }

    #[test]
    fn test_large_key_material() {
        // Dilithium3 secret key is 4032 bytes
        let key = vec![42u8; 4032];
        let password = b"strong-password-123!";

        let keystore = encrypt(&key, password, "dilithium3").unwrap();
        let recovered = decrypt(&keystore, password).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn test_serialization() {
        let secret = b"test";
        let keystore = encrypt(secret, b"pass", "test").unwrap();

        let json = serde_json::to_string(&keystore).unwrap();
        let deserialized: EncryptedKeystore = serde_json::from_str(&json).unwrap();

        assert_eq!(decrypt(&deserialized, b"pass").unwrap(), secret);
    }

    #[test]
    fn test_invalid_version() {
        let mut keystore = encrypt(b"test", b"pass", "test").unwrap();
        keystore.version = 99;
        assert!(matches!(
            decrypt(&keystore, b"pass"),
            Err(KeystoreError::InvalidFormat)
        ));
    }
}
