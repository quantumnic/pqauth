//! SHAKE-256 based Message Authentication Code.
//!
//! Replaces HMAC-SHA1 used in classical TOTP with a quantum-resistant MAC
//! built on SHAKE-256 (extendable output function from the SHA-3 family).
//!
//! Construction: MAC(K, M) = SHAKE-256(K || M || K, output_len)
//! This is an envelope MAC (similar to HMAC's double-pass but leveraging
//! SHAKE-256's sponge construction which is resistant to length-extension).

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

/// Default MAC output length in bytes (32 bytes = 256 bits of security).
pub const DEFAULT_MAC_LEN: usize = 32;

/// Compute SHAKE-256 envelope MAC: SHAKE256(key || message || key, out_len).
///
/// The envelope construction prevents length-extension attacks and provides
/// a clean separation between key and message domains.
pub fn shake256_mac(key: &[u8], message: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(key);
    hasher.update(message);
    hasher.update(key);

    let mut output = vec![0u8; out_len];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// Compute MAC and return a fixed-size array (32 bytes).
pub fn shake256_mac_fixed(key: &[u8], message: &[u8]) -> [u8; DEFAULT_MAC_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(key);
    hasher.update(message);
    hasher.update(key);

    let mut output = [0u8; DEFAULT_MAC_LEN];
    let mut reader = hasher.finalize_xof();
    reader.read(&mut output);
    output
}

/// Constant-time comparison of two MACs to prevent timing attacks.
pub fn verify_mac(expected: &[u8], computed: &[u8]) -> bool {
    if expected.len() != computed.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(computed.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// A keyed MAC context that zeroizes the key on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct ShakeMac {
    key: Vec<u8>,
}

impl ShakeMac {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn mac(&self, message: &[u8]) -> [u8; DEFAULT_MAC_LEN] {
        shake256_mac_fixed(&self.key, message)
    }

    pub fn verify(&self, message: &[u8], tag: &[u8]) -> bool {
        let computed = self.mac(message);
        verify_mac(&computed, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_deterministic() {
        let key = b"test-key-256-bits-long-enough!!!";
        let msg = b"hello world";
        let mac1 = shake256_mac(key, msg, 32);
        let mac2 = shake256_mac(key, msg, 32);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_mac_different_keys() {
        let msg = b"same message";
        let mac1 = shake256_mac(b"key1", msg, 32);
        let mac2 = shake256_mac(b"key2", msg, 32);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_mac_different_messages() {
        let key = b"same-key";
        let mac1 = shake256_mac(key, b"msg1", 32);
        let mac2 = shake256_mac(key, b"msg2", 32);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_verify_mac_valid() {
        let mac = ShakeMac::new(b"secret".to_vec());
        let tag = mac.mac(b"data");
        assert!(mac.verify(b"data", &tag));
    }

    #[test]
    fn test_verify_mac_invalid() {
        let mac = ShakeMac::new(b"secret".to_vec());
        let tag = mac.mac(b"data");
        assert!(!mac.verify(b"wrong", &tag));
    }

    #[test]
    fn test_constant_time_comparison() {
        assert!(verify_mac(&[1, 2, 3], &[1, 2, 3]));
        assert!(!verify_mac(&[1, 2, 3], &[1, 2, 4]));
        assert!(!verify_mac(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn test_variable_output_length() {
        let key = b"key";
        let msg = b"msg";
        let short = shake256_mac(key, msg, 16);
        let long = shake256_mac(key, msg, 64);
        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 64);
        // Short should be prefix of long (SHAKE-256 XOF property)
        assert_eq!(&short[..], &long[..16]);
    }
}
