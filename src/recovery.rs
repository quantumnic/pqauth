//! Recovery Code Generation.
//!
//! Generates backup recovery codes for account recovery when PQ keys are lost.
//! Similar to Google/GitHub backup codes but with higher entropy.
//!
//! Format: 8 groups of 4 alphanumeric chars (e.g., "A3F7-K9M2-P1X4-Q8R6-B2C5-D7E1-G4H8-J6L0")
//! Each code provides ~128 bits of entropy.
//!
//! Codes are stored as SHAKE-256 hashes (server never sees plaintext after generation).

use crate::shake_mac;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Characters used in recovery codes (unambiguous alphanumeric).
/// Excludes: 0/O, 1/I/L, 5/S to avoid confusion.
const ALPHABET: &[u8] = b"2346789ABCDEFGHJKMNPQRTUVWXYZ";

/// Number of recovery codes generated per enrollment.
pub const DEFAULT_CODE_COUNT: usize = 10;

/// Groups per code.
const GROUPS: usize = 8;
/// Characters per group.
const GROUP_LEN: usize = 4;

/// A single recovery code (plaintext, shown to user once).
#[derive(Clone, Debug)]
pub struct RecoveryCode {
    pub code: String,
}

/// A hashed recovery code (stored server-side).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HashedRecoveryCode {
    /// SHAKE-256 hash of the code (hex).
    pub hash: String,
    /// Whether this code has been used.
    pub used: bool,
}

/// Generate a single random recovery code.
pub fn generate_code() -> RecoveryCode {
    let mut rng = rand::thread_rng();
    let mut groups = Vec::with_capacity(GROUPS);

    for _ in 0..GROUPS {
        let group: String = (0..GROUP_LEN)
            .map(|_| {
                let idx = rng.gen_range(0..ALPHABET.len());
                ALPHABET[idx] as char
            })
            .collect();
        groups.push(group);
    }

    RecoveryCode {
        code: groups.join("-"),
    }
}

/// Generate a batch of recovery codes.
pub fn generate_codes(count: usize) -> Vec<RecoveryCode> {
    (0..count).map(|_| generate_code()).collect()
}

/// Hash a recovery code for server-side storage.
pub fn hash_code(code: &str) -> HashedRecoveryCode {
    // Normalize: remove dashes, uppercase
    let normalized: String = code
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_uppercase();
    let hash = shake_mac::shake256_mac(b"pqauth-recovery-v1", normalized.as_bytes(), 32);
    HashedRecoveryCode {
        hash: hex::encode(hash),
        used: false,
    }
}

/// Verify a recovery code against stored hashes.
/// Returns the index of the matching code, or None.
pub fn verify_code(code: &str, stored: &[HashedRecoveryCode]) -> Option<usize> {
    let candidate = hash_code(code);
    stored
        .iter()
        .position(|h| !h.used && h.hash == candidate.hash)
}

/// Recovery code set with hashed codes for storage.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecoveryCodeSet {
    pub codes: Vec<HashedRecoveryCode>,
    pub remaining: usize,
}

impl RecoveryCodeSet {
    /// Create from plaintext codes (hashes them).
    pub fn from_codes(codes: &[RecoveryCode]) -> Self {
        let hashed: Vec<HashedRecoveryCode> = codes.iter().map(|c| hash_code(&c.code)).collect();
        let remaining = hashed.len();
        Self {
            codes: hashed,
            remaining,
        }
    }

    /// Try to use a recovery code. Returns true if valid and unused.
    pub fn use_code(&mut self, code: &str) -> bool {
        if let Some(idx) = verify_code(code, &self.codes) {
            self.codes[idx].used = true;
            self.remaining -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_format() {
        let code = generate_code();
        let parts: Vec<&str> = code.code.split('-').collect();
        assert_eq!(parts.len(), GROUPS);
        for part in &parts {
            assert_eq!(part.len(), GROUP_LEN);
            assert!(part.chars().all(|c| ALPHABET.contains(&(c as u8))));
        }
    }

    #[test]
    fn test_generate_batch() {
        let codes = generate_codes(DEFAULT_CODE_COUNT);
        assert_eq!(codes.len(), DEFAULT_CODE_COUNT);

        // All codes should be unique
        let unique: std::collections::HashSet<_> = codes.iter().map(|c| &c.code).collect();
        assert_eq!(unique.len(), DEFAULT_CODE_COUNT);
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = hash_code("A3F7-K9M2-P1X4-Q8R6-B2C5-D7E1-G4H8-J6N0");
        let h2 = hash_code("A3F7-K9M2-P1X4-Q8R6-B2C5-D7E1-G4H8-J6N0");
        assert_eq!(h1.hash, h2.hash);
    }

    #[test]
    fn test_hash_normalization() {
        // Codes without dashes should hash the same
        let h1 = hash_code("A3F7-K9M2");
        let h2 = hash_code("A3F7K9M2");
        assert_eq!(h1.hash, h2.hash);
    }

    #[test]
    fn test_verify_valid_code() {
        let codes = generate_codes(5);
        let set = RecoveryCodeSet::from_codes(&codes);
        let idx = verify_code(&codes[2].code, &set.codes);
        assert_eq!(idx, Some(2));
    }

    #[test]
    fn test_verify_invalid_code() {
        let codes = generate_codes(5);
        let set = RecoveryCodeSet::from_codes(&codes);
        assert_eq!(
            verify_code("XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX", &set.codes),
            None
        );
    }

    #[test]
    fn test_use_code() {
        let codes = generate_codes(3);
        let mut set = RecoveryCodeSet::from_codes(&codes);
        assert_eq!(set.remaining, 3);

        assert!(set.use_code(&codes[0].code));
        assert_eq!(set.remaining, 2);

        // Can't reuse
        assert!(!set.use_code(&codes[0].code));
        assert_eq!(set.remaining, 2);

        // Other codes still work
        assert!(set.use_code(&codes[1].code));
        assert_eq!(set.remaining, 1);
    }

    #[test]
    fn test_serialization() {
        let codes = generate_codes(3);
        let set = RecoveryCodeSet::from_codes(&codes);
        let json = serde_json::to_string(&set).unwrap();
        let deserialized: RecoveryCodeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.codes.len(), 3);
        assert_eq!(deserialized.remaining, 3);

        // Verify works on deserialized
        assert!(verify_code(&codes[1].code, &deserialized.codes).is_some());
    }

    #[test]
    fn test_entropy() {
        // Each char has log2(29) ≈ 4.86 bits of entropy
        // 8 groups × 4 chars = 32 chars → ~155 bits of entropy
        let code = generate_code();
        let chars: Vec<char> = code.code.chars().filter(|c| *c != '-').collect();
        assert_eq!(chars.len(), GROUPS * GROUP_LEN);
        // 155 bits > 128 bits minimum ✓
    }
}
