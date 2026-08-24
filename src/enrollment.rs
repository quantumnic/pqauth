//! Enrollment Protocol: Kyber-based key exchange for 2FA setup.
//!
//! Protocol flow:
//!   1. Client generates Dilithium keypair (signing) + optional Ed25519 (hybrid)
//!   2. Server generates Kyber keypair, sends public key to client
//!   3. Client encapsulates a shared secret using server's Kyber public key
//!   4. Client sends: (ciphertext, dilithium_public_key) to server
//!   5. Server decapsulates to recover shared secret
//!   6. Both derive a PQ-TOTP seed from the shared secret using SHAKE-256
//!   7. Server stores: client's Dilithium public key + TOTP seed
//!   8. Client stores: TOTP seed + server identity
//!
//! The shared secret from Kyber is quantum-safe, so even if the enrollment
//! exchange is recorded, a future quantum computer cannot recover the TOTP seed.

use crate::dilithium::KeySizes as DilithiumKeySizes;
use crate::kyber::{self, Encapsulated, KeySizes as KyberKeySizes, KyberKeypair};
use crate::shake_mac;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for TOTP seed derivation.
const TOTP_SEED_DOMAIN: &[u8] = b"pqauth-totp-seed-v1";

/// Length of derived TOTP seed in bytes.
pub const TOTP_SEED_LEN: usize = 32;

#[derive(Error, Debug)]
pub enum EnrollmentError {
    #[error("Kyber error: {0}")]
    Kyber(#[from] kyber::KyberError),
    #[error("invalid server identity")]
    InvalidServerIdentity,
    #[error("invalid ciphertext length (expected {expected}, got {got})")]
    InvalidCiphertextLength { expected: usize, got: usize },
    #[error("invalid Dilithium public key length (expected {expected}, got {got})")]
    InvalidPublicKeyLength { expected: usize, got: usize },
}

/// Server-side enrollment state.
///
/// The ephemeral Kyber secret key is zeroized when dropped.
#[derive(Serialize, Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerEnrollment {
    /// Server's Kyber keypair (ephemeral, for this enrollment only).
    pub kyber_public_key: Vec<u8>,
    #[serde(skip_serializing)]
    pub kyber_secret_key: Vec<u8>,
    /// Server identity string (e.g., domain name).
    pub server_id: String,
}

/// Data sent from server to client to initiate enrollment.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrollmentChallenge {
    pub kyber_public_key: Vec<u8>,
    pub server_id: String,
}

/// Data sent from client to server to complete enrollment.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnrollmentResponse {
    /// Kyber ciphertext (encapsulated shared secret).
    pub ciphertext: Vec<u8>,
    /// Client's Dilithium public key (for future challenge-response auth).
    pub dilithium_public_key: Vec<u8>,
}

/// Completed enrollment record stored by the server.
///
/// The TOTP seed is zeroized when the record is dropped.
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentRecord {
    /// Client's Dilithium public key.
    pub dilithium_public_key: Vec<u8>,
    /// Derived TOTP seed (shared between client and server).
    pub totp_seed: Vec<u8>,
    /// Server identity.
    pub server_id: String,
}

/// Client-side enrollment result.
///
/// The TOTP seed is zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientEnrollment {
    /// Derived TOTP seed.
    pub totp_seed: Vec<u8>,
    /// Server identity.
    pub server_id: String,
}

// --- Server-side functions ---

impl ServerEnrollment {
    /// Create a new enrollment session.
    pub fn new(server_id: &str) -> Self {
        let kp = KyberKeypair::generate();
        Self {
            kyber_public_key: kp.public_key.clone(),
            kyber_secret_key: kp.secret_key.clone(),
            server_id: server_id.to_string(),
        }
    }

    /// Generate the challenge to send to the client.
    pub fn challenge(&self) -> EnrollmentChallenge {
        EnrollmentChallenge {
            kyber_public_key: self.kyber_public_key.clone(),
            server_id: self.server_id.clone(),
        }
    }

    /// Complete enrollment using the client's response.
    pub fn complete(
        &self,
        response: &EnrollmentResponse,
    ) -> Result<EnrollmentRecord, EnrollmentError> {
        // Validate lengths before touching key material so malformed
        // enrollments are rejected with a clear error instead of being
        // stored and only failing later during authentication.
        if response.ciphertext.len() != KyberKeySizes::CIPHERTEXT {
            return Err(EnrollmentError::InvalidCiphertextLength {
                expected: KyberKeySizes::CIPHERTEXT,
                got: response.ciphertext.len(),
            });
        }
        if response.dilithium_public_key.len() != DilithiumKeySizes::PUBLIC_KEY {
            return Err(EnrollmentError::InvalidPublicKeyLength {
                expected: DilithiumKeySizes::PUBLIC_KEY,
                got: response.dilithium_public_key.len(),
            });
        }

        // Reconstruct Kyber keypair to decapsulate
        let kp = KyberKeypair {
            public_key: self.kyber_public_key.clone(),
            secret_key: self.kyber_secret_key.clone(),
        };
        let shared_secret = kp.decapsulate(&response.ciphertext)?;
        let totp_seed = derive_totp_seed(&shared_secret, &self.server_id);

        Ok(EnrollmentRecord {
            dilithium_public_key: response.dilithium_public_key.clone(),
            totp_seed,
            server_id: self.server_id.clone(),
        })
    }
}

// --- Client-side functions ---

/// Client processes the enrollment challenge from the server.
/// Returns the response to send back + the client's enrollment data.
pub fn client_enroll(
    challenge: &EnrollmentChallenge,
    dilithium_public_key: &[u8],
) -> Result<(EnrollmentResponse, ClientEnrollment), EnrollmentError> {
    if challenge.server_id.is_empty() {
        return Err(EnrollmentError::InvalidServerIdentity);
    }

    let encapsulated = kyber::encapsulate(&challenge.kyber_public_key)?;
    let Encapsulated {
        ciphertext,
        shared_secret,
    } = &encapsulated;

    let totp_seed = derive_totp_seed(shared_secret, &challenge.server_id);

    let response = EnrollmentResponse {
        ciphertext: ciphertext.clone(),
        dilithium_public_key: dilithium_public_key.to_vec(),
    };

    let client_data = ClientEnrollment {
        totp_seed,
        server_id: challenge.server_id.clone(),
    };

    Ok((response, client_data))
}

/// Derive a TOTP seed from a Kyber shared secret + server identity.
/// Uses SHAKE-256 with a domain separator for key derivation.
fn derive_totp_seed(shared_secret: &[u8], server_id: &str) -> Vec<u8> {
    // Build input: domain || shared_secret || server_id
    let mut input = Vec::new();
    input.extend_from_slice(TOTP_SEED_DOMAIN);
    input.extend_from_slice(shared_secret);
    input.extend_from_slice(server_id.as_bytes());

    shake_mac::shake256(&input, TOTP_SEED_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dilithium;

    #[test]
    fn test_full_enrollment_flow() {
        // 1. Client generates Dilithium keypair
        let client_kp = dilithium::Keypair::generate();

        // 2. Server creates enrollment session
        let server = ServerEnrollment::new("example.com");
        let challenge = server.challenge();

        // 3. Client processes challenge
        let (response, client_data) = client_enroll(&challenge, &client_kp.public_key).unwrap();

        // 4. Server completes enrollment
        let record = server.complete(&response).unwrap();

        // 5. Both should have the same TOTP seed
        assert_eq!(client_data.totp_seed, record.totp_seed);
        assert_eq!(client_data.totp_seed.len(), TOTP_SEED_LEN);
        assert_eq!(record.server_id, "example.com");
        assert_eq!(record.dilithium_public_key, client_kp.public_key);
    }

    #[test]
    fn test_different_enrollments_different_seeds() {
        let client_kp = dilithium::Keypair::generate();

        let server1 = ServerEnrollment::new("example.com");
        let challenge1 = server1.challenge();
        let (resp1, data1) = client_enroll(&challenge1, &client_kp.public_key).unwrap();
        let _record1 = server1.complete(&resp1).unwrap();

        let server2 = ServerEnrollment::new("example.com");
        let challenge2 = server2.challenge();
        let (resp2, data2) = client_enroll(&challenge2, &client_kp.public_key).unwrap();
        let _record2 = server2.complete(&resp2).unwrap();

        // Different Kyber keypairs → different shared secrets → different seeds
        assert_ne!(data1.totp_seed, data2.totp_seed);
    }

    #[test]
    fn test_different_servers_different_seeds() {
        let client_kp = dilithium::Keypair::generate();

        // Same Kyber keypair but different server_id should give different seeds
        // (due to domain separation in derive_totp_seed)
        // We can't easily test this with same shared_secret since Kyber is randomized,
        // but we can test derive_totp_seed directly
        let shared = vec![0xABu8; 32];
        let seed1 = derive_totp_seed(&shared, "server-a.com");
        let seed2 = derive_totp_seed(&shared, "server-b.com");
        assert_ne!(seed1, seed2);

        // Also check that client key is stored
        let server = ServerEnrollment::new("test.com");
        let challenge = server.challenge();
        let (resp, _) = client_enroll(&challenge, &client_kp.public_key).unwrap();
        let record = server.complete(&resp).unwrap();
        assert_eq!(record.dilithium_public_key, client_kp.public_key);
    }

    #[test]
    fn test_empty_server_id_rejected() {
        let client_kp = dilithium::Keypair::generate();
        let server = ServerEnrollment::new("valid.com");
        let mut challenge = server.challenge();
        challenge.server_id = String::new();

        let result = client_enroll(&challenge, &client_kp.public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_seed_deterministic_derivation() {
        // Same inputs should always give the same seed
        let shared = vec![0x42u8; 32];
        let s1 = derive_totp_seed(&shared, "test.com");
        let s2 = derive_totp_seed(&shared, "test.com");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_reject_short_ciphertext() {
        let client_kp = dilithium::Keypair::generate();
        let server = ServerEnrollment::new("example.com");
        let (mut response, _) = client_enroll(&server.challenge(), &client_kp.public_key).unwrap();
        response.ciphertext.truncate(KyberKeySizes::CIPHERTEXT - 1);

        let result = server.complete(&response);
        assert!(matches!(
            result,
            Err(EnrollmentError::InvalidCiphertextLength { .. })
        ));
    }

    #[test]
    fn test_reject_invalid_public_key_length() {
        let client_kp = dilithium::Keypair::generate();
        let server = ServerEnrollment::new("example.com");
        let (mut response, _) = client_enroll(&server.challenge(), &client_kp.public_key).unwrap();
        response.dilithium_public_key = vec![0u8; 32];

        let result = server.complete(&response);
        assert!(matches!(
            result,
            Err(EnrollmentError::InvalidPublicKeyLength {
                expected: DilithiumKeySizes::PUBLIC_KEY,
                got: 32
            })
        ));
    }

    #[test]
    fn test_enrollment_totp_integration() {
        // Verify the derived seed works with PQ-TOTP
        use crate::pq_totp;

        let client_kp = dilithium::Keypair::generate();
        let server = ServerEnrollment::new("example.com");
        let challenge = server.challenge();
        let (response, client_data) = client_enroll(&challenge, &client_kp.public_key).unwrap();
        let record = server.complete(&response).unwrap();

        // Both sides generate the same TOTP code
        let ts = 1000000u64;
        let client_code = pq_totp::generate(&client_data.totp_seed, ts);
        let server_code = pq_totp::generate(&record.totp_seed, ts);
        assert_eq!(client_code, server_code);

        // And verification works
        assert!(pq_totp::verify(&record.totp_seed, client_code, ts, 1));
    }
}
