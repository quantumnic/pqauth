//! Challenge-Response Authentication Protocol.
//!
//! Flow:
//!   1. Server generates a random 32-byte challenge (nonce)
//!   2. Server sends challenge to client
//!   3. Client signs: signature = Dilithium.Sign(sk, challenge || timestamp)
//!   4. Client sends (signature, timestamp) back
//!   5. Server verifies signature against stored public key
//!   6. Server checks timestamp is within acceptable window
//!   7. Server checks nonce hasn't been reused (replay prevention)

use crate::dilithium::{self, Keypair};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Challenge validity window in seconds.
pub const CHALLENGE_VALIDITY_SECS: u64 = 300; // 5 minutes

#[derive(Error, Debug)]
pub enum ChallengeError {
    #[error("challenge expired")]
    Expired,
    #[error("challenge already used (replay attack)")]
    Replay,
    #[error("signature verification failed: {0}")]
    SignatureFailed(#[from] dilithium::DilithiumError),
    #[error("timestamp out of range")]
    TimestampOutOfRange,
}

/// A challenge issued by the server.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Challenge {
    /// Random 32-byte nonce.
    pub nonce: [u8; 32],
    /// Unix timestamp when the challenge was issued.
    pub issued_at: u64,
}

impl Challenge {
    /// Generate a new random challenge.
    pub fn new(timestamp: u64) -> Self {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            nonce,
            issued_at: timestamp,
        }
    }

    /// Build the message to be signed: nonce || timestamp_bytes.
    pub fn signing_payload(&self, client_timestamp: u64) -> Vec<u8> {
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&client_timestamp.to_be_bytes());
        payload
    }

    /// Check if the challenge has expired.
    pub fn is_expired(&self, current_timestamp: u64) -> bool {
        current_timestamp.saturating_sub(self.issued_at) > CHALLENGE_VALIDITY_SECS
    }
}

/// A client's response to a challenge.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeResponse {
    /// The original challenge nonce (to identify which challenge).
    pub nonce: [u8; 32],
    /// Client's timestamp when signing.
    pub client_timestamp: u64,
    /// Dilithium signature over (nonce || client_timestamp).
    pub signature: Vec<u8>,
}

/// Client-side: sign a challenge.
pub fn respond_to_challenge(
    keypair: &Keypair,
    challenge: &Challenge,
    client_timestamp: u64,
) -> Result<ChallengeResponse, dilithium::DilithiumError> {
    let payload = challenge.signing_payload(client_timestamp);
    let signature = keypair.sign(&payload)?;
    Ok(ChallengeResponse {
        nonce: challenge.nonce,
        client_timestamp,
        signature,
    })
}

/// Server-side verifier with replay prevention.
pub struct ChallengeVerifier {
    /// Set of used nonces (in production, use a time-bounded cache).
    used_nonces: HashSet<[u8; 32]>,
    /// Maximum allowed clock skew in seconds.
    max_clock_skew: u64,
}

impl ChallengeVerifier {
    pub fn new(max_clock_skew: u64) -> Self {
        Self {
            used_nonces: HashSet::new(),
            max_clock_skew,
        }
    }

    /// Verify a challenge response.
    pub fn verify(
        &mut self,
        challenge: &Challenge,
        response: &ChallengeResponse,
        public_key: &[u8],
        current_timestamp: u64,
    ) -> Result<(), ChallengeError> {
        // 1. Check challenge not expired
        if challenge.is_expired(current_timestamp) {
            return Err(ChallengeError::Expired);
        }

        // 2. Check nonce not reused
        if self.used_nonces.contains(&response.nonce) {
            return Err(ChallengeError::Replay);
        }

        // 3. Check client timestamp is reasonable
        let skew = response.client_timestamp.abs_diff(current_timestamp);
        if skew > self.max_clock_skew {
            return Err(ChallengeError::TimestampOutOfRange);
        }

        // 4. Verify signature
        let payload = challenge.signing_payload(response.client_timestamp);
        dilithium::verify_detached(public_key, &payload, &response.signature)?;

        // 5. Mark nonce as used
        self.used_nonces.insert(response.nonce);

        Ok(())
    }

    /// Clear expired nonces (call periodically).
    pub fn clear_expired(&mut self) {
        // In a real implementation, nonces would be stored with timestamps
        // and expired ones pruned. For now, just clear all.
        self.used_nonces.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_response_flow() {
        let keypair = Keypair::generate();
        let server_time = 1000000u64;
        let client_time = 1000001u64;

        // Server issues challenge
        let challenge = Challenge::new(server_time);

        // Client responds
        let response = respond_to_challenge(&keypair, &challenge, client_time).unwrap();

        // Server verifies
        let mut verifier = ChallengeVerifier::new(60);
        let result = verifier.verify(&challenge, &response, &keypair.public_key, server_time + 5);
        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_prevention() {
        let keypair = Keypair::generate();
        let ts = 1000000u64;

        let challenge = Challenge::new(ts);
        let response = respond_to_challenge(&keypair, &challenge, ts).unwrap();

        let mut verifier = ChallengeVerifier::new(60);

        // First verification succeeds
        assert!(verifier
            .verify(&challenge, &response, &keypair.public_key, ts + 1)
            .is_ok());

        // Replay should fail
        let result = verifier.verify(&challenge, &response, &keypair.public_key, ts + 2);
        assert!(matches!(result, Err(ChallengeError::Replay)));
    }

    #[test]
    fn test_expired_challenge() {
        let keypair = Keypair::generate();
        let ts = 1000000u64;

        let challenge = Challenge::new(ts);
        let response = respond_to_challenge(&keypair, &challenge, ts).unwrap();

        let mut verifier = ChallengeVerifier::new(60);
        let result = verifier.verify(
            &challenge,
            &response,
            &keypair.public_key,
            ts + CHALLENGE_VALIDITY_SECS + 1,
        );
        assert!(matches!(result, Err(ChallengeError::Expired)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = Keypair::generate();
        let keypair2 = Keypair::generate();
        let ts = 1000000u64;

        let challenge = Challenge::new(ts);
        let response = respond_to_challenge(&keypair1, &challenge, ts).unwrap();

        let mut verifier = ChallengeVerifier::new(60);
        let result = verifier.verify(&challenge, &response, &keypair2.public_key, ts + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_clock_skew_tolerance() {
        let keypair = Keypair::generate();
        let server_time = 1000000u64;

        let challenge = Challenge::new(server_time);
        // Client clock is 30s ahead
        let response = respond_to_challenge(&keypair, &challenge, server_time + 30).unwrap();

        let mut verifier = ChallengeVerifier::new(60);
        // Should pass with 60s tolerance
        assert!(verifier
            .verify(&challenge, &response, &keypair.public_key, server_time + 1)
            .is_ok());
    }

    #[test]
    fn test_excessive_clock_skew() {
        let keypair = Keypair::generate();
        let ts = 1000000u64;

        let challenge = Challenge::new(ts);
        // Client clock is way off
        let response = respond_to_challenge(&keypair, &challenge, ts + 1000).unwrap();

        let mut verifier = ChallengeVerifier::new(60);
        let result = verifier.verify(&challenge, &response, &keypair.public_key, ts + 1);
        assert!(matches!(result, Err(ChallengeError::TimestampOutOfRange)));
    }
}
