//! PQ-Auth REST Server.
//!
//! Provides a JSON API for post-quantum 2FA:
//!   - POST /enroll/begin      — Start enrollment, get Kyber public key
//!   - POST /enroll/complete    — Finish enrollment with client's response
//!   - POST /challenge          — Get a challenge for authentication
//!   - POST /verify             — Verify a challenge response or TOTP code
//!
//! All state is in-memory (for research/demo purposes).

use crate::challenge::{
    self, Challenge, ChallengeResponse, ChallengeVerifier,
};
use crate::enrollment::{self, EnrollmentRecord, ServerEnrollment};
use crate::pq_totp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("user already enrolled: {0}")]
    UserAlreadyEnrolled(String),
    #[error("no pending enrollment for user: {0}")]
    NoPendingEnrollment(String),
    #[error("no pending challenge for user: {0}")]
    NoPendingChallenge(String),
    #[error("enrollment failed: {0}")]
    EnrollmentFailed(#[from] enrollment::EnrollmentError),
    #[error("challenge verification failed: {0}")]
    ChallengeFailed(#[from] challenge::ChallengeError),
    #[error("rate limited")]
    RateLimited,
}

/// Audit log entry.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub user_id: String,
    pub action: String,
    pub success: bool,
    pub detail: Option<String>,
}

/// Server state (in-memory).
#[derive(Clone)]
pub struct PqAuthServer {
    inner: Arc<Mutex<ServerInner>>,
}

struct ServerInner {
    /// Server identity (e.g., domain).
    server_id: String,
    /// Enrolled users: user_id → enrollment record.
    users: HashMap<String, EnrollmentRecord>,
    /// Pending enrollments: user_id → server enrollment state.
    pending_enrollments: HashMap<String, ServerEnrollment>,
    /// Pending challenges: user_id → challenge.
    pending_challenges: HashMap<String, Challenge>,
    /// Challenge verifier (nonce tracking).
    verifier: ChallengeVerifier,
    /// Audit log.
    audit_log: Vec<AuditEntry>,
    /// Rate limit: user_id → (count, window_start).
    rate_limits: HashMap<String, (u32, u64)>,
    /// Max attempts per rate limit window.
    max_attempts: u32,
    /// Rate limit window in seconds.
    rate_window: u64,
}

// --- Request/Response types for the API ---

#[derive(Serialize, Deserialize, Debug)]
pub struct EnrollBeginRequest {
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnrollBeginResponse {
    pub kyber_public_key: String, // hex
    pub server_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnrollCompleteRequest {
    pub user_id: String,
    pub ciphertext: String,           // hex
    pub dilithium_public_key: String, // hex
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EnrollCompleteResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeRequest {
    pub user_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeIssued {
    pub nonce: String, // hex
    pub issued_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyRequest {
    pub user_id: String,
    /// Either a TOTP code or a challenge-response.
    #[serde(flatten)]
    pub method: VerifyMethod,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum VerifyMethod {
    Totp {
        totp_code: u32,
    },
    Challenge {
        nonce: String,
        client_timestamp: u64,
        signature: String, // hex
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyResponse {
    pub valid: bool,
    pub message: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

impl PqAuthServer {
    pub fn new(server_id: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ServerInner {
                server_id: server_id.to_string(),
                users: HashMap::new(),
                pending_enrollments: HashMap::new(),
                pending_challenges: HashMap::new(),
                verifier: ChallengeVerifier::new(60),
                audit_log: Vec::new(),
                rate_limits: HashMap::new(),
                max_attempts: 5,
                rate_window: 300,
            })),
        }
    }

    fn audit(
        &self,
        inner: &mut ServerInner,
        user_id: &str,
        action: &str,
        success: bool,
        detail: Option<String>,
    ) {
        inner.audit_log.push(AuditEntry {
            timestamp: now_unix(),
            user_id: user_id.to_string(),
            action: action.to_string(),
            success,
            detail,
        });
    }

    fn check_rate_limit(&self, inner: &mut ServerInner, user_id: &str) -> Result<(), ServerError> {
        let now = now_unix();
        let entry = inner
            .rate_limits
            .entry(user_id.to_string())
            .or_insert((0, now));
        if now - entry.1 > inner.rate_window {
            *entry = (1, now);
            Ok(())
        } else {
            entry.0 += 1;
            if entry.0 > inner.max_attempts {
                Err(ServerError::RateLimited)
            } else {
                Ok(())
            }
        }
    }

    /// Begin enrollment for a user.
    pub fn enroll_begin(&self, user_id: &str) -> Result<EnrollBeginResponse, ServerError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.users.contains_key(user_id) {
            return Err(ServerError::UserAlreadyEnrolled(user_id.to_string()));
        }

        let enrollment = ServerEnrollment::new(&inner.server_id);
        let challenge = enrollment.challenge();
        let resp = EnrollBeginResponse {
            kyber_public_key: hex::encode(&challenge.kyber_public_key),
            server_id: challenge.server_id,
        };
        inner
            .pending_enrollments
            .insert(user_id.to_string(), enrollment);
        self.audit(&mut inner, user_id, "enroll_begin", true, None);
        Ok(resp)
    }

    /// Complete enrollment for a user.
    pub fn enroll_complete(
        &self,
        req: &EnrollCompleteRequest,
    ) -> Result<EnrollCompleteResponse, ServerError> {
        let mut inner = self.inner.lock().unwrap();
        let enrollment = inner
            .pending_enrollments
            .remove(&req.user_id)
            .ok_or_else(|| ServerError::NoPendingEnrollment(req.user_id.clone()))?;

        let response = enrollment::EnrollmentResponse {
            ciphertext: hex::decode(&req.ciphertext).unwrap_or_default(),
            dilithium_public_key: hex::decode(&req.dilithium_public_key).unwrap_or_default(),
        };

        let record = enrollment.complete(&response)?;
        inner.users.insert(req.user_id.clone(), record);
        self.audit(&mut inner, &req.user_id, "enroll_complete", true, None);
        Ok(EnrollCompleteResponse {
            success: true,
            message: "Enrollment successful".to_string(),
        })
    }

    /// Issue a challenge for authentication.
    pub fn issue_challenge(&self, user_id: &str) -> Result<ChallengeIssued, ServerError> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.users.contains_key(user_id) {
            return Err(ServerError::UserNotFound(user_id.to_string()));
        }
        self.check_rate_limit(&mut inner, user_id)?;

        let ts = now_unix();
        let challenge = Challenge::new(ts);
        let resp = ChallengeIssued {
            nonce: hex::encode(challenge.nonce),
            issued_at: challenge.issued_at,
        };
        inner
            .pending_challenges
            .insert(user_id.to_string(), challenge);
        self.audit(&mut inner, user_id, "challenge_issued", true, None);
        Ok(resp)
    }

    /// Verify authentication (TOTP or challenge-response).
    pub fn verify(&self, req: &VerifyRequest) -> Result<VerifyResponse, ServerError> {
        let mut inner = self.inner.lock().unwrap();
        let user = inner
            .users
            .get(&req.user_id)
            .ok_or_else(|| ServerError::UserNotFound(req.user_id.clone()))?
            .clone();

        self.check_rate_limit(&mut inner, &req.user_id)?;

        match &req.method {
            VerifyMethod::Totp { totp_code } => {
                let ts = now_unix();
                let valid = pq_totp::verify(&user.totp_seed, *totp_code, ts, 1);
                self.audit(
                    &mut inner,
                    &req.user_id,
                    "verify_totp",
                    valid,
                    Some(format!("code={totp_code}")),
                );
                Ok(VerifyResponse {
                    valid,
                    message: if valid {
                        "TOTP verified".to_string()
                    } else {
                        "Invalid TOTP code".to_string()
                    },
                })
            }
            VerifyMethod::Challenge {
                nonce,
                client_timestamp,
                signature,
            } => {
                let challenge = inner
                    .pending_challenges
                    .remove(&req.user_id)
                    .ok_or_else(|| ServerError::NoPendingChallenge(req.user_id.clone()))?;

                let nonce_bytes: [u8; 32] = hex::decode(nonce)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap_or([0u8; 32]);

                let cr = ChallengeResponse {
                    nonce: nonce_bytes,
                    client_timestamp: *client_timestamp,
                    signature: hex::decode(signature).unwrap_or_default(),
                };

                let ts = now_unix();
                let result = inner
                    .verifier
                    .verify(&challenge, &cr, &user.dilithium_public_key, ts);

                let valid = result.is_ok();
                self.audit(
                    &mut inner,
                    &req.user_id,
                    "verify_challenge",
                    valid,
                    result.err().map(|e| e.to_string()),
                );

                Ok(VerifyResponse {
                    valid,
                    message: if valid {
                        "Challenge-response verified".to_string()
                    } else {
                        "Challenge verification failed".to_string()
                    },
                })
            }
        }
    }

    /// Get audit log entries.
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap().audit_log.clone()
    }

    /// Check if a user is enrolled.
    pub fn is_enrolled(&self, user_id: &str) -> bool {
        self.inner.lock().unwrap().users.contains_key(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dilithium;

    #[test]
    fn test_full_enrollment_and_totp_verify() {
        let server = PqAuthServer::new("test.pqauth.dev");

        // Begin enrollment
        let begin = server.enroll_begin("alice").unwrap();
        assert!(!begin.kyber_public_key.is_empty());

        // Client side: generate keys and enroll
        let client_kp = dilithium::Keypair::generate();
        let challenge = enrollment::EnrollmentChallenge {
            kyber_public_key: hex::decode(&begin.kyber_public_key).unwrap(),
            server_id: begin.server_id,
        };
        let (resp, client_data) =
            enrollment::client_enroll(&challenge, &client_kp.public_key).unwrap();

        // Complete enrollment
        let complete_req = EnrollCompleteRequest {
            user_id: "alice".to_string(),
            ciphertext: hex::encode(&resp.ciphertext),
            dilithium_public_key: hex::encode(&resp.dilithium_public_key),
        };
        let complete = server.enroll_complete(&complete_req).unwrap();
        assert!(complete.success);

        // Verify with TOTP
        let ts = now_unix();
        let code = pq_totp::generate(&client_data.totp_seed, ts);
        let verify_req = VerifyRequest {
            user_id: "alice".to_string(),
            method: VerifyMethod::Totp { totp_code: code },
        };
        let result = server.verify(&verify_req).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_duplicate_enrollment_rejected() {
        let server = PqAuthServer::new("test.pqauth.dev");

        // Enroll alice
        let begin = server.enroll_begin("alice").unwrap();
        let client_kp = dilithium::Keypair::generate();
        let challenge = enrollment::EnrollmentChallenge {
            kyber_public_key: hex::decode(&begin.kyber_public_key).unwrap(),
            server_id: begin.server_id,
        };
        let (resp, _) = enrollment::client_enroll(&challenge, &client_kp.public_key).unwrap();
        server
            .enroll_complete(&EnrollCompleteRequest {
                user_id: "alice".to_string(),
                ciphertext: hex::encode(&resp.ciphertext),
                dilithium_public_key: hex::encode(&resp.dilithium_public_key),
            })
            .unwrap();

        // Try to enroll again
        let result = server.enroll_begin("alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_user_challenge() {
        let server = PqAuthServer::new("test.pqauth.dev");
        let result = server.issue_challenge("nobody");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_totp_rejected() {
        let server = PqAuthServer::new("test.pqauth.dev");

        // Quick enroll
        let begin = server.enroll_begin("bob").unwrap();
        let client_kp = dilithium::Keypair::generate();
        let challenge = enrollment::EnrollmentChallenge {
            kyber_public_key: hex::decode(&begin.kyber_public_key).unwrap(),
            server_id: begin.server_id,
        };
        let (resp, _) = enrollment::client_enroll(&challenge, &client_kp.public_key).unwrap();
        server
            .enroll_complete(&EnrollCompleteRequest {
                user_id: "bob".to_string(),
                ciphertext: hex::encode(&resp.ciphertext),
                dilithium_public_key: hex::encode(&resp.dilithium_public_key),
            })
            .unwrap();

        let result = server
            .verify(&VerifyRequest {
                user_id: "bob".to_string(),
                method: VerifyMethod::Totp { totp_code: 0 },
            })
            .unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_audit_log() {
        let server = PqAuthServer::new("test.pqauth.dev");
        let _ = server.enroll_begin("carol");
        let log = server.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "enroll_begin");
        assert!(log[0].success);
    }
}
