//! # pqauth — Post-Quantum Safe Two-Factor Authentication
//!
//! A research-grade implementation of 2FA using post-quantum cryptographic
//! primitives, designed to be secure against both classical and quantum attacks.
//!
//! ## Core Components
//!
//! - **SHAKE-256 MAC**: Quantum-resistant message authentication code
//! - **PQ-TOTP**: Time-based one-time passwords using SHAKE-256 (replaces HMAC-SHA1)
//! - **CRYSTALS-Dilithium**: Lattice-based digital signatures (NIST PQC standard)
//! - **CRYSTALS-Kyber**: Lattice-based key encapsulation (NIST PQC standard)
//! - **Hybrid Signatures**: Ed25519 + Dilithium3 composite for transition period
//! - **Challenge-Response**: Server-authenticated protocol with replay prevention
//! - **Enrollment**: Kyber-based key exchange for secure 2FA setup
//! - **Key Storage**: Argon2id + AES-256-GCM encrypted key protection
//! - **Recovery Codes**: High-entropy backup codes with SHAKE-256 hashing
//! - **Server**: REST API for enrollment, challenge, and verification

pub mod challenge;
pub mod dilithium;
pub mod enrollment;
pub mod hybrid;
pub mod keystore;
pub mod kyber;
pub mod pq_totp;
pub mod recovery;
pub mod server;
pub mod shake_mac;
