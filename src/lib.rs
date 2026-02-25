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
//! - **Challenge-Response**: Server-authenticated protocol with replay prevention
//! - **Key Storage**: Argon2id + AES-256-GCM encrypted key protection
//! - **Recovery Codes**: High-entropy backup codes with SHAKE-256 hashing

pub mod challenge;
pub mod dilithium;
pub mod keystore;
pub mod kyber;
pub mod pq_totp;
pub mod recovery;
pub mod shake_mac;
