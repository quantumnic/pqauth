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
//! - **Challenge-Response**: Server-authenticated protocol with replay prevention

pub mod challenge;
pub mod dilithium;
pub mod pq_totp;
pub mod shake_mac;
