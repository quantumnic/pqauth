# Security Model — pqauth

## Threat Model

### Adversary Capabilities
- **Classical attacker**: Unlimited classical compute. Can perform all known polynomial-time attacks.
- **Quantum attacker**: Access to a cryptographically-relevant quantum computer (CRQC) capable of running Shor's algorithm against RSA/ECC key sizes in use today.
- **Network attacker**: Can observe, replay, modify, and inject messages on any network path.
- **Compromised server**: Attacker gains read access to server database (but not runtime memory).

### What We Protect Against
| Threat | Mitigation |
|---|---|
| Quantum key recovery (Shor) | Dilithium3 + Kyber768 (lattice-based, no known quantum speedup beyond Grover) |
| TOTP seed extraction from network capture | Kyber KEM enrollment — shared secret never traverses the wire |
| Replay attacks | Challenge nonces tracked server-side; each nonce single-use |
| Brute-force TOTP | 8-digit codes (10^8 space) + rate limiting (5 attempts / 5 min) |
| Timing side-channels on MAC verification | Constant-time comparison in `shake_mac::verify_mac` |
| Key extraction from storage | Argon2id (memory-hard KDF) + AES-256-GCM encryption at rest |
| Classical signature forgery during PQ transition | Hybrid mode: Ed25519 ∧ Dilithium3 (both must verify) |

### What We Do NOT Protect Against
- **Side-channel attacks on PQ primitives**: We use the `pqcrypto` crate which wraps reference C implementations. These are not hardened against power analysis, cache timing, etc.
- **Compromised client device**: If the attacker has the client's secret key material in memory, authentication is broken regardless of algorithm.
- **Implementation bugs**: This is research-grade software, not audited for production use.

## NIST Security Levels

| Algorithm | NIST Level | Quantum Security | Classical Equivalent |
|---|---|---|---|
| Dilithium3 (ML-DSA-65) | Level 3 | ~128-bit | ~AES-192 |
| Kyber768 (ML-KEM-768) | Level 3 | ~128-bit | ~AES-192 |
| SHAKE-256 MAC | Level 3+ | ~128-bit (Grover halves) | ~AES-256 pre-quantum |
| Ed25519 (hybrid only) | Level 1 classical | **0 against CRQC** | ~128-bit classical |
| Hybrid (Ed25519+Dilithium3) | Level 3 | ~128-bit | Best of both |

## Key Sizes

| Algorithm | Public Key | Secret Key | Signature / Ciphertext |
|---|---|---|---|
| RSA-2048 | 256 B | ~1.2 KB | 256 B |
| Ed25519 | 32 B | 64 B | 64 B |
| Dilithium3 | 1,952 B | 4,032 B | 3,309 B |
| Kyber768 | 1,184 B | 2,400 B | 1,088 B |
| Hybrid (Ed25519+Dil3) | 1,984 B | 4,096 B | 3,373 B |

## Protocol Security Properties

### Enrollment (Kyber KEM)
- **Forward secrecy**: Each enrollment uses an ephemeral Kyber keypair. Even if the server's long-term keys are later compromised, past enrollment secrets remain safe.
- **IND-CCA2 security**: Kyber768 is IND-CCA2 secure under the Module-LWE assumption.

### Authentication (Dilithium Signatures)
- **EUF-CMA security**: Dilithium3 is existentially unforgeable under chosen-message attack under the Module-LWE and Module-SIS assumptions.
- **Non-repudiation**: Signed challenges provide proof of authentication.

### PQ-TOTP (SHAKE-256)
- **PRF security**: SHAKE-256 in envelope MAC mode (K||M||K) provides PRF security under the sponge indifferentiability framework.
- **Grover resistance**: 256-bit SHAKE output provides ~128-bit security against Grover's quantum search.

## Recommendations

1. **Use hybrid mode during transition**: Until confidence in lattice assumptions matures, hybrid Ed25519+Dilithium3 provides defense-in-depth.
2. **Rotate keys periodically**: Even PQ keys should be rotated (yearly recommended).
3. **Do not use in production**: This is research software. Use for learning, prototyping, and experimentation only.
4. **Monitor NIST PQC updates**: The standards (FIPS 203/204) may receive parameter updates.

## References

- [FIPS 203 (ML-KEM / Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 (ML-DSA / Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [SHA-3 / SHAKE (FIPS 202)](https://csrc.nist.gov/pubs/fips/202/final)
