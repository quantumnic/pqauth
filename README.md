# pqauth — Post-Quantum Safe Two-Factor Authentication

[![CI](https://github.com/redbasecap-buiss/pqauth/actions/workflows/ci.yml/badge.svg)](https://github.com/redbasecap-buiss/pqauth/actions)

A research-grade post-quantum 2FA system built in pure Rust. Designed to remain secure against both classical and quantum adversaries.

## Why Post-Quantum 2FA?

Classical TOTP (RFC 6238) relies on HMAC-SHA1 — while SHA-1 itself isn't directly broken by quantum computers, the broader authentication ecosystem (key exchange, signatures) is vulnerable to Shor's algorithm. **pqauth** replaces the entire authentication stack with quantum-resistant primitives:

| Component | Classical | pqauth (Post-Quantum) |
|---|---|---|
| MAC for TOTP | HMAC-SHA1 | SHAKE-256 envelope MAC |
| Signatures | Ed25519 / RSA | CRYSTALS-Dilithium3 (NIST FIPS 204) |
| Code length | 6 digits | 8 digits (100× more entropy) |
| Challenge-response | N/A | Dilithium-signed challenges with replay prevention |

## Protocol Overview

### PQ-TOTP (Time-Based Tokens)

```
T = floor(unix_time / 30)
mac = SHAKE256(secret ‖ T.to_be_bytes() ‖ secret)
offset = mac[31] & 0x0F
code = u32_be(mac[offset..offset+4]) & 0x7FFFFFFF mod 10^8
```

Compatible with standard 30-second windows. 8-digit codes provide ~26.6 bits of entropy per token (vs ~19.9 for 6-digit).

### Challenge-Response Authentication

1. **Server** generates 32-byte random nonce
2. **Client** signs `nonce ‖ timestamp` with Dilithium3 private key
3. **Server** verifies signature, checks timestamp window, prevents replay

### Key Sizes (NIST Level 3)

| | Public Key | Secret Key | Signature |
|---|---|---|---|
| Ed25519 | 32 B | 64 B | 64 B |
| **Dilithium3** | **1,952 B** | **4,032 B** | **3,309 B** |

The size increase is the cost of quantum resistance. Still practical for most applications.

## Usage

```bash
# Generate a Dilithium3 keypair
pqauth keygen

# Generate current PQ-TOTP code
pqauth auth --secret <hex-encoded-secret>

# Verify a code
pqauth verify <code> --secret <hex-encoded-secret>

# Show algorithm comparison
pqauth info
```

## Architecture

```
src/
├── lib.rs          # Library root
├── shake_mac.rs    # SHAKE-256 envelope MAC
├── pq_totp.rs      # Post-quantum TOTP (8-digit, 30s windows)
├── dilithium.rs    # CRYSTALS-Dilithium3 signature wrapper
├── challenge.rs    # Challenge-response protocol with replay prevention
└── main.rs         # CLI interface
```

## Security Considerations

- **SHAKE-256 MAC**: Based on Keccak sponge construction. Envelope MAC (K‖M‖K) prevents length-extension. Quantum security: ~128 bits (Grover's reduces to √ but SHAKE-256 with 256-bit output retains 128-bit quantum security).
- **Dilithium3**: Lattice-based (Module-LWE). NIST Security Level 3. Believed resistant to all known quantum attacks.
- **Replay prevention**: Server tracks used nonces. Challenges expire after 5 minutes.
- **Constant-time verification**: MAC comparison uses constant-time XOR to prevent timing attacks.

⚠️ **This is research-grade software. Do not use in production without independent cryptographic review.**

## License

MIT
