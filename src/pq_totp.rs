//! Post-Quantum TOTP (Time-based One-Time Password).
//!
//! Replaces classical TOTP (RFC 6238, HMAC-SHA1) with SHAKE-256 MAC.
//! - 30-second time windows (standard UX)
//! - 8-digit codes (more entropy than standard 6-digit: 10^8 vs 10^6)
//! - Quantum-resistant: SHAKE-256 is based on Keccak sponge (NIST SHA-3)
//!
//! Algorithm:
//!   1. T = floor(unix_timestamp / 30)
//!   2. msg = T.to_be_bytes()
//!   3. mac = SHAKE256_MAC(secret, msg)
//!   4. offset = mac[last_byte] & 0x0F
//!   5. code = u32_from_be(mac[offset..offset+4]) & 0x7FFFFFFF
//!   6. otp = code % 10^8

use crate::shake_mac;

/// Time step in seconds (30s, same as standard TOTP).
pub const TIME_STEP: u64 = 30;

/// Number of digits in the OTP code.
pub const CODE_DIGITS: u32 = 8;

/// Modulus for truncation (10^8).
const MODULUS: u32 = 100_000_000;

/// Generate a PQ-TOTP code for the given secret and Unix timestamp.
pub fn generate(secret: &[u8], timestamp: u64) -> u32 {
    generate_at_step(secret, timestamp / TIME_STEP)
}

/// Generate a PQ-TOTP code for a specific time step counter.
pub fn generate_at_step(secret: &[u8], counter: u64) -> u32 {
    let msg = counter.to_be_bytes();
    let mac = shake_mac::shake256_mac(secret, &msg, 32);

    // Dynamic truncation (same approach as RFC 4226 / 6238)
    let offset = (mac[mac.len() - 1] & 0x0F) as usize;
    let code = u32::from_be_bytes([
        mac[offset] & 0x7F,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);

    code % MODULUS
}

/// Verify a PQ-TOTP code with a time window tolerance.
///
/// `window` specifies how many time steps before/after to accept (default: 1).
/// This accounts for clock drift between client and server.
pub fn verify(secret: &[u8], code: u32, timestamp: u64, window: u64) -> bool {
    let current_step = timestamp / TIME_STEP;
    let start = current_step.saturating_sub(window);
    let end = current_step + window;

    let candidate = code.to_be_bytes();
    for step in start..=end {
        // Constant-time comparison so verification timing does not leak
        // how many leading bytes of the expected code matched.
        if shake_mac::verify_mac(&candidate, &generate_at_step(secret, step).to_be_bytes()) {
            return true;
        }
    }
    false
}

/// Format an OTP code as a zero-padded string.
pub fn format_code(code: u32) -> String {
    format!("{:08}", code)
}

/// Get the current time step counter.
pub fn current_step(timestamp: u64) -> u64 {
    timestamp / TIME_STEP
}

/// Seconds remaining in the current time window.
pub fn seconds_remaining(timestamp: u64) -> u64 {
    TIME_STEP - (timestamp % TIME_STEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"12345678901234567890123456789012"; // 32 bytes

    #[test]
    fn test_generate_deterministic() {
        let code1 = generate(TEST_SECRET, 1000000);
        let code2 = generate(TEST_SECRET, 1000000);
        assert_eq!(code1, code2);
    }

    #[test]
    fn test_same_window_same_code() {
        // Timestamps in the same 30s window should produce the same code
        let code1 = generate(TEST_SECRET, 1000000);
        let code2 = generate(TEST_SECRET, 1000010); // +10s, same window
        assert_eq!(code1, code2);
    }

    #[test]
    fn test_different_window_different_code() {
        let code1 = generate(TEST_SECRET, 1000000);
        let code2 = generate(TEST_SECRET, 1000030); // next window
                                                    // Could theoretically collide but astronomically unlikely
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_code_range() {
        // Code must be < 10^8
        for ts in (0..100).map(|i| i * 30) {
            let code = generate(TEST_SECRET, ts);
            assert!(code < MODULUS, "Code {} exceeds modulus", code);
        }
    }

    #[test]
    fn test_verify_current() {
        let ts = 1000000u64;
        let code = generate(TEST_SECRET, ts);
        assert!(verify(TEST_SECRET, code, ts, 1));
    }

    #[test]
    fn test_verify_within_window() {
        let ts = 1000000u64;
        let code = generate(TEST_SECRET, ts);
        // Should verify within ±1 step window
        assert!(verify(TEST_SECRET, code, ts + 30, 1)); // next step
        assert!(verify(TEST_SECRET, code, ts - 30, 1)); // prev step (if same window math)
    }

    #[test]
    fn test_verify_outside_window() {
        let ts = 1000000u64;
        let code = generate(TEST_SECRET, ts);
        // Should NOT verify 3 steps away with window=1
        assert!(!verify(TEST_SECRET, code, ts + 90, 1));
    }

    #[test]
    fn test_format_code() {
        assert_eq!(format_code(1234), "00001234");
        assert_eq!(format_code(12345678), "12345678");
        assert_eq!(format_code(0), "00000000");
    }

    #[test]
    fn test_seconds_remaining() {
        assert_eq!(seconds_remaining(0), 30);
        assert_eq!(seconds_remaining(1), 29);
        assert_eq!(seconds_remaining(29), 1);
        assert_eq!(seconds_remaining(30), 30);
    }

    #[test]
    fn test_different_secrets() {
        let code1 = generate(b"secret-one-32-bytes-long-aaaaaa", 1000000);
        let code2 = generate(b"secret-two-32-bytes-long-bbbbbb", 1000000);
        assert_ne!(code1, code2);
    }
}
