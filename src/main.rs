use clap::{Parser, Subcommand};
use pqauth::{dilithium, hybrid, kyber, pq_totp, recovery, server};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "pqauth")]
#[command(about = "Post-quantum safe two-factor authentication")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Dilithium3 keypair
    Keygen {
        /// Generate hybrid Ed25519+Dilithium3 keypair
        #[arg(long)]
        hybrid: bool,
    },
    /// Start the PQ-Auth REST server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "8443")]
        port: u16,
        /// Server identity (domain)
        #[arg(long, default_value = "localhost")]
        server_id: String,
    },
    /// Generate current PQ-TOTP code
    Auth {
        /// Hex-encoded shared secret
        #[arg(long)]
        secret: String,
    },
    /// Verify a PQ-TOTP code
    Verify {
        /// The OTP code to verify
        code: String,
        /// Hex-encoded shared secret
        #[arg(long)]
        secret: String,
        /// Time window tolerance (number of 30s steps)
        #[arg(long, default_value = "1")]
        window: u64,
    },
    /// Show key size comparison (PQ vs classical)
    Info,
    /// Generate recovery codes
    Recovery {
        /// Number of codes to generate
        #[arg(long, default_value = "10")]
        count: usize,
    },
    /// Benchmark PQ operations
    Benchmark {
        /// Number of iterations
        #[arg(long, default_value = "100")]
        iterations: usize,
    },
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { hybrid: use_hybrid } => {
            if use_hybrid {
                let kp = hybrid::HybridKeypair::generate();
                println!("=== Hybrid Ed25519 + Dilithium3 Keypair ===");
                println!(
                    "Ed25519 public key ({} bytes): {}",
                    kp.ed25519_public.len(),
                    hex::encode(&kp.ed25519_public)
                );
                println!(
                    "Dilithium3 public key ({} bytes): {}",
                    kp.dilithium_public.len(),
                    hex::encode(&kp.dilithium_public)
                );
                println!("\nSecurity: Classical (Ed25519) + Quantum (Dilithium3)");
                println!("Hybrid signature size: {} bytes", hybrid::HYBRID_SIG_SIZE);
            } else {
                let kp = dilithium::Keypair::generate();
                println!("=== Dilithium3 Keypair ===");
                println!(
                    "Public key ({} bytes): {}",
                    kp.public_key.len(),
                    hex::encode(&kp.public_key)
                );
                println!(
                    "Secret key ({} bytes): [redacted, {} bytes]",
                    kp.secret_key.len(),
                    kp.secret_key.len()
                );
                println!("\nSecurity level: NIST Level 3 (~128-bit quantum security)");
            }
        }
        Commands::Serve { port, server_id } => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(run_server(port, &server_id));
        }
        Commands::Auth { secret } => {
            let secret_bytes = hex::decode(&secret).expect("invalid hex secret");
            let ts = now_unix();
            let code = pq_totp::generate(&secret_bytes, ts);
            let remaining = pq_totp::seconds_remaining(ts);
            println!("{}", pq_totp::format_code(code));
            println!("Valid for {}s", remaining);
        }
        Commands::Verify {
            code,
            secret,
            window,
        } => {
            let secret_bytes = hex::decode(&secret).expect("invalid hex secret");
            let code_num: u32 = code.parse().expect("code must be numeric");
            let ts = now_unix();
            if pq_totp::verify(&secret_bytes, code_num, ts, window) {
                println!("✓ Valid");
            } else {
                println!("✗ Invalid");
                std::process::exit(1);
            }
        }
        Commands::Info => {
            println!("=== Post-Quantum Key Size Comparison ===\n");
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "Algorithm", "PubKey", "SecKey", "Sig/CT"
            );
            println!("{}", "-".repeat(52));
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "RSA-2048", "256 B", "1.2 KB", "256 B"
            );
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "Ed25519", "32 B", "64 B", "64 B"
            );
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "Dilithium3 (PQ)", "1,952 B", "4,032 B", "3,309 B"
            );
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "Dilithium5 (PQ)", "2,592 B", "4,864 B", "4,595 B"
            );
            println!(
                "{:<20} {:>10} {:>10} {:>10}",
                "Kyber768 (PQ)", "1,184 B", "2,400 B", "1,088 B"
            );
            println!("\nNote: PQ keys are larger but provide quantum resistance.");
            println!("NIST estimates quantum computers capable of breaking RSA/ECC");
            println!("could emerge within 10-20 years. Migrate now.");
        }
        Commands::Recovery { count } => {
            let codes = recovery::generate_codes(count);
            println!("=== Recovery Codes ===");
            println!("Store these in a safe place. Each code can only be used once.\n");
            for (i, code) in codes.iter().enumerate() {
                println!("  {:2}. {}", i + 1, code.code);
            }
            println!("\n⚠  These codes will NOT be shown again.");
            println!("   Each provides ~155 bits of entropy.");
        }
        Commands::Benchmark { iterations } => {
            println!("=== PQ Cryptography Benchmark ({iterations} iterations) ===\n");

            // Dilithium3 keygen
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = dilithium::Keypair::generate();
            }
            let dilithium_keygen = start.elapsed() / iterations as u32;

            // Dilithium3 sign
            let kp = dilithium::Keypair::generate();
            let msg = b"benchmark message for signing operations";
            let start = Instant::now();
            let mut sig = vec![];
            for _ in 0..iterations {
                sig = kp.sign(msg).unwrap();
            }
            let dilithium_sign = start.elapsed() / iterations as u32;

            // Dilithium3 verify
            let start = Instant::now();
            for _ in 0..iterations {
                kp.verify(msg, &sig).unwrap();
            }
            let dilithium_verify = start.elapsed() / iterations as u32;

            // Kyber768 keygen
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = kyber::KyberKeypair::generate();
            }
            let kyber_keygen = start.elapsed() / iterations as u32;

            // Kyber768 encapsulate
            let kyber_kp = kyber::KyberKeypair::generate();
            let start = Instant::now();
            let mut enc = kyber::encapsulate(&kyber_kp.public_key).unwrap();
            for _ in 1..iterations {
                enc = kyber::encapsulate(&kyber_kp.public_key).unwrap();
            }
            let kyber_encaps = start.elapsed() / iterations as u32;

            // Kyber768 decapsulate
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = kyber_kp.decapsulate(&enc.ciphertext).unwrap();
            }
            let kyber_decaps = start.elapsed() / iterations as u32;

            // PQ-TOTP generate
            let secret = b"benchmark-secret-key-32-bytes!!";
            let ts = now_unix();
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = pq_totp::generate(secret, ts);
            }
            let totp_gen = start.elapsed() / iterations as u32;

            println!("{:<25} {:>12}", "Operation", "Avg Time");
            println!("{}", "-".repeat(38));
            println!("{:<25} {:>12?}", "Dilithium3 keygen", dilithium_keygen);
            println!("{:<25} {:>12?}", "Dilithium3 sign", dilithium_sign);
            println!("{:<25} {:>12?}", "Dilithium3 verify", dilithium_verify);
            println!("{:<25} {:>12?}", "Kyber768 keygen", kyber_keygen);
            println!("{:<25} {:>12?}", "Kyber768 encapsulate", kyber_encaps);
            println!("{:<25} {:>12?}", "Kyber768 decapsulate", kyber_decaps);
            println!("{:<25} {:>12?}", "PQ-TOTP generate", totp_gen);
            println!("\nAll operations are fast enough for real-time 2FA.");
        }
    }
}

async fn run_server(port: u16, server_id: &str) {
    use axum::{http::StatusCode, routing::post, Json, Router};

    let state = server::PqAuthServer::new(server_id);

    let app = Router::new()
        .route(
            "/enroll/begin",
            post({
                let s = state.clone();
                move |Json(req): Json<server::EnrollBeginRequest>| async move {
                    match s.enroll_begin(&req.user_id) {
                        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
                        Err(e) => (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/enroll/complete",
            post({
                let s = state.clone();
                move |Json(req): Json<server::EnrollCompleteRequest>| async move {
                    match s.enroll_complete(&req) {
                        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
                        Err(e) => (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/challenge",
            post({
                let s = state.clone();
                move |Json(req): Json<server::ChallengeRequest>| async move {
                    match s.issue_challenge(&req.user_id) {
                        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
                        Err(e) => (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        ),
                    }
                }
            }),
        )
        .route(
            "/verify",
            post({
                let s = state.clone();
                move |Json(req): Json<server::VerifyRequest>| async move {
                    match s.verify(&req) {
                        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())),
                        Err(e) => (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({ "error": e.to_string() })),
                        ),
                    }
                }
            }),
        );

    let addr = format!("0.0.0.0:{port}");
    println!("🔐 PQ-Auth server starting on http://{addr}");
    println!("   Server ID: {server_id}");
    println!("   Endpoints:");
    println!("     POST /enroll/begin    — Start enrollment");
    println!("     POST /enroll/complete — Complete enrollment");
    println!("     POST /challenge       — Get auth challenge");
    println!("     POST /verify          — Verify TOTP or challenge-response");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind failed");
    axum::serve(listener, app).await.expect("server error");
}
