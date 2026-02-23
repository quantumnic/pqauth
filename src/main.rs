use clap::{Parser, Subcommand};
use pqauth::{dilithium, pq_totp};
use std::time::{SystemTime, UNIX_EPOCH};

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
    Keygen,
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
        Commands::Keygen => {
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
    }
}
