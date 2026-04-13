//! Cachee CLI — the world's first post-quantum caching service.
//!
//! Commands:
//!   cachee init          — Initialize config and generate PQ keypair
//!   cachee start         — Start the cache daemon (RESP on port 6380)
//!   cachee stop          — Stop the running daemon
//!   cachee status        — Show daemon status, stats, and hit rate
//!   cachee set/get/del   — Direct cache operations from terminal
//!   cachee ttl KEY       — Check remaining TTL on a key
//!   cachee keys PATTERN  — List keys matching a glob pattern
//!   cachee flush         — Clear all cached entries
//!   cachee dump/restore  — Snapshot and restore cache state
//!   cachee attest        — Enable/disable PQ attestation (Substrate)
//!   cachee auth          — API key management for remote connections
//!   cachee tls           — TLS certificate management
//!   cachee rotate-keys   — Rotate PQ keypair without downtime
//!   cachee plan          — View/upgrade pricing plan
//!   cachee usage         — Real-time usage and billing
//!   cachee bench         — Run built-in throughput/latency benchmark
//!   cachee metrics       — Pretty-printed metrics summary
//!   cachee logs          — Tail daemon logs
//!   cachee info          — System and engine info dump
//!   cachee doctor        — Diagnose common issues
//!   cachee export        — Export stats to JSON
//!   cachee sdk           — Generate client boilerplate
//!   cachee cluster       — Federated D-Cachee operations

use clap::{Parser, Subcommand};

mod config;
mod daemon;
mod resp;
mod bench;
mod attest;
mod plan;
mod security;
mod diagnostics;
mod data;
mod signup;

#[derive(Parser)]
#[command(
    name = "cachee",
    version,
    about = "The world's first post-quantum caching service",
    long_about = "Cachee — high-performance cache with PQ attestation.\nEvery entry carries a 58-byte Substrate receipt signed by 3 independent PQ families.\nCache poisoning is cryptographically impossible."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Account ────────────────────────────────────────
    /// Create a Cachee account
    Signup {
        /// Your email address
        #[arg(long)]
        email: String,
    },
    /// Verify your email with the code you received
    Verify {
        /// Verification code
        #[arg(long)]
        code: String,
        /// Email (auto-detected from pending signup)
        #[arg(long)]
        email: Option<String>,
    },
    /// Show your account info
    Whoami,
    /// Log out and remove credentials
    Logout,

    // ── Setup ─────────────────────────────────────────
    /// Initialize Cachee — create config, generate PQ keypair
    Init {
        /// Port for RESP server
        #[arg(long, default_value = "6380")]
        port: u16,
        /// Maximum cache entries
        #[arg(long, default_value = "1000000")]
        max_keys: usize,
        /// Default TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u32,
    },
    /// Start the Cachee daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
        /// Config file path
        #[arg(long)]
        config: Option<String>,
    },
    /// Stop the running daemon
    Stop,
    /// Show daemon status, stats, hit rate
    Status,

    // ── Cache operations ──────────────────────────────
    /// Store a value
    Set {
        key: String,
        value: String,
        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u32>,
    },
    /// Retrieve a value
    Get {
        key: String,
        /// Show attestation receipt
        #[arg(long)]
        receipt: bool,
    },
    /// Delete a key
    Del {
        key: String,
    },
    /// Check remaining TTL on a key (seconds)
    Ttl {
        key: String,
    },
    /// List keys matching a glob pattern
    Keys {
        /// Glob pattern (e.g. "session:*")
        pattern: String,
        /// Max results to return
        #[arg(long, default_value = "100")]
        limit: usize,
    },
    /// Clear all cached entries
    Flush {
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Snapshot cache state to disk
    Dump {
        /// Output file path
        #[arg(long, default_value = "cachee-dump.bin")]
        output: String,
    },
    /// Restore cache state from snapshot
    Restore {
        /// Input file path
        #[arg(long, default_value = "cachee-dump.bin")]
        input: String,
    },

    // ── PQ attestation ────────────────────────────────
    /// PQ attestation control
    Attest {
        #[command(subcommand)]
        action: AttestAction,
    },

    // ── Security ──────────────────────────────────────
    /// API key management for remote connections
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// TLS certificate management
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
    /// Rotate PQ keypair without downtime
    RotateKeys,

    // ── Billing ───────────────────────────────────────
    /// View or upgrade pricing plan
    Plan {
        #[command(subcommand)]
        action: PlanAction,
    },
    /// Real-time usage, credits, and projected billing
    Usage,

    // ── Observability ─────────────────────────────────
    /// Run built-in benchmark
    Bench {
        /// Duration in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Number of concurrent workers
        #[arg(long, default_value = "8")]
        workers: usize,
    },
    /// Pretty-printed metrics summary
    Metrics,
    /// Tail daemon logs
    Logs {
        /// Number of lines to show
        #[arg(long, default_value = "50")]
        lines: usize,
        /// Follow (stream new lines)
        #[arg(long, short)]
        follow: bool,
    },
    /// Export stats to JSON
    Export {
        /// Output file (stdout if omitted)
        #[arg(long)]
        output: Option<String>,
    },

    // ── Diagnostics ───────────────────────────────────
    /// System and engine info
    Info,
    /// Diagnose common issues
    Doctor,

    // ── SDK ───────────────────────────────────────────
    /// Generate client boilerplate for your language
    Sdk {
        #[command(subcommand)]
        action: SdkAction,
    },

    // ── Federation ────────────────────────────────────
    /// D-Cachee federation
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
}

#[derive(Subcommand)]
enum AttestAction {
    /// Enable PQ attestation on all SET operations
    Enable,
    /// Disable PQ attestation
    Disable,
    /// Show attestation status and key info
    Status,
}

#[derive(Subcommand)]
enum AuthAction {
    /// Generate a new API key
    Create {
        /// Human-readable label
        #[arg(long)]
        label: String,
        /// Permissions: read, write, admin
        #[arg(long, default_value = "read,write")]
        permissions: String,
    },
    /// List all API keys
    List,
    /// Revoke an API key
    Revoke {
        /// Key ID to revoke
        key_id: String,
    },
}

#[derive(Subcommand)]
enum TlsAction {
    /// Enable TLS with auto-generated self-signed cert
    Enable,
    /// Import existing certificate and key
    Import {
        /// Path to PEM certificate
        #[arg(long)]
        cert: String,
        /// Path to PEM private key
        #[arg(long)]
        key: String,
    },
    /// Disable TLS
    Disable,
    /// Show TLS status
    Status,
}

#[derive(Subcommand)]
enum PlanAction {
    /// Show current plan details
    Show,
    /// Upgrade to a paid plan
    Upgrade {
        /// Plan tier: starter, professional, enterprise
        tier: String,
    },
    /// Show all available plans and pricing
    List,
}

#[derive(Subcommand)]
enum SdkAction {
    /// Generate client boilerplate
    Init {
        /// Language: rust, python, node, go
        #[arg(long)]
        lang: String,
        /// Output directory
        #[arg(long, default_value = ".")]
        output: String,
    },
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Join a D-Cachee federation
    Join {
        /// Comma-separated peer addresses
        #[arg(long)]
        peers: String,
    },
    /// Leave the federation
    Leave,
    /// Show cluster status
    Status,
    /// List all nodes in the federation
    Nodes,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cachee=info".parse().unwrap())
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        // Account
        Commands::Signup { email } => signup::signup(&email).await?,
        Commands::Verify { code, email } => signup::verify(email.as_deref(), &code).await?,
        Commands::Whoami => signup::whoami().await?,
        Commands::Logout => signup::logout().await?,

        // Lifecycle
        Commands::Init { port, max_keys, ttl } => config::init(port, max_keys, ttl).await?,
        Commands::Start { foreground, config: config_path } => daemon::start(foreground, config_path).await?,
        Commands::Stop => daemon::stop().await?,
        Commands::Status => daemon::status().await?,

        // Cache operations
        Commands::Set { key, value, ttl } => resp::set(&key, &value, ttl).await?,
        Commands::Get { key, receipt } => resp::get(&key, receipt).await?,
        Commands::Del { key } => resp::del(&key).await?,
        Commands::Ttl { key } => resp::ttl(&key).await?,
        Commands::Keys { pattern, limit } => resp::keys(&pattern, limit).await?,
        Commands::Flush { yes } => data::flush(yes).await?,
        Commands::Dump { output } => data::dump(&output).await?,
        Commands::Restore { input } => data::restore(&input).await?,

        // Attestation
        Commands::Attest { action } => match action {
            AttestAction::Enable => attest::enable().await?,
            AttestAction::Disable => attest::disable().await?,
            AttestAction::Status => attest::status().await?,
        },

        // Security
        Commands::Auth { action } => match action {
            AuthAction::Create { label, permissions } => security::auth_create(&label, &permissions).await?,
            AuthAction::List => security::auth_list().await?,
            AuthAction::Revoke { key_id } => security::auth_revoke(&key_id).await?,
        },
        Commands::Tls { action } => match action {
            TlsAction::Enable => security::tls_enable().await?,
            TlsAction::Import { cert, key } => security::tls_import(&cert, &key).await?,
            TlsAction::Disable => security::tls_disable().await?,
            TlsAction::Status => security::tls_status().await?,
        },
        Commands::RotateKeys => security::rotate_keys().await?,

        // Billing
        Commands::Plan { action } => match action {
            PlanAction::Show => plan::show().await?,
            PlanAction::Upgrade { tier } => plan::upgrade(&tier).await?,
            PlanAction::List => plan::list().await?,
        },
        Commands::Usage => plan::usage().await?,

        // Observability
        Commands::Bench { duration, workers } => bench::run(duration, workers).await?,
        Commands::Metrics => diagnostics::metrics().await?,
        Commands::Logs { lines, follow } => diagnostics::logs(lines, follow).await?,
        Commands::Export { output } => diagnostics::export(output).await?,

        // Diagnostics
        Commands::Info => diagnostics::info().await?,
        Commands::Doctor => diagnostics::doctor().await?,

        // SDK
        Commands::Sdk { action } => match action {
            SdkAction::Init { lang, output } => diagnostics::sdk_init(&lang, &output).await?,
        },

        // Federation
        Commands::Cluster { action } => match action {
            ClusterAction::Join { peers } => {
                println!("Joining D-Cachee federation: {peers}");
                println!("(federation support coming in v0.2)");
            }
            ClusterAction::Leave => println!("Left D-Cachee federation"),
            ClusterAction::Status => println!("Not connected to any federation"),
            ClusterAction::Nodes => println!("No nodes discovered"),
        },
    }

    Ok(())
}
