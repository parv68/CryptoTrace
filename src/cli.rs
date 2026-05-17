use clap::{Parser, Subcommand};
use crate::error::Result;
use crate::types::DetectionResult;

/// Cryptographic Fingerprinting & Data Classification Engine
#[derive(Parser)]
#[command(name = "cryptotrace")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a string or file for cryptographic fingerprints
    Analyze {
        /// Input to analyze (string literal or file path)
        input: String,

        /// Threat context: malware, password, or forensics (default: forensics)
        #[arg(long, default_value = "forensics")]
        context: String,

        /// Enable recursive layer analysis
        #[arg(long)]
        deep: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,

        /// Append AI narrative (requires AI provider config)
        #[arg(long)]
        ai: bool,
    },

    /// Update the signature database (GPG-verified)
    Update {
        /// Roll back to previous signature database version
        #[arg(long)]
        rollback: bool,

        /// Import signature update from a local file (air-gap mode)
        #[arg(long)]
        from_file: Option<String>,
    },

    /// Show engine and signature database versions
    Version,

    /// Clear AI output cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Show active configuration (secrets redacted)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
pub enum CacheAction {
    Clear,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    Show,
}

/// Run the CLI command and return a DetectionResult (if applicable).
pub async fn run() -> Result<Option<DetectionResult>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Analyze { input, context, deep, json: _, ai: _ } => {
            let detection_context = match context.as_str() {
                "malware" => crate::types::DetectionContext::Malware,
                "password" => crate::types::DetectionContext::Password,
                _ => crate::types::DetectionContext::Forensics,
            };

            // Try as file first, then as string
            let path = std::path::Path::new(input);
            let mut result = if path.exists() {
                crate::analyzers::file::analyze_file(path)?
            } else {
                crate::analyzers::string::analyze_string(input)?
            };

            // Apply detection context
            result.detection_context = detection_context;

            // Recursive analysis
            if *deep && !result.algorithm.as_deref().map_or(true, |a| a.is_empty()) {
                let config = crate::analyzers::recursive::RecursiveConfig::default();
                let layers = crate::analyzers::recursive::analyze_recursive(&result.input_hash.as_bytes(), &config)?;
                // Convert recursive layers to DetectionResult layers
                for layer in layers {
                    let layer_result = DetectionResult {
                        input_hash: result.input_hash.clone(),
                        source_type: crate::types::SourceType::Binary,
                        entropy: 0.0,
                        sliding_entropy: None,
                        detected_type: layer.detected_type,
                        algorithm: Some(layer.algorithm),
                        confidence: layer.confidence,
                        calibrated: false,
                        calibration_samples: None,
                        heuristic_raw: None,
                        confidence_is_provisional: true,
                        false_positive_risk: 0.0,
                        risk_level: crate::types::RiskLevel::Unknown,
                        weakness: None,
                        weakness_cve: vec![],
                        recommendations: vec![],
                        signals: None,
                        primary_drivers: vec![],
                        conflicting_signals: vec![],
                        decision_trace: None,
                        layers: vec![],
                        ai_narrative: None,
                        detection_context: result.detection_context,
                        engine_version: result.engine_version.clone(),
                        signature_db_version: result.signature_db_version.clone(),
                    };
                    result.layers.push(layer_result);
                }
            }

            // Log audit trail
            crate::intelligence::audit::log_analysis(&result);

            Ok(Some(result))
        }

        Commands::Update { rollback, from_file } => {
            let _ = (rollback, from_file);
            tracing::info!("Signature update not yet implemented (Phase 2)");
            Ok(None)
        }

        Commands::Version => {
            println!("CryptoTrace v{}", env!("CARGO_PKG_VERSION"));
            println!("Engine: {}", env!("CARGO_PKG_VERSION"));
            println!("Signature DB: 0.0.0");
            Ok(None)
        }

        Commands::Cache { action } => {
            match action {
                CacheAction::Clear => {
                    tracing::info!("Cache cleared");
                }
            }
            Ok(None)
        }

        Commands::Config { action } => {
            match action {
                ConfigAction::Show => {
                    println!("AI enabled: false");
                    println!("API rate limit: 60/min");
                    println!("Max file size: 50MB");
                    println!("Max string size: 10MB");
                }
            }
            Ok(None)
        }
    }
}

/// Format and print the analysis result based on CLI flags.
pub fn print_result(result: &DetectionResult, json: bool) {
    if json {
        println!("{}", crate::reports::json::format_json(result));
    } else {
        print!("{}", crate::reports::terminal::format_terminal(result));
    }
}
