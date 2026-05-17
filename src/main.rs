#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::fmt::init();

    match crate::cli::run().await {
        Ok(Some(result)) => {
            // Check JSON flag from CLI args
            let json = std::env::args().any(|a| a == "--json");
            cli::print_result(&result, json);
        }
        Ok(None) => {
            // Non-analysis command (version, update, config) — already printed
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

// Import the library crate
use cryptotrace::cli;
