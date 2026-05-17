/// Isolated worker process for risky parsing operations.
/// This binary is spawned by the main cryptotrace process when parser isolation
/// is enabled (Phase 5+). It reads input from stdin, performs the requested
/// operation, and writes results to stdout.
///
/// Phase 1: stub — accepts input and passes it through unchanged.
use std::io::{self, Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let operation = if args.len() > 2 {
        args[2].clone()
    } else {
        "passthrough".to_string()
    };

    // Read all input from stdin
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).expect("Failed to read stdin");

    // Perform the operation
    let result = match operation.as_str() {
        "passthrough" => input,
        _ => {
            eprintln!("Unknown operation: {}", operation);
            std::process::exit(1);
        }
    };

    // Write result to stdout
    io::stdout().write_all(&result).expect("Failed to write stdout");
    io::stdout().flush().expect("Failed to flush stdout");
}
