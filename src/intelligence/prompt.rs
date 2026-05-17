/// Prompt builder and response validator. Placeholder for Phase 4.
/// Validates that AI responses do not contain hallucinated algorithm names.
pub fn validate_ai_response(response: &str, known_algorithms: &[&str]) -> Result<(), String> {
    for algo in known_algorithms {
        if response.contains(algo) {
            return Ok(());
        }
    }
    Err("AI response contains no known algorithm references — possible hallucination".to_string())
}
