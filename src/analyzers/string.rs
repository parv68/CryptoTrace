use crate::error::Result;
use crate::types::DetectionResult;

/// Analyze a string input through the full detection pipeline.
pub fn analyze_string(input: &str) -> Result<DetectionResult> {
    let guard = crate::sanitization::InputGuard::new();
    let sanitized = guard.sanitize_string(input)?;
    super::file::analyze_bytes(&sanitized.raw_bytes, crate::types::SourceType::String)
}
