use crate::types::DetectionResult;
use std::time::{SystemTime, UNIX_EPOCH};

/// Log analysis events for audit trail.
/// In Phase 1 this is a simple log; in production it writes structured JSON logs.
pub fn log_analysis(result: &DetectionResult) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    tracing::info!(
        input_hash = %result.input_hash,
        detected_type = %result.detected_type,
        algorithm = ?result.algorithm,
        confidence = result.confidence,
        risk_level = ?result.risk_level,
        timestamp = timestamp,
        "Analysis complete"
    );
}
