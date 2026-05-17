use crate::types::DetectionResult;

/// Serialize a DetectionResult to pretty-printed JSON.
pub fn format_json(result: &DetectionResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

/// Serialize a DetectionResult to compact JSON (one line).
pub fn format_json_compact(result: &DetectionResult) -> String {
    serde_json::to_string(result).unwrap_or_else(|_| "{}".to_string())
}
