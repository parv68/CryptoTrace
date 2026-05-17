use crate::core::encoding::EncodingDetection;
use crate::core::hashing::HashDetection;
use crate::types::{DetectionResult, RiskLevel, SignalBreakdown, SlidingEntropy, SourceType};

/// Simple confidence calculation: weighted combination of detection signals.
/// This is the **Phase 1 provisional** engine. Phase 3 will replace this with
/// empirically validated multi-signal weighting + Platt scaling calibration.
pub fn compute_confidence(
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
    _sliding: Option<&SlidingEntropy>,
) -> f64 {
    let signal_strength = hash_detection
        .map(|h| h.confidence)
        .or_else(|| encoding_detection.map(|e| e.confidence))
        .unwrap_or(0.0);

    // Entropy consistency: how well does the entropy match the detection type?
    let entropy_consistency = if hash_detection.is_some() {
        // Hashes typically have low entropy (< 4.0)
        if entropy < 4.0 { 0.9 } else { 0.3 }
    } else if encoding_detection.is_some() {
        // Encodings vary — base64 is ~6.0, hex is ~4.0
        if entropy > 3.0 && entropy < 7.0 { 0.8 } else { 0.4 }
    } else {
        0.5
    };

    signal_strength * 0.5 + entropy_consistency * 0.3 + 0.2 // length_match placeholder
}

/// Build a provisional DetectionResult for Phase 1.
#[allow(unused_variables)]
pub fn build_detection_result(
    input: &[u8],
    source_type: SourceType,
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
    sliding: Option<&SlidingEntropy>,
) -> DetectionResult {
    let input_hash = crate::core::hashing::sha256_hex(input);
    let confidence = compute_confidence(
        hash_detection,
        encoding_detection,
        entropy,
        sliding,
    );

    let (detected_type, algorithm, weakness, risk_level, recommendations) = if let Some(h) = hash_detection {
        (
            "hash".to_string(),
            Some(h.algorithm.clone()),
            Some(h.weakness_flags.join(", ")),
            h.risk_level.clone(),
            match h.algorithm.as_str() {
                "MD5" => vec!["Replace with bcrypt (cost ≥ 12) or Argon2id.".to_string()],
                "SHA1" => vec!["Upgrade to SHA256 or stronger.".to_string()],
                "NTLM" => vec!["Replace with bcrypt or Argon2id.".to_string()],
                _ => vec![],
            },
        )
    } else if let Some(e) = encoding_detection {
        (
            "encoding".to_string(),
            Some(e.encoding_type.clone()),
            None,
            RiskLevel::Low,
            vec![],
        )
    } else {
        let entropy_class = crate::core::entropy::classify_entropy(entropy, 3.5, 6.0, 7.5);
        (
            if entropy > 7.5 {
                "high_entropy".to_string()
            } else {
                "plaintext".to_string()
            },
            None,
            None,
            RiskLevel::Unknown,
            vec![],
        )
    };

    // Build signal breakdown
    let signals = SignalBreakdown {
        entropy,
        byte_distribution: None,
        block_alignment: 0.0,
        magic_bytes: 0.0,
        length_pattern: if algorithm.is_some() { 1.0 } else { 0.0 },
        charset_purity: encoding_detection.map(|_| 1.0),
        window_variance: sliding.map(|s| s.entropy_variance),
    };

    DetectionResult {
        input_hash,
        source_type,
        entropy,
        sliding_entropy: sliding.cloned(),
        detected_type,
        algorithm,
        confidence: confidence.min(1.0),
        calibrated: false,
        calibration_samples: None,
        heuristic_raw: Some(confidence),
        confidence_is_provisional: true,
        false_positive_risk: 0.0,
        risk_level,
        weakness,
        weakness_cve: vec![],
        recommendations,
        signals: Some(signals),
        primary_drivers: vec![],
        conflicting_signals: vec![],
        decision_trace: None,
        layers: vec![],
        ai_narrative: None,
        detection_context: crate::types::DetectionContext::Forensics,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        signature_db_version: "0.0.0".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_bounds() {
        let result = compute_confidence(None, None, 5.0, None);
        assert!(result >= 0.0 && result <= 1.0);
    }
}
