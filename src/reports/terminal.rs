use crate::types::DetectionResult;

/// Format a DetectionResult as a human-readable terminal report.
pub fn format_terminal(result: &DetectionResult) -> String {
    let mut output = String::new();
    output.push_str("═══════════════════════════════════════\n");
    output.push_str(" CryptoTrace Analysis Report\n");
    output.push_str("═══════════════════════════════════════\n\n");

    output.push_str(&format!(" Input:      {}\n", &result.input_hash[..32.min(result.input_hash.len())]));
    output.push_str(&format!(" Entropy:    {:.2} / 8.00", result.entropy));

    // Add sliding window info if available
    if let Some(ref sliding) = result.sliding_entropy {
        if !sliding.window_scores.is_empty() {
            output.push_str(&format!("  [max local: {:.2}]", sliding.max_window_entropy));
        }
    }
    output.push('\n');

    output.push_str(&format!(" Risk Level: {:?}\n", result.risk_level));
    output.push_str(&format!(" Source:     {:?}\n", result.source_type));

    output.push('\n');
    output.push_str(&format!(" Detection:  {}\n", result.algorithm.as_deref().unwrap_or("Unknown")));
    output.push_str(&format!(" Type:       {}\n", result.detected_type));
    output.push_str(&format!(" Confidence: {:.0}%", result.confidence * 100.0));
    if result.confidence_is_provisional {
        output.push_str(" (provisional — Phase 1 engine)");
    }
    if result.calibrated {
        output.push_str(" [calibrated]");
    }
    output.push('\n');

    // Signal breakdown
    if let Some(ref signals) = result.signals {
        output.push_str("\n Signals:\n");
        output.push_str(&format!("   entropy            {:.2}\n", signals.entropy));
        if let Some(bd) = signals.byte_distribution {
            output.push_str(&format!("   byte_distribution  {:.2}\n", bd));
        }
        output.push_str(&format!("   block_alignment    {:.2}\n", signals.block_alignment));
        output.push_str(&format!("   magic_bytes        {:.2}\n", signals.magic_bytes));
        output.push_str(&format!("   length_pattern     {:.2}\n", signals.length_pattern));
        if let Some(cp) = signals.charset_purity {
            output.push_str(&format!("   charset_purity     {:.2}\n", cp));
        }
        if let Some(wv) = signals.window_variance {
            output.push_str(&format!("   window_variance    {:.2}\n", wv));
        }
    }

    if let Some(ref weakness) = result.weakness {
        output.push_str(&format!("\n Weakness:   {}\n", weakness));
    }

    if !result.recommendations.is_empty() {
        output.push_str("\n Recommendation:\n");
        for rec in &result.recommendations {
            output.push_str(&format!("   {}\n", rec));
        }
    }

    // Layer tree
    if !result.layers.is_empty() {
        output.push_str("\n Layer Tree:\n");
        for detection in &result.layers {
            let layer = crate::types::Layer {
                depth: 0,
                detected_type: detection.detected_type.clone(),
                algorithm: detection.algorithm.clone().unwrap_or_default(),
                confidence: detection.confidence,
                decoded_preview: None,
                decoded_length: 0,
                expansion_ratio: None,
                children: vec![],
            };
            format_layer_tree(&mut output, &layer, 1);
        }
    }

    // AI narrative
    if let Some(ref ai) = result.ai_narrative {
        output.push_str("\n AI Narrative:\n");
        output.push_str(&format!("   {}\n", ai.summary));
        output.push_str(&format!("   Risk: {}\n", ai.risk_reason));
        output.push_str(&format!("   Action: {}\n", ai.recommended_action));
    }

    output.push_str("\n═══════════════════════════════════════\n");

    output
}

fn format_layer_tree(output: &mut String, layer: &crate::types::Layer, indent: usize) {
    let prefix = "  ".repeat(indent);
    output.push_str(&format!(
        "{}├─ [{}] {} ({:.0}% confidence)\n",
        prefix, layer.depth, layer.algorithm, layer.confidence * 100.0
    ));
    if let Some(ratio) = layer.expansion_ratio {
        output.push_str(&format!("{}│  expansion: {:.1}:1\n", prefix, ratio));
    }
    for child in &layer.children {
        format_layer_tree(output, child, indent + 1);
    }
}
