//! Template utilities

use anyhow::Result;

/// Generate a review prompt for AI consumption
pub fn generate_review_prompt(context: &serde_json::Value) -> Result<String> {
    let mut template = String::from(include_str!("../../templates/review.md.tera"));

    // Simple template replacement (for now, could use Tera)
    if let Some(target) = context.get("target") {
        template = template.replace("{{target}}", &target.to_string());
    }

    Ok(template)
}

/// Generate a report filename
pub fn report_filename(target: &str, format: &str) -> String {
    let sanitized = target
        .replace("https://", "")
        .replace("http://", "")
        .replace('/', "-")
        .replace(':', "-");

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");

    format!("warden-report-{}-{}.{}", sanitized, timestamp, format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_filename() {
        let filename = report_filename("https://example.com", "json");
        assert!(filename.contains("example.com"));
        assert!(filename.ends_with(".json"));
    }
}
