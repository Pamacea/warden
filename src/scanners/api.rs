//! API Security Scanner - REST, GraphQL, and WebSocket testing

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

pub struct ApiScanner {
    client: Client,
    config: ScannerConfig,
}

impl ApiScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client for API scanning");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // GraphQL introspection check
        report.merge(self.check_graphql_introspection(url).await?);

        // REST API parameter tampering
        report.merge(self.check_rest_parameter_tampering(url).await?);

        // Mass assignment detection
        report.merge(self.check_mass_assignment(url).await?);

        // API versioning issues
        report.merge(self.check_api_versioning(url).await?);

        // WebSocket security (if WebSocket endpoint detected)
        if self.config.aggressive {
            report.merge(self.check_websocket_security(url).await?);
        }

        Ok(report)
    }

    /// GraphQL Introspection detection
    async fn check_graphql_introspection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Common GraphQL endpoints
        let graphql_paths = vec![
            "/graphql",
            "/api/graphql",
            "/graphiql",
            "/api",
            "/v1/graphql",
            "/v2/graphql",
        ];

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Try each GraphQL path
        for path in graphql_paths {
            let graphql_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);

            // Introspection query to detect GraphQL
            let introspection_query = r#"{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name}directives{name}}"}}"#;

            match self
                .client
                .post(&graphql_url)
                .header("Content-Type", "application/json")
                .body(introspection_query)
                .send()
                .await
            {
                Ok(response) => {
                    let _status = response.status();
                    let text = response.text().await.unwrap_or_default();

                    // Check for GraphQL response patterns
                    if text.contains("__schema")
                        || text.contains("__type")
                        || text.contains("queryType")
                        || text.contains("IntrospectionQuery")
                    {
                        // Check if introspection is enabled
                        if text.contains("\"name\":") && text.len() > 100 {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "GraphQL Introspection Enabled".to_string(),
                                description: format!(
                                    "GraphQL endpoint at {} has introspection enabled, exposing the full schema.",
                                    path
                                ),
                                location: Some(graphql_url.clone()),
                                recommendation: Some("Disable introspection in production. Use 'disable_introspection' or restrict access.".to_string()),
                                cwe: Some("CWE-215".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });

                            // Check for depth limiting
                            if !text.contains("maxDepth") && !text.contains("depthLimit") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Medium,
                                    title: "GraphQL Depth Limit Not Configured".to_string(),
                                    description: "GraphQL endpoint lacks depth limiting, allowing potential DoS via nested queries.".to_string(),
                                    location: Some(graphql_url.clone()),
                                    recommendation: Some("Implement query depth analysis limits (e.g., maxDepth: 5)".to_string()),
                                    cwe: Some("CWE-770".to_string()),
                                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                                });
                            }

                            // Check for query complexity limiting
                            if !text.contains("complexity") && !text.contains("cost") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Low,
                                    title: "GraphQL Query Complexity Limit Not Detected".to_string(),
                                    description: "GraphQL endpoint may not enforce query complexity limits.".to_string(),
                                    location: Some(graphql_url),
                                    recommendation: Some("Implement query complexity analysis to prevent expensive queries.".to_string()),
                                    cwe: Some("CWE-770".to_string()),
                                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                                });
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// REST API Parameter Tampering detection
    async fn check_rest_parameter_tampering(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Test common REST endpoints
        let test_endpoints = vec![
            ("/api/users/1", "user profile"),
            ("/api/users/me", "current user"),
            ("/api/profile", "profile"),
            ("/api/account", "account"),
            ("/v1/users/1", "v1 user"),
            ("/v2/users/1", "v2 user"),
        ];

        for (_endpoint, _desc) in test_endpoints {
            // Try IDOR-like manipulations
            let idor_variations = vec![
                format!("{}{}", base_url.to_string().trim_end_matches('/'), "/api/users/2"),
                format!("{}{}", base_url.to_string().trim_end_matches('/'), "/api/users/999"),
                format!("{}{}", base_url.to_string().trim_end_matches('/'), "/api/users/0"),
                format!("{}{}", base_url.to_string().trim_end_matches('/'), "/api/users/admin"),
            ];

            for test_endpoint in &idor_variations {
                match self.client.get(test_endpoint).send().await {
                    Ok(response) => {
                        let status = response.status();
                        let text = response.text().await.unwrap_or_default();

                        // Check if we can access other users' data
                        if status.is_success()
                            && (text.contains("email") || text.contains("user") || text.contains("profile"))
                        {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::High,
                                title: "Potential IDOR (Insecure Direct Object Reference)".to_string(),
                                description: format!(
                                    "Could access data at {} by manipulating ID parameter. Direct object reference may be insecure.",
                                    test_endpoint
                                ),
                                location: Some(test_endpoint.clone()),
                                recommendation: Some("Implement proper access controls. Verify user owns the requested resource. Use indirect object references.".to_string()),
                                cwe: Some("CWE-639".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Test parameter pollution
        let pollution_params = vec![("id", "1"), ("user_id", "1"), ("account", "1")];

        for (param, value) in pollution_params {
            let mut test_url = base_url.clone();
            test_url.query_pairs_mut().append_pair(param, value);
            test_url
                .query_pairs_mut()
                .append_pair(format!("{}_", param).as_str(), "2"); // polluted param

            match self.client.get(test_url.as_str()).send().await {
                Ok(response) => {
                    let headers = response.headers().clone();

                    // Check if application processes duplicate parameters incorrectly
                    if headers
                        .get_all("set-cookie")
                        .iter()
                        .count()
                        > 2
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Low,
                            title: "Potential Parameter Pollution".to_string(),
                            description: format!(
                                "Application may be vulnerable to parameter pollution on parameter '{}'",
                                param
                            ),
                            location: Some(test_url.to_string()),
                            recommendation: Some("Validate and sanitize all parameters. Handle duplicate parameters properly.".to_string()),
                            cwe: Some("CWE-434".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Mass Assignment detection
    async fn check_mass_assignment(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Try common API endpoints that might accept mass assignment
        let test_endpoints = vec!["/api/users", "/api/register", "/api/profile", "/v1/users"];

        for endpoint in test_endpoints {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), endpoint);

            // Mass assignment payloads - try to set privileged fields
            let privileged_fields = vec![
                ("role", "admin"),
                ("is_admin", "true"),
                ("admin", "true"),
                ("permissions", "all"),
                ("is_superuser", "true"),
                ("is_staff", "true"),
                ("credits", "999999"),
                ("balance", "999999"),
                ("verified", "true"),
                ("active", "true"),
            ];

            for (field, value) in privileged_fields {
                let mut test_url = base_url.clone();
                test_url.query_pairs_mut().append_pair(field, value);

                match self.client.post(test_url.as_str()).send().await {
                    Ok(response) => {
                        let status = response.status();
                        let text = response.text().await.unwrap_or_default();

                        // If request accepted (2xx) without proper authentication
                        if status.is_success() || status.as_u16() == 201 {
                            // Check if the privileged value was reflected
                            if text.contains(value) || text.contains(field) {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::High,
                                    title: format!("Potential Mass Assignment ({})", field),
                                    description: format!(
                                        "Parameter '{}' may be vulnerable to mass assignment. Privileged field '{}' could be set.",
                                        field, field
                                    ),
                                    location: Some(test_url.to_string()),
                                    recommendation: Some("Use allow-listing for mass assignment. Explicitly define which fields can be set via API.".to_string()),
                                    cwe: Some("CWE-915".to_string()),
                                    owasp: Some("A03:2021 - Injection".to_string()),
                                });
                                break;
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }

            // Test JSON mass assignment
            let json_payloads = vec![
                r#"{"user": {"role": "admin", "is_admin": true}}"#,
                r#"{"profile": {"is_staff": true, "permissions": ["all"]}}"#,
                r#"{"account": {"balance": 999999, "credits": 999999}}"#,
            ];

            for payload in json_payloads {
                match self
                    .client
                    .post(&test_url)
                    .header("Content-Type", "application/json")
                    .body(payload)
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();

                        if status.is_success() || status.as_u16() == 201 {
                            report.add_finding(Vuln {
                                severity: VulnSeverity::Medium,
                                title: "Potential JSON Mass Assignment".to_string(),
                                description: "API may accept arbitrary fields in JSON, allowing mass assignment attacks.".to_string(),
                                location: Some(test_url.clone()),
                                recommendation: Some("Implement field validation and allow-listing for all input models.".to_string()),
                                cwe: Some("CWE-915".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(report)
    }

    /// API Versioning Issues detection
    async fn check_api_versioning(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Check for multiple API versions
        let version_endpoints = vec!["/v1/", "/v2/", "/api/v1/", "/api/v2/", "/v3/"];

        let mut versions_found = vec![];

        for version_path in version_endpoints {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), version_path);

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    if !response.status().is_server_error() {
                        // Check if it's actually an API endpoint
                        if let Ok(text) = response.text().await {
                            if text.contains("json")
                                || text.contains("api")
                                || text.contains("data")
                                || text.contains("[]")
                                || text.contains("{}")
                            {
                                versions_found.push(version_path);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Check for insecure deprecated versions
        if versions_found.len() > 1 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: "Multiple API Versions Active".to_string(),
                description: format!(
                    "Multiple API versions detected: {:?}. Consider deprecating old versions.",
                    versions_found
                ),
                location: Some(base_url.to_string()),
                recommendation: Some("Maintain a clear API versioning strategy. Deprecate old versions with proper notice.".to_string()),
                cwe: Some("CWE-454".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check for unversioned API
        let unversioned = format!("{}/api/", base_url.to_string().trim_end_matches('/'));
        match self.client.get(&unversioned).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Info,
                        title: "Unversioned API Endpoint Detected".to_string(),
                        description: "API endpoint without version detected. This makes API evolution difficult.".to_string(),
                        location: Some(unversioned),
                        recommendation: Some("Implement API versioning (e.g., /api/v1/). Use semantic versioning.".to_string()),
                        cwe: Some("CWE-454".to_string()),
                        owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                    });
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }

    /// WebSocket Security testing
    async fn check_websocket_security(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(report),
        };

        // Common WebSocket endpoints
        let ws_paths = vec![
            "/ws",
            "/websocket",
            "/socket.io",
            "/socket",
            "/realtime",
            "/live",
            "/events",
        ];

        for path in ws_paths {
            let ws_url = format!(
                "{}{}",
                base_url.to_string().replace("http://", "ws://").replace("https://", "wss://"),
                path
            );

            // Try to detect WebSocket availability via HTTP upgrade check
            let http_url = ws_url.replace("ws://", "http://").replace("wss://", "https://");

            match self.client.get(&http_url).send().await {
                Ok(response) => {
                    let headers = response.headers();

                    // Check for WebSocket upgrade header
                    if let Some(upgrade) = headers.get("upgrade") {
                        if let Ok(upgrade_str) = upgrade.to_str() {
                            if upgrade_str.to_lowercase().contains("websocket") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Info,
                                    title: "WebSocket Endpoint Detected".to_string(),
                                    description: format!("WebSocket endpoint found at {}", path),
                                    location: Some(ws_url.clone()),
                                    recommendation: Some("Ensure WebSocket uses WSS (encrypted). Implement origin validation and rate limiting.".to_string()),
                                    cwe: Some("CWE-926".to_string()),
                                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                                });

                                // Check if using WSS (secure)
                                if ws_url.starts_with("ws://") {
                                    report.add_finding(Vuln {
                                        severity: VulnSeverity::Medium,
                                        title: "WebSocket Using Unencrypted Protocol".to_string(),
                                        description: "WebSocket endpoint uses ws:// instead of wss://, exposing data in transit.".to_string(),
                                        location: Some(ws_url),
                                        recommendation: Some("Use WSS (WebSocket Secure) for all WebSocket connections.".to_string()),
                                        cwe: Some("CWE-319".to_string()),
                                        owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                                    });
                                }

                                // Check for Origin validation
                                let headers_clone = headers.clone();
                                if headers_clone.get("sec-websocket-protocol").is_none() {
                                    report.add_finding(Vuln {
                                        severity: VulnSeverity::Low,
                                        title: "WebSocket May Lack Origin Validation".to_string(),
                                        description: "WebSocket endpoint may not validate the Origin header, allowing CSRF attacks.".to_string(),
                                        location: Some(path.to_string()),
                                        recommendation: Some("Validate the Origin header on WebSocket handshake. Use Sec-WebSocket-Protocol.".to_string()),
                                        cwe: Some("CWE-346".to_string()),
                                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Check for Socket.io specific vulnerabilities
        let socketio_paths = vec!["/socket.io/", "/socket.io"];

        for path in socketio_paths {
            let test_url = format!(
                "{}{}",
                base_url.to_string().trim_end_matches('/'),
                path
            );

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        if let Ok(text) = response.text().await {
                            if text.contains("socket.io") || text.contains("engine.io") {
                                report.add_finding(Vuln {
                                    severity: VulnSeverity::Info,
                                    title: "Socket.io Endpoint Detected".to_string(),
                                    description: "Socket.io library detected. Ensure proper CORS and authentication.".to_string(),
                                    location: Some(test_url),
                                    recommendation: Some("Configure Socket.io with proper origins, authentication, and rate limiting.".to_string()),
                                    cwe: Some("CWE-926".to_string()),
                                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                                });
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }
}
