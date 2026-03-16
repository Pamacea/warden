//! GraphQL Security Scanner

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;

pub struct GraphQLScanner {
    client: Client,
    config: ScannerConfig,
}

#[derive(Debug, Clone)]
struct GraphQLEndpoint {
    url: String,
    path: String,
    detected_via: String,
}

impl GraphQLScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");
        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));
        let endpoints = self.detect_graphql_endpoints(url).await?;
        if endpoints.is_empty() {
            return Ok(report);
        }
        for endpoint in endpoints {
            report.merge(self.test_introspection(&endpoint).await?);
            report.merge(self.test_injection(&endpoint).await?);
            if self.config.aggressive {
                report.merge(self.test_dos(&endpoint).await?);
            }
            report.merge(self.test_batching(&endpoint).await?);
        }
        Ok(report)
    }

    async fn detect_graphql_endpoints(&self, url: &str) -> Result<Vec<GraphQLEndpoint>> {
        let mut endpoints = Vec::new();
        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(endpoints),
        };
        let paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/api"];
        for path in paths {
            let endpoint_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);
            if self.is_graphql_endpoint(&endpoint_url).await {
                endpoints.push(GraphQLEndpoint {
                    url: endpoint_url.clone(),
                    path: path.to_string(),
                    detected_via: "POST".to_string(),
                });
            }
        }
        Ok(endpoints)
    }

    async fn is_graphql_endpoint(&self, url: &str) -> bool {
        let test = r#"{"query":"query{__typename}"#;
        match self.client.post(url).header("Content-Type", "application/json")
            .body(test).send().await {
            Ok(r) => {
                if r.status().is_success() || r.status().as_u16() == 400 {
                    if let Ok(t) = r.text().await {
                        return t.contains("__typename") || t.contains("\"data\"");
                    }
                }
                false
            }
            Err(_) => false,
        }
    }

    async fn test_introspection(&self, endpoint: &GraphQLEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));
        let query = r#"{"query":"query{__schema{queryType{name}}}"#;
        match self.client.post(&endpoint.url).header("Content-Type", "application/json")
            .body(query).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if text.contains("__schema") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "GraphQL Introspection Enabled".to_string(),
                        description: "Introspection is enabled.".to_string(),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Disable introspection.".to_string()),
                        cwe: Some("CWE-215".to_string()),
                        owasp: Some("A01:2021".to_string()),
                    });
                }
            }
            Err(_) => {}
        }
        Ok(report)
    }

    async fn test_injection(&self, endpoint: &GraphQLEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));
        let payload = r#"{"query":"query{user(id:\"1'OR'1'='1\"){id}}"#;
        match self.client.post(&endpoint.url).header("Content-Type", "application/json")
            .body(payload).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if text.contains("SQL") || text.contains("mysql") {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "Potential SQL Injection".to_string(),
                        description: "SQLi possible in args.".to_string(),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Use parameterized queries.".to_string()),
                        cwe: Some("CWE-89".to_string()),
                        owasp: Some("A03:2021".to_string()),
                    });
                }
            }
            Err(_) => {}
        }
        Ok(report)
    }

    async fn test_dos(&self, endpoint: &GraphQLEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));
        let query = r#"{"query":"query{user(id:\"1\"){friends{friends{friends{id}}}}}"#;
        let start = std::time::Instant::now();
        match self.client.post(&endpoint.url).header("Content-Type", "application/json")
            .body(query).send().await {
            Ok(r) => {
                let elapsed = start.elapsed();
                let text = r.text().await.unwrap_or_default();
                if text.contains("\"data\"") && elapsed.as_secs() > 2 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Depth Limit Not Configured".to_string(),
                        description: format!("Deep query took {}ms", elapsed.as_millis()),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Implement depth limiting.".to_string()),
                        cwe: Some("CWE-770".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                }
            }
            Err(_) => {}
        }
        Ok(report)
    }

    async fn test_batching(&self, endpoint: &GraphQLEndpoint) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(endpoint.url.clone()));
        let batch = r#"[{"query":"query{__typename}"},{"query":"query{__typename}"}]"#;
        match self.client.post(&endpoint.url).header("Content-Type", "application/json")
            .body(batch).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if text.matches("__typename").count() >= 2 {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: "Batch Queries Enabled".to_string(),
                        description: "GraphQL accepts batch queries.".to_string(),
                        location: Some(endpoint.url.clone()),
                        recommendation: Some("Disable batching.".to_string()),
                        cwe: Some("CWE-770".to_string()),
                        owasp: Some("A04:2021".to_string()),
                    });
                }
            }
            Err(_) => {}
        }
        Ok(report)
    }
}
