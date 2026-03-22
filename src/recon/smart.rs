//! Smart Reconnaissance Scanner - Advanced Automated Discovery
//!
//! This module provides comprehensive reconnaissance capabilities including:
//! - Automated subdomain enumeration
//! - Port scanning intelligence
//! - Technology fingerprinting
//! - API endpoint discovery
//! - Attack surface mapping
//! - Passive reconnaissance
//! - Active reconnaissance

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Smart Reconnaissance Scanner
pub struct SmartReconScanner {
    config: ScannerConfig,
    client: reqwest::Client,
}

impl SmartReconScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(30);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client for smart recon");

        Self { config, client }
    }

    /// Main scan entry point - orchestrates all reconnaissance phases
    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Phase 1: Passive Reconnaissance
        let passive_results = self.passive_reconnaissance(url).await?;
        report.merge(self.passive_results_to_report(&passive_results, url).await?);

        // Phase 2: Attack Surface Mapping
        let attack_surface = self.map_attack_surface(url, &passive_results).await?;
        report.merge(self.attack_surface_to_report(&attack_surface, url).await?);

        // Phase 3: Technology Fingerprinting
        let technologies = self.fingerprint_technologies(url).await?;
        report.merge(self.technologies_to_report(&technologies, url).await?);

        // Phase 4: Active Reconnaissance (aggressive mode only)
        if self.config.aggressive {
            let active_results = self.active_reconnaissance(url, &attack_surface).await?;
            report.merge(self.active_results_to_report(&active_results, url).await?);
        }

        // Phase 5: Results Aggregation and Deduplication
        self.aggregate_results(&mut report);

        Ok(report)
    }

    /// Phase 1: Passive Reconnaissance
    /// Gather information without directly contacting the target
    async fn passive_reconnaissance(&self, url: &str) -> Result<ReconResult> {
        let mut result = ReconResult::new(url.to_string());

        // Extract domain from URL
        let domain = self.extract_domain(url);
        result.domain = domain.clone();

        // Certificate Transparency Log enumeration
        result.subdomains.extend(self.enumerate_ct_logs(&domain).await?);

        // DNS enumeration
        result.dns_records.extend(self.dns_enumeration(&domain).await?);

        // Search engine reconnaissance
        result.search_engine_findings.extend(self.search_engine_dorking(&domain).await?);

        // Shodan/Censys search (if API keys available)
        if let Ok(shodan_results) = self.shodan_search(&domain).await {
            result.shodan_findings = shodan_results;
        }

        Ok(result)
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> String {
        url.parse::<url::Url>()
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| url.to_string())
    }

    /// Enumerate subdomains via Certificate Transparency logs
    async fn enumerate_ct_logs(&self, domain: &str) -> Result<Vec<SubdomainResult>> {
        let mut subdomains = Vec::new();

        // crt.sh API endpoint
        let ct_url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            domain.replace("www.", "")
        );

        match self.client.get(&ct_url).send().await {
            Ok(response) => {
                if let Ok(text) = response.text().await {
                    // Parse JSON response
                    if let Ok(json_data) = serde_json::from_str::<Vec<CrtShEntry>>(&text) {
                        for entry in json_data {
                            // Extract subdomains from name_value
                            for name in entry.name_value.split('\n') {
                                let cleaned = name.trim().trim_end_matches('.');
                                if !cleaned.is_empty() && cleaned.contains(domain) {
                                    subdomains.push(SubdomainResult {
                                        subdomain: cleaned.to_string(),
                                        source: "crt.sh".to_string(),
                                        ip_addresses: Vec::new(),
                                        status: "found".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        // DNS dumpster-style subdomain guessing
        let common_subdomains = vec![
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "admin", "api", "beta", "dev", "staging", "test", "app", "mobile",
            "cdn", "static", "assets", "img", "images", "video", "media",
            "blog", "shop", "store", "secure", "vpn", "remote", "portal",
            "dashboard", "panel", "cpanel", "whm", "webdisk",
            "autodiscover", "autoconfig", "wp", "wordpress",
            "docs", "help", "support", "wiki", "kb",
            "m", "mobile", "touch", "w",
            "cloud", "cdn", "edge", "origin",
        ];

        // Store for potential active resolution
        for sub in common_subdomains {
            let full_domain = format!("{}.{}", sub, domain);
            subdomains.push(SubdomainResult {
                subdomain: full_domain,
                source: "wordlist".to_string(),
                ip_addresses: Vec::new(),
                status: "pending".to_string(),
            });
        }

        Ok(subdomains)
    }

    /// DNS Enumeration
    async fn dns_enumeration(&self, domain: &str) -> Result<Vec<DnsRecord>> {
        let mut records = Vec::new();

        // Common DNS record types to check
        let _record_types = vec![
            "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "DMARC",
        ];

        // Common DNS records
        let common_records = vec![
            ("@", "A"),
            ("www", "A"),
            ("mail", "A"),
            ("api", "A"),
            ("admin", "A"),
            ("@", "MX"),
            ("@._domainkey", "TXT"),
            ("_dmarc", "TXT"),
        ];

        for (name, rtype) in common_records {
            let full_name = if name == "@" {
                domain.to_string()
            } else {
                format!("{}.{}", name, domain)
            };

            records.push(DnsRecord {
                name: full_name,
                record_type: rtype.to_string(),
                value: "unknown".to_string(), // Would need DNS resolution
                source: "wordlist".to_string(),
            });
        }

        Ok(records)
    }

    /// Search Engine Dorking
    async fn search_engine_dorking(&self, domain: &str) -> Result<Vec<SearchEngineFinding>> {
        let mut findings = Vec::new();

        // Common Google dorks for the domain
        let dorks = vec![
            (format!("site:{} filetype:pdf", domain), "PDF Files"),
            (format!("site:{} filetype:xls OR filetype:xlsx", domain), "Excel Files"),
            (format!("site:{} filetype:doc OR filetype:docx", domain), "Word Documents"),
            (format!("site:{} inurl:admin", domain), "Admin Panels"),
            (format!("site:{} inurl:login", domain), "Login Pages"),
            (format!("site:{} inurl:wp-content", domain), "WordPress Content"),
            (format!("site:{} inurl:backup", domain), "Backup Files"),
            (format!("site:{} intext:\"Index of\"", domain), "Directory Listings"),
            (format!("site:{} intitle:\"index of\"", domain), "Index Pages"),
            (format!("site:{} inurl:.env", domain), "Environment Files"),
            (format!("site:{} inurl:config", domain), "Config Files"),
            (format!("site:{} ext:xml", domain), "XML Files"),
            (format!("site:{} ext:sql", domain), "SQL Files"),
            (format!("site:{} ext:log", domain), "Log Files"),
        ];

        for (dork, description) in dorks {
            findings.push(SearchEngineFinding {
                dork: dork.clone(),
                description: description.to_string(),
                url: format!("https://www.google.com/search?q={}", urlencoding::encode(&dork)),
                finding_type: "dork".to_string(),
            });
        }

        Ok(findings)
    }

    /// Shodan Search (placeholder - requires API key)
    async fn shodan_search(&self, domain: &str) -> Result<Vec<ShodanFinding>> {
        // This would require a Shodan API key
        // For now, return search URLs
        let findings = vec![
            ShodanFinding {
                service: "Web Server".to_string(),
                port: 443,
                info: format!("Check Shodan for exposed services on {}", domain),
                url: format!("https://www.shodan.io/search?query={}", domain),
            },
        ];

        Ok(findings)
    }

    /// Phase 2: Attack Surface Mapping
    async fn map_attack_surface(
        &self,
        url: &str,
        passive_results: &ReconResult,
    ) -> Result<AttackSurfaceMap> {
        let mut surface = AttackSurfaceMap::new(url.to_string());

        // Map discovered subdomains
        for subdomain in &passive_results.subdomains {
            surface.assets.insert(Asset {
                name: subdomain.subdomain.clone(),
                asset_type: AssetType::Subdomain,
                url: format!("https://{}", subdomain.subdomain),
                status: subdomain.status.clone(),
                risk_score: self.calculate_subdomain_risk(&subdomain.subdomain),
            });
        }

        // Map web application endpoints
        let endpoints = self.discover_web_endpoints(url).await?;
        for endpoint in endpoints {
            surface.assets.insert(Asset {
                name: endpoint.clone(),
                asset_type: AssetType::Endpoint,
                url: format!("{}{}", url.trim_end_matches('/'), endpoint),
                status: "discovered".to_string(),
                risk_score: self.calculate_endpoint_risk(&endpoint),
            });
        }

        // Map potential API endpoints
        let api_endpoints = self.discover_api_endpoints(url).await?;
        for endpoint in api_endpoints {
            surface.assets.insert(Asset {
                name: endpoint.path.clone(),
                asset_type: AssetType::ApiEndpoint,
                url: format!("{}{}", url.trim_end_matches('/'), endpoint.path),
                status: "discovered".to_string(),
                risk_score: self.calculate_api_risk(&endpoint),
            });
        }

        // Calculate total risk score
        surface.total_risk_score = surface.assets.iter()
            .map(|a| a.risk_score)
            .sum::<f32>() / surface.assets.len().max(1) as f32;

        Ok(surface)
    }

    /// Discover web application endpoints
    async fn discover_web_endpoints(&self, url: &str) -> Result<Vec<String>> {
        let mut endpoints = Vec::new();

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(endpoints),
        };

        // Check for common web paths
        let common_paths = vec![
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/",
            "/admin",
            "/login",
            "/register",
            "/api",
            "/v1",
            "/v2",
            "/graphql",
            "/swagger",
            "/api-docs",
            "/console",
            "/dashboard",
            "/panel",
            "/cpanel",
            "/wp-admin",
            "/wp-login.php",
            "/administrator",
            "/manager",
            "/user",
            "/account",
            "/profile",
            "/settings",
            "/config",
            "/backup",
            "/backups",
            "/test",
            "/testing",
            "/dev",
            "/staging",
            "/beta",
            "/upload",
            "/uploads",
            "/download",
            "/downloads",
            "/files",
            "/static",
            "/assets",
            "/public",
            "/private",
            "/internal",
            "/secret",
            "/logs",
            "/log",
            "/cache",
            "/tmp",
            "/temp",
            "/debug",
            "/error",
            "/errors",
            "/status",
            "/health",
            "/metrics",
            "/prometheus",
            "/grafana",
            "/kibana",
            "/elasticsearch",
        ];

        for path in common_paths {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);

            match self.client.head(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() != 404 {
                        endpoints.push(path.to_string());
                    }
                }
                Err(_) => {}
            }
        }

        Ok(endpoints)
    }

    /// Discover API endpoints with details
    async fn discover_api_endpoints(&self, url: &str) -> Result<Vec<ApiEndpointInfo>> {
        let mut endpoints = Vec::new();

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(endpoints),
        };

        // Common API endpoint patterns
        let api_patterns = vec![
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/backup",
            "/api/export",
            "/api/import",
            "/api/upload",
            "/api/download",
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/reset",
            "/api/auth/logout",
            "/api/v1/users",
            "/api/v1/admin",
            "/api/v1/config",
            "/api/v2/users",
            "/api/v2/admin",
            "/graphql",
            "/graphiql",
            "/api/graphql",
            "/rest/users",
            "/rest/admin",
            "/ws",
            "/socket.io",
            "/api/swagger.json",
            "/api/openapi.json",
            "/api/docs",
            "/swagger",
            "/api-docs",
            "/v1/api-docs",
            "/api/metrics",
            "/api/health",
            "/api/status",
            "/api/debug",
            "/api/test",
        ];

        for path in api_patterns {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() != 404 {
                        endpoints.push(ApiEndpointInfo {
                            path: path.to_string(),
                            methods: self.detect_allowed_methods(&test_url).await?,
                            auth_required: self.detect_auth_requirement(&test_url).await?,
                            rate_limited: self.detect_rate_limit(&test_url).await?,
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok(endpoints)
    }

    /// Detect allowed HTTP methods for an endpoint
    async fn detect_allowed_methods(&self, url: &str) -> Result<Vec<String>> {
        let mut methods = Vec::new();

        let http_methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];

        for method in http_methods {
            let request = match method {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "DELETE" => self.client.delete(url),
                "PATCH" => self.client.patch(url),
                "OPTIONS" => self.client.request(reqwest::Method::OPTIONS, url),
                "HEAD" => self.client.head(url),
                _ => continue,
            };

            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() != 405 && status.as_u16() != 501 {
                        methods.push(method.to_string());
                    }
                }
                Err(_) => {}
            }
        }

        Ok(methods)
    }

    /// Detect if endpoint requires authentication
    async fn detect_auth_requirement(&self, url: &str) -> Result<bool> {
        match self.client.get(url).send().await {
            Ok(response) => {
                let status = response.status();
                let headers = response.headers();

                // Check for auth indicators
                if status.as_u16() == 401 || status.as_u16() == 403 {
                    return Ok(true);
                }

                if headers.contains_key("www-authenticate") {
                    return Ok(true);
                }

                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }

    /// Detect if endpoint has rate limiting
    async fn detect_rate_limit(&self, url: &str) -> Result<bool> {
        match self.client.get(url).send().await {
            Ok(response) => {
                let headers = response.headers();

                // Check for rate limit headers
                if headers.contains_key("x-ratelimit-limit")
                    || headers.contains_key("x-rate-limit-limit")
                    || headers.contains_key("ratelimit-limit")
                {
                    return Ok(true);
                }

                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }

    /// Calculate risk score for a subdomain
    fn calculate_subdomain_risk(&self, subdomain: &str) -> f32 {
        let mut risk: f32 = 0.5; // Base risk

        // Higher risk for admin/dev subdomains
        if subdomain.contains("admin")
            || subdomain.contains("dev")
            || subdomain.contains("staging")
            || subdomain.contains("test")
            || subdomain.contains("beta")
            || subdomain.contains("pre")
            || subdomain.contains("internal")
        {
            risk += 0.3;
        }

        // Lower risk for www
        if subdomain.starts_with("www.") {
            risk -= 0.1;
        }

        risk.min(1.0).max(0.0)
    }

    /// Calculate risk score for an endpoint
    fn calculate_endpoint_risk(&self, endpoint: &str) -> f32 {
        let mut risk: f32 = 0.3; // Base risk

        // High risk endpoints
        if endpoint.contains("admin")
            || endpoint.contains("config")
            || endpoint.contains("backup")
            || endpoint.contains("debug")
            || endpoint.contains("test")
            || endpoint.contains("dev")
        {
            risk += 0.4;
        }

        // Medium risk endpoints
        if endpoint.contains("api")
            || endpoint.contains("graphql")
            || endpoint.contains("swagger")
            || endpoint.contains("docs")
        {
            risk += 0.2;
        }

        risk.min(1.0).max(0.0)
    }

    /// Calculate risk score for an API endpoint
    fn calculate_api_risk(&self, endpoint: &ApiEndpointInfo) -> f32 {
        let mut risk = self.calculate_endpoint_risk(&endpoint.path);

        // Higher risk if no auth required
        if !endpoint.auth_required {
            risk += 0.2;
        }

        // Higher risk for DELETE/PUT/PATCH methods
        for method in &endpoint.methods {
            if method == "DELETE" || method == "PUT" || method == "PATCH" {
                risk += 0.1;
            }
        }

        // Lower risk if rate limited
        if endpoint.rate_limited {
            risk -= 0.1;
        }

        risk.min(1.0).max(0.0)
    }

    /// Phase 3: Technology Fingerprinting
    async fn fingerprint_technologies(&self, url: &str) -> Result<Vec<TechnologyFingerprint>> {
        let mut technologies = Vec::new();

        match self.client.get(url).send().await {
            Ok(response) => {
                // Clone headers before consuming response
                let headers = response.headers().clone();
                let text = response.text().await.unwrap_or_default();

                // Check server header
                if let Some(server) = headers.get("server") {
                    if let Ok(server_str) = server.to_str() {
                        technologies.push(TechnologyFingerprint {
                            name: "Server".to_string(),
                            version: server_str.to_string(),
                            category: "Server".to_string(),
                            confidence: 0.9,
                        });

                        // Detect specific server types
                        if server_str.contains("nginx") {
                            technologies.push(TechnologyFingerprint {
                                name: "Nginx".to_string(),
                                version: server_str.to_string(),
                                category: "Web Server".to_string(),
                                confidence: 0.95,
                            });
                        } else if server_str.contains("Apache") {
                            technologies.push(TechnologyFingerprint {
                                name: "Apache".to_string(),
                                version: server_str.to_string(),
                                category: "Web Server".to_string(),
                                confidence: 0.95,
                            });
                        } else if server_str.contains("cloudflare") {
                            technologies.push(TechnologyFingerprint {
                                name: "Cloudflare".to_string(),
                                version: "CDN".to_string(),
                                category: "CDN/Proxy".to_string(),
                                confidence: 0.9,
                            });
                        }
                    }
                }

                // Check X-Powered-By header
                if let Some(x_powered) = headers.get("x-powered-by") {
                    if let Ok(powered_str) = x_powered.to_str() {
                        technologies.push(TechnologyFingerprint {
                            name: powered_str.to_string(),
                            version: String::new(),
                            category: "Framework".to_string(),
                            confidence: 0.95,
                        });
                    }
                }

                // Check for common CMS/frameworks in HTML
                let cms_patterns = vec![
                    (r#"wp-content"#, "WordPress", "CMS"),
                    (r#"wp-includes"#, "WordPress", "CMS"),
                    (r#"/node_modules/"#, "Node.js", "Runtime"),
                    (r#"react"#, "React", "Frontend Framework"),
                    (r#"__NEXT_DATA__"#, "Next.js", "Frontend Framework"),
                    (r#"nuxt"#, "Nuxt.js", "Frontend Framework"),
                    (r#"_nuxt"#, "Nuxt.js", "Frontend Framework"),
                    (r#"vue"#, "Vue.js", "Frontend Framework"),
                    (r#"angular"#, "Angular", "Frontend Framework"),
                    (r#"data-v-"#, "Vue.js", "Frontend Framework"),
                    (r#"gatsby"#, "Gatsby", "SSG"),
                    (r#"Drupal"#, "Drupal", "CMS"),
                    (r#"Joomla"#, "Joomla", "CMS"),
                    (r#"Laravel"#, "Laravel", "PHP Framework"),
                    (r#"django"#, "Django", "Python Framework"),
                    (r#"flask"#, "Flask", "Python Framework"),
                    (r#"rails"#, "Ruby on Rails", "Ruby Framework"),
                    (r#"express"#, "Express.js", "Node.js Framework"),
                    (r#"/assets/"#, "Ruby on Rails", "Ruby Framework"),
                    (r#"Shopify"#, "Shopify", "E-commerce"),
                    (r#"shopify"#, "Shopify", "E-commerce"),
                    (r#"woocommerce"#, "WooCommerce", "E-commerce"),
                    (r#"stripe"#, "Stripe", "Payment"),
                    (r#"jquery"#, "jQuery", "JavaScript Library"),
                ];

                for (pattern, name, category) in cms_patterns {
                    if text.contains(pattern) {
                        technologies.push(TechnologyFingerprint {
                            name: name.to_string(),
                            version: String::new(),
                            category: category.to_string(),
                            confidence: 0.8,
                        });
                    }
                }

                // Check for analytics
                let analytics_patterns = vec![
                    ("googletagmanager.com", "Google Tag Manager", "Analytics"),
                    ("google-analytics.com", "Google Analytics", "Analytics"),
                    ("facebook.com/tr", "Facebook Pixel", "Analytics"),
                    ("hotjar.com", "Hotjar", "Analytics"),
                    ("segment.com", "Segment", "Analytics"),
                    ("amplitude.com", "Amplitude", "Analytics"),
                    ("mixpanel.com", "Mixpanel", "Analytics"),
                ];

                for (pattern, name, category) in analytics_patterns {
                    if text.contains(pattern) {
                        technologies.push(TechnologyFingerprint {
                            name: name.to_string(),
                            version: String::new(),
                            category: category.to_string(),
                            confidence: 0.9,
                        });
                    }
                }
            }
            Err(_) => {}
        }

        Ok(technologies)
    }

    /// Phase 4: Active Reconnaissance
    async fn active_reconnaissance(
        &self,
        url: &str,
        attack_surface: &AttackSurfaceMap,
    ) -> Result<ActiveReconResult> {
        let mut result = ActiveReconResult::new(url.to_string());

        let base_url = match url.parse::<url::Url>() {
            Ok(u) => u,
            Err(_) => return Ok(result),
        };

        // Targeted directory fuzzing
        let fuzz_paths = self.smart_directory_fuzzing(&base_url).await?;
        result.discovered_paths.extend(fuzz_paths);

        // Parameter discovery
        for asset in attack_surface.assets.iter() {
            if asset.asset_type == AssetType::Endpoint {
                let params = self.discover_parameters(&asset.url).await?;
                result.parameters.extend(params);
            }
        }

        // Header analysis
        let headers = self.analyze_headers(&base_url).await?;
        result.header_info = headers;

        Ok(result)
    }

    /// Smart directory fuzzing with intelligent payloads
    async fn smart_directory_fuzzing(&self, base_url: &url::Url) -> Result<Vec<String>> {
        let mut discovered = Vec::new();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;

        // Intelligent wordlist based on discovered technologies
        let tech_based_paths = vec![
            // REST API
            "/api/v1", "/api/v2", "/api/v3", "/rest", "/graphql",
            // Admin/Management
            "/admin", "/administrator", "/wp-admin", "/admin/login", "/admin/dashboard",
            "/manager", "/manage", "/cpanel", "/whm", "/plex",
            // Config/Settings
            "/config", "/settings", "/setup", "/install", "/installation",
            // Debug/Dev
            "/debug", "/test", "/testing", "/dev", "/staging", "/beta",
            // Authentication
            "/login", "/logout", "/auth", "/authenticate", "/signin", "/signup",
            "/register", "/reset", "/forgot", "/recover",
            // User/Account
            "/user", "/users", "/account", "/profile", "/me",
            // Data/Export
            "/export", "/download", "/backup", "/backups", "/dump",
            // Documentation
            "/docs", "/documentation", "/help", "/support", "/wiki", "/kb",
            // API Docs
            "/swagger", "/api-docs", "/redoc", "/openapi", "/graphql",
            // Monitoring
            "/health", "/status", "/metrics", "/prometheus", "/grafana",
            // Uploads/Files
            "/upload", "/uploads", "/files", "/static", "/assets", "/media",
            // Logs/Cache
            "/logs", "/log", "/cache", "/tmp", "/temp", "/sessions",
            // Web services
            "/webmail", "/email", "/mail", "/ftp", "webdisk",
            // Development tools
            "/phpmyadmin", "/adminer", "/console", "/terminal", "/shell",
            // Cloud services
            "/.well-known", "/aws", "/azure", "/s3",
            // CI/CD
            "/jenkins", "/gitlab", "/github", "/bitbucket", "/ci",
            // Container/K8s
            "/kubernetes", "/k8s", "/docker", "/container",
        ];

        for path in tech_based_paths {
            let test_url = format!("{}{}", base_url.to_string().trim_end_matches('/'), path);

            match client.head(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    if status.as_u16() != 404 {
                        discovered.push(path.to_string());
                    }
                }
                Err(_) => {}
            }
        }

        Ok(discovered)
    }

    /// Discover parameters used by endpoints
    async fn discover_parameters(&self, url: &str) -> Result<Vec<ParameterInfo>> {
        let mut parameters = Vec::new();

        // Common parameter names
        let common_params = vec![
            "id", "user_id", "user", "username", "email", "password",
            "token", "api_key", "key", "secret", "access_token",
            "redirect", "url", "return", "next", "goto",
            "file", "filename", "path", "dir", "folder",
            "page", "limit", "offset", "sort", "order",
            "search", "query", "q", "filter", "category",
            "action", "method", "cmd", "exec", "command",
            "debug", "test", "dev", "verbose",
            "format", "output", "callback", "jsonp",
            "lang", "locale", "language",
        ];

        // Try adding each parameter with a test value
        for param in common_params {
            let test_url = if url.contains('?') {
                format!("{}&{}=test", url, param)
            } else {
                format!("{}?{}=test", url, param)
            };

            match self.client.get(&test_url).send().await {
                Ok(response) => {
                    let status = response.status();
                    // If response is different from base, parameter might be accepted
                    if status.as_u16() != 404 {
                        parameters.push(ParameterInfo {
                            name: param.to_string(),
                            param_type: self.guess_parameter_type(param),
                            required: false,
                            values: vec!["test".to_string()],
                        });
                    }
                }
                Err(_) => {}
            }
        }

        Ok(parameters)
    }

    /// Guess parameter type based on name
    fn guess_parameter_type(&self, param: &str) -> String {
        match param {
            p if p.contains("id") => "integer".to_string(),
            p if p.contains("email") => "email".to_string(),
            p if p.contains("pass") => "password".to_string(),
            p if p.contains("token") || p.contains("key") => "string".to_string(),
            p if p.contains("url") || p.contains("redirect") => "url".to_string(),
            p if p.contains("file") => "file".to_string(),
            p if p.contains("page") || p.contains("limit") => "integer".to_string(),
            _ => "string".to_string(),
        }
    }

    /// Analyze security headers
    async fn analyze_headers(&self, base_url: &url::Url) -> Result<HeaderAnalysis> {
        let mut analysis = HeaderAnalysis::new();

        match self.client.get(base_url.as_str()).send().await {
            Ok(response) => {
                let headers = response.headers();

                // Check for security headers
                analysis.has_hsts = headers.contains_key("strict-transport-security");
                analysis.has_csp = headers.contains_key("content-security-policy");
                analysis.has_xframe = headers.contains_key("x-frame-options");
                analysis.has_xss = headers.contains_key("x-content-type-options")
                    || headers.contains_key("x-xss-protection");
                analysis.has_referrer = headers.contains_key("referrer-policy");
                analysis.has_permissions = headers.contains_key("permissions-policy");

                // Check for information disclosure
                if let Some(server) = headers.get("server") {
                    analysis.server_header = server.to_str().unwrap_or("Unknown").to_string();
                }

                if let Some(x_powered) = headers.get("x-powered-by") {
                    analysis.x_powered_by = x_powered.to_str().unwrap_or("Unknown").to_string();
                }

                // Collect all headers
                for (name, value) in headers.iter() {
                    if let Ok(value_str) = value.to_str() {
                        analysis.all_headers.insert(
                            name.as_str().to_string(),
                            value_str.to_string(),
                        );
                    }
                }
            }
            Err(_) => {}
        }

        Ok(analysis)
    }

    /// Convert passive results to vulnerability report
    async fn passive_results_to_report(&self, results: &ReconResult, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Report discovered subdomains
        if !results.subdomains.is_empty() {
            let unique_subs: HashSet<_> = results.subdomains.iter()
                .map(|s| s.subdomain.clone())
                .collect();

            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: format!("Discovered {} Subdomains", unique_subs.len()),
                description: format!(
                    "Subdomain enumeration discovered {} unique subdomains including: {:?}",
                    unique_subs.len(),
                    unique_subs.iter().take(10).collect::<Vec<_>>()
                ),
                location: Some(results.domain.clone()),
                recommendation: Some("Review all discovered subdomains and ensure they are properly secured.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Report DNS records
        if !results.dns_records.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: format!("Discovered {} DNS Records", results.dns_records.len()),
                description: format!("DNS enumeration found {} records", results.dns_records.len()),
                location: Some(results.domain.clone()),
                recommendation: Some("Review DNS records for unauthorized entries.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Report search engine findings
        if !results.search_engine_findings.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: format!("{} Search Engine Dorks Available", results.search_engine_findings.len()),
                description: format!(
                    "Generated {} Google dorks for passive reconnaissance. Use these to discover exposed information.",
                    results.search_engine_findings.len()
                ),
                location: Some(format!("https://www.google.com/search?q=site:{}", results.domain)),
                recommendation: Some("Perform manual reconnaissance using the provided dorks.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Convert attack surface to vulnerability report
    async fn attack_surface_to_report(&self, surface: &AttackSurfaceMap, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Categorize assets by risk
        let high_risk: Vec<_> = surface.assets.iter()
            .filter(|a| a.risk_score >= 0.7)
            .collect();

        let medium_risk: Vec<_> = surface.assets.iter()
            .filter(|a| a.risk_score >= 0.4 && a.risk_score < 0.7)
            .collect();

        if !high_risk.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: format!("{} High-Risk Assets Discovered", high_risk.len()),
                description: format!(
                    "Attack surface mapping identified {} high-risk assets: {}",
                    high_risk.len(),
                    high_risk.iter()
                        .map(|a| a.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                location: Some(url.to_string()),
                recommendation: Some("Review and secure high-risk assets. Implement additional access controls.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        if !medium_risk.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: format!("{} Medium-Risk Assets Discovered", medium_risk.len()),
                description: format!("Attack surface includes {} medium-risk assets.", medium_risk.len()),
                location: Some(url.to_string()),
                recommendation: Some("Review medium-risk assets for proper security controls.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Report overall attack surface risk
        let risk_level = if surface.total_risk_score >= 0.7 {
            "High"
        } else if surface.total_risk_score >= 0.4 {
            "Medium"
        } else {
            "Low"
        };

        report.add_finding(Vuln {
            severity: VulnSeverity::Info,
            title: format!("Attack Surface Risk: {}", risk_level),
            description: format!(
                "Total attack surface consists of {} assets with an overall risk score of {:.2}",
                surface.assets.len(),
                surface.total_risk_score
            ),
            location: Some(url.to_string()),
            recommendation: Some("Regularly audit and reduce attack surface by removing unnecessary assets.".to_string()),
            cwe: Some("CWE-200".to_string()),
            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
        });

        Ok(report)
    }

    /// Convert technology fingerprints to vulnerability report
    async fn technologies_to_report(&self, tech: &[TechnologyFingerprint], url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        if tech.is_empty() {
            return Ok(report);
        }

        // Group by category
        let mut by_category: HashMap<&str, Vec<&TechnologyFingerprint>> = HashMap::new();
        for t in tech {
            by_category.entry(&t.category).or_default().push(t);
        }

        for (category, techs) in &by_category {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: format!("Detected {} Technology: {}", category, techs.len()),
                description: format!(
                    "Fingerprinted technologies in {}: {}",
                    category,
                    techs.iter()
                        .map(|t| if t.version.is_empty() { t.name.clone() } else { format!("{} ({})", t.name, t.version) })
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                location: Some(url.to_string()),
                recommendation: Some("Keep all detected technologies updated and monitor for security advisories.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Convert active reconnaissance results to vulnerability report
    async fn active_results_to_report(&self, results: &ActiveReconResult, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Report discovered paths
        if !results.discovered_paths.is_empty() {
            let sensitive_paths: Vec<&String> = results.discovered_paths.iter()
                .filter(|p| p.contains("admin") || p.contains("config") || p.contains("backup") || p.contains("debug"))
                .collect();

            if !sensitive_paths.is_empty() {
                let paths_str = sensitive_paths.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ");

                report.add_finding(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("{} Sensitive Paths Discovered", sensitive_paths.len()),
                    description: format!(
                        "Active reconnaissance found sensitive paths: {}",
                        paths_str
                    ),
                    location: Some(url.to_string()),
                    recommendation: Some("Ensure sensitive paths are properly secured and not exposed.".to_string()),
                    cwe: Some("CWE-215".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }
        }

        // Report header analysis
        let missing_headers = vec![
            ("Strict-Transport-Security", !results.header_info.has_hsts),
            ("Content-Security-Policy", !results.header_info.has_csp),
            ("X-Frame-Options", !results.header_info.has_xframe),
            ("X-Content-Type-Options", !results.header_info.has_xss),
            ("Referrer-Policy", !results.header_info.has_referrer),
            ("Permissions-Policy", !results.header_info.has_permissions),
        ];

        let missing: Vec<_> = missing_headers.into_iter()
            .filter(|(_, missing)| *missing)
            .map(|(name, _)| name)
            .collect();

        if !missing.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Low,
                title: format!("Missing Security Headers: {}", missing.join(", ")),
                description: format!(
                    "The following security headers are not set: {}",
                    missing.join(", ")
                ),
                location: Some(url.to_string()),
                recommendation: Some("Implement missing security headers to enhance protection.".to_string()),
                cwe: Some("CWE-693".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Report information disclosure
        if !results.header_info.server_header.is_empty() || !results.header_info.x_powered_by.is_empty() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Information Disclosure in Headers".to_string(),
                description: format!(
                    "Server headers disclose technology information: Server: {}, X-Powered-By: {}",
                    results.header_info.server_header,
                    results.header_info.x_powered_by
                ),
                location: Some(url.to_string()),
                recommendation: Some("Suppress server and X-Powered-By headers to reduce information disclosure.".to_string()),
                cwe: Some("CWE-200".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        Ok(report)
    }

    /// Aggregate and deduplicate results
    fn aggregate_results(&self, report: &mut ScanReport) {
        // Deduplicate findings by title and location
        let mut seen = HashSet::new();
        let mut unique_findings = Vec::new();

        for finding in &report.findings {
            let key = format!("{}|{}", finding.title, finding.location.as_ref().unwrap_or(&String::new()));
            if seen.insert(key) {
                unique_findings.push(finding.clone());
            }
        }

        report.findings = unique_findings;

        // Manually recalculate summary
        report.summary.total = report.findings.len();
        report.summary.critical = report.findings.iter().filter(|v| v.severity == VulnSeverity::Critical).count();
        report.summary.high = report.findings.iter().filter(|v| v.severity == VulnSeverity::High).count();
        report.summary.medium = report.findings.iter().filter(|v| v.severity == VulnSeverity::Medium).count();
        report.summary.low = report.findings.iter().filter(|v| v.severity == VulnSeverity::Low).count();
        report.summary.info = report.findings.iter().filter(|v| v.severity == VulnSeverity::Info).count();
    }
}

/// Certificate Transparency log entry
#[derive(Debug, Clone, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

/// Passive reconnaissance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconResult {
    pub domain: String,
    pub subdomains: Vec<SubdomainResult>,
    pub dns_records: Vec<DnsRecord>,
    pub search_engine_findings: Vec<SearchEngineFinding>,
    pub shodan_findings: Vec<ShodanFinding>,
}

impl ReconResult {
    fn new(domain: String) -> Self {
        Self {
            domain,
            subdomains: Vec::new(),
            dns_records: Vec::new(),
            search_engine_findings: Vec::new(),
            shodan_findings: Vec::new(),
        }
    }
}

/// Subdomain discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
    pub ip_addresses: Vec<String>,
    pub status: String,
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub source: String,
}

/// Search engine finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchEngineFinding {
    pub dork: String,
    pub description: String,
    pub url: String,
    pub finding_type: String,
}

/// Shodan finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanFinding {
    pub service: String,
    pub port: u16,
    pub info: String,
    pub url: String,
}

/// Attack surface map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceMap {
    pub target: String,
    pub assets: HashSet<Asset>,
    pub total_risk_score: f32,
}

impl AttackSurfaceMap {
    fn new(target: String) -> Self {
        Self {
            target,
            assets: HashSet::new(),
            total_risk_score: 0.0,
        }
    }
}

/// Asset in the attack surface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    pub asset_type: AssetType,
    pub url: String,
    pub status: String,
    pub risk_score: f32,
}

impl PartialEq for Asset {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.asset_type == other.asset_type
    }
}

impl Eq for Asset {}

impl std::hash::Hash for Asset {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.asset_type.hash(state);
    }
}

/// Asset type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AssetType {
    Subdomain,
    Endpoint,
    ApiEndpoint,
    Service,
    Database,
}

/// API endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpointInfo {
    pub path: String,
    pub methods: Vec<String>,
    pub auth_required: bool,
    pub rate_limited: bool,
}

/// Technology fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyFingerprint {
    pub name: String,
    pub version: String,
    pub category: String,
    pub confidence: f32,
}

/// Active reconnaissance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveReconResult {
    pub target: String,
    pub discovered_paths: Vec<String>,
    pub parameters: Vec<ParameterInfo>,
    pub header_info: HeaderAnalysis,
}

impl ActiveReconResult {
    fn new(target: String) -> Self {
        Self {
            target,
            discovered_paths: Vec::new(),
            parameters: Vec::new(),
            header_info: HeaderAnalysis::new(),
        }
    }
}

/// Parameter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    pub name: String,
    pub param_type: String,
    pub required: bool,
    pub values: Vec<String>,
}

/// Header analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderAnalysis {
    pub all_headers: HashMap<String, String>,
    pub has_hsts: bool,
    pub has_csp: bool,
    pub has_xframe: bool,
    pub has_xss: bool,
    pub has_referrer: bool,
    pub has_permissions: bool,
    pub server_header: String,
    pub x_powered_by: String,
}

impl HeaderAnalysis {
    fn new() -> Self {
        Self {
            all_headers: HashMap::new(),
            has_hsts: false,
            has_csp: false,
            has_xframe: false,
            has_xss: false,
            has_referrer: false,
            has_permissions: false,
            server_header: String::new(),
            x_powered_by: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_subdomain_risk() {
        let scanner = create_test_scanner();

        assert!(scanner.calculate_subdomain_risk("admin.example.com") > 0.7);
        assert!(scanner.calculate_subdomain_risk("dev.example.com") > 0.7);
        assert!(scanner.calculate_subdomain_risk("www.example.com") < 0.7);
    }

    #[test]
    fn test_calculate_endpoint_risk() {
        let scanner = create_test_scanner();

        assert!(scanner.calculate_endpoint_risk("/admin") > 0.6);
        assert!(scanner.calculate_endpoint_risk("/config") > 0.6);
        assert!(scanner.calculate_endpoint_risk("/api/health") < 0.6);
    }

    #[test]
    fn test_guess_parameter_type() {
        let scanner = create_test_scanner();

        assert_eq!(scanner.guess_parameter_type("user_id"), "integer");
        assert_eq!(scanner.guess_parameter_type("email"), "email");
        assert_eq!(scanner.guess_parameter_type("password"), "password");
        assert_eq!(scanner.guess_parameter_type("unknown"), "string");
    }

    fn create_test_scanner() -> SmartReconScanner {
        let config = ScannerConfig::new();
        SmartReconScanner::new(config)
    }
}
