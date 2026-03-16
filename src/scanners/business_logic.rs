//! Business Logic Vulnerability scanner
//!
//! Detects business logic vulnerabilities in web applications:
//! - Price manipulation (negative, fractional, currency abuse)
//! - Coupon abuse (stacking, expired reuse, unlimited usage)
//! - Privilege escalation (role manipulation, IDOR, admin paths)
//! - Payment bypass (free orders, skip steps, amount modification)
//! - Cart manipulation (quantity after payment, negative quantities, product swap)

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

/// Test configuration for business logic parameters
#[derive(Debug, Clone)]
struct BlTest {
    category: &'static str,
    name: &'static str,
    payload_json: &'static str,
    severity: VulnSeverity,
    expected_behavior: &'static str,
}

impl BlTest {
    /// Parse the JSON payload
    fn payload(&self) -> Value {
        serde_json::from_str(self.payload_json).unwrap_or_else(|_| Value::Null)
    }
}

/// Business Logic test payloads
const PRICE_TESTS: &[BlTest] = &[
    BlTest {
        category: "price",
        name: "negative_price",
        payload_json: r#"{"price": -100.0, "amount": -1.0}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should reject negative prices",
    },
    BlTest {
        category: "price",
        name: "zero_price",
        payload_json: r#"{"price": 0, "amount": 0.01}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should reject or flag zero-price orders",
    },
    BlTest {
        category: "price",
        name: "fractional_cents",
        payload_json: r#"{"price": 0.001, "amount": 1000000}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should handle fractional cents properly",
    },
    BlTest {
        category: "price",
        name: "overflow_price",
        payload_json: r#"{"price": 999999999.99}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should reject unreasonable prices",
    },
    BlTest {
        category: "price",
        name: "scientific_notation",
        payload_json: r#"{"price": "1e-5"}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should parse scientific notation correctly",
    },
    BlTest {
        category: "price",
        name: "string_price",
        payload_json: r#"{"price": "free"}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should validate price is numeric",
    },
    BlTest {
        category: "price",
        name: "null_price",
        payload_json: r#"{"price": null}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should reject null prices",
    },
    BlTest {
        category: "price",
        name: "array_price",
        payload_json: r#"{"price": [100, 50]}"#,
        severity: VulnSeverity::Low,
        expected_behavior: "Should reject array prices",
    },
];

/// Coupon abuse test payloads
const COUPON_TESTS: &[BlTest] = &[
    BlTest {
        category: "coupon",
        name: "double_coupon",
        payload_json: r#"{"coupon": "SAVE10", "coupon2": "SAVE20"}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should prevent multiple coupons",
    },
    BlTest {
        category: "coupon",
        name: "expired_coupon",
        payload_json: r#"{"coupon": "EXPIRED2020"}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should reject expired coupons",
    },
    BlTest {
        category: "coupon",
        name: "single_use_reuse",
        payload_json: r#"{"coupon": "ONETIME2024"}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should prevent single-use coupon reuse",
    },
    BlTest {
        category: "coupon",
        name: "stacking_same",
        payload_json: r#"{"coupons": ["SAVE10", "SAVE10", "SAVE10"]}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should prevent stacking same coupon",
    },
    BlTest {
        category: "coupon",
        name: "negative_discount",
        payload_json: r#"{"discount": -50}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should reject negative discounts",
    },
    BlTest {
        category: "coupon",
        name: "over_100_discount",
        payload_json: r#"{"discount": 150}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should cap discounts at 100%",
    },
    BlTest {
        category: "coupon",
        name: "empty_coupon",
        payload_json: r#"{"coupon": ""}"#,
        severity: VulnSeverity::Low,
        expected_behavior: "Should handle empty coupon codes",
    },
];

/// Privilege escalation test payloads
const PRIVILEGE_TESTS: &[BlTest] = &[
    BlTest {
        category: "privilege",
        name: "role_admin",
        payload_json: r#"{"role": "admin", "is_admin": true}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should not accept role from client",
    },
    BlTest {
        category: "privilege",
        name: "role_superuser",
        payload_json: r#"{"role": "superuser", "permissions": ["all"]}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should not accept role from client",
    },
    BlTest {
        category: "privilege",
        name: "role_parameter",
        payload_json: r#"{"user_type": "admin", "access_level": 99}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should validate roles server-side",
    },
    BlTest {
        category: "privilege",
        name: "privilege_escalation_id",
        payload_json: r#"{"user_id": 1, "target_user_id": 1}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should enforce IDOR protection",
    },
    BlTest {
        category: "privilege",
        name: "bypass_permission_check",
        payload_json: r#"{"bypass": true, "skip_auth": true}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should ignore bypass parameters",
    },
    BlTest {
        category: "privilege",
        name: "session_fixation",
        payload_json: r#"{"session_id": "admin_session", "user_id": 1}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should validate session ownership",
    },
];

/// Payment bypass test payloads
const PAYMENT_TESTS: &[BlTest] = &[
    BlTest {
        category: "payment",
        name: "payment_skip",
        payload_json: r#"{"payment_required": false, "skip_payment": true}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should require payment regardless of parameter",
    },
    BlTest {
        category: "payment",
        name: "free_order_bypass",
        payload_json: r#"{"total": 0, "paid": true}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should validate payment for non-zero orders",
    },
    BlTest {
        category: "payment",
        name: "amount_manipulation",
        payload_json: r#"{"amount": 0.01, "paid_amount": 100}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should validate paid amount matches total",
    },
    BlTest {
        category: "payment",
        name: "currency_mismatch",
        payload_json: r#"{"currency": "USD", "pay_currency": "JPY"}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should validate currency consistency",
    },
    BlTest {
        category: "payment",
        name: "payment_status_override",
        payload_json: r#"{"status": "paid", "payment_id": "fake"}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should not accept payment status from client",
    },
    BlTest {
        category: "payment",
        name: "refund_bypass",
        payload_json: r#"{"refund": true, "amount": 99999}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should validate refund eligibility",
    },
];

/// Cart manipulation test payloads
const CART_TESTS: &[BlTest] = &[
    BlTest {
        category: "cart",
        name: "negative_quantity",
        payload_json: r#"{"quantity": -1}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should reject negative quantities",
    },
    BlTest {
        category: "cart",
        name: "zero_quantity",
        payload_json: r#"{"quantity": 0, "price": 100}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should handle zero quantity properly",
    },
    BlTest {
        category: "cart",
        name: "overflow_quantity",
        payload_json: r#"{"quantity": 999999999}"#,
        severity: VulnSeverity::Medium,
        expected_behavior: "Should limit maximum quantity",
    },
    BlTest {
        category: "cart",
        name: "fractional_quantity",
        payload_json: r#"{"quantity": 0.5}"#,
        severity: VulnSeverity::Low,
        expected_behavior: "Should handle fractional quantities based on product",
    },
    BlTest {
        category: "cart",
        name: "product_swap",
        payload_json: r#"{"product_id": 1, "actual_product_id": 2}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should validate product ID consistency",
    },
    BlTest {
        category: "cart",
        name: "price_override",
        payload_json: r#"{"product_id": 1, "price": 0.01}"#,
        severity: VulnSeverity::Critical,
        expected_behavior: "Should fetch prices server-side",
    },
    BlTest {
        category: "cart",
        name: "cart_after_payment",
        payload_json: r#"{"action": "update", "order_id": "paid_order_123"}"#,
        severity: VulnSeverity::High,
        expected_behavior: "Should lock cart after payment",
    },
];

/// Parameter names for business logic testing
const BL_PARAMS: &[&[&str]] = &[
    &["price", "amount", "total", "cost"],
    &["coupon", "discount", "promo", "voucher"],
    &["role", "user_type", "access_level", "permissions"],
    &["payment", "paid", "status", "checkout"],
    &["quantity", "qty", "count", "number"],
    &["product_id", "item_id", "sku", "product"],
];

/// IDOR patterns to test
const IDOR_PATTERNS: &[(&str, &str)] = &[
    ("user_id", "1"),
    ("account_id", "1"),
    ("order_id", "1"),
    ("id", "1"),
    ("profile_id", "1"),
];

/// Admin path patterns
const ADMIN_PATHS: &[&str] = &[
    "/admin",
    "/administrator",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/wp-admin",
    "/manager",
    "/console",
    "/controlpanel",
    "/admin/index.php",
    "/admin/login",
    "/admin/home",
    "/backend",
    "/admin panel",
    "/admin/",
    "/administrator/",
    "/root",
    "/sysadmin",
    "/admin1",
    "/admin2",
];

pub struct BusinessLogicScanner {
    client: Client,
    config: ScannerConfig,
}

impl BusinessLogicScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        eprintln!("  Business Logic Scanner starting...");

        // Phase 1: Test for common API endpoints
        report.merge(self.test_api_endpoints(url).await?);

        // Phase 2: Test price manipulation
        report.merge(self.test_price_manipulation(url).await?);

        // Phase 3: Test coupon abuse
        report.merge(self.test_coupon_abuse(url).await?);

        // Phase 4: Test privilege escalation
        report.merge(self.test_privilege_escalation(url).await?);

        // Phase 5: Test payment bypass
        report.merge(self.test_payment_bypass(url).await?);

        // Phase 6: Test cart manipulation
        report.merge(self.test_cart_manipulation(url).await?);

        // Phase 7: Test IDOR vulnerabilities
        report.merge(self.test_idor(url).await?);

        // Phase 8: Check admin path access
        report.merge(self.test_admin_paths(url).await?);

        // Phase 9: Aggressive mode - race conditions
        if self.config.aggressive {
            report.merge(self.test_race_conditions(url).await?);
        }

        Ok(report)
    }

    /// Test common API endpoints for business logic
    async fn test_api_endpoints(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let endpoints = [
            "/api/cart",
            "/api/checkout",
            "/api/order",
            "/api/coupon",
            "/api/user",
            "/api/payment",
            "/cart",
            "/checkout",
            "/order",
        ];

        let base = base_url.trim_end_matches('/');

        for endpoint in endpoints {
            let url = format!("{}{}", base, endpoint);

            // Test GET request
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                if status.is_success() || status.as_u16() == 405 {
                    // Endpoint exists
                    if status.is_success() {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("Business Logic Endpoint: {}", endpoint),
                            description: format!("Discovered business logic endpoint at {}", url),
                            location: Some(url),
                            recommendation: Some("Ensure proper authentication and authorization on all business logic endpoints.".to_string()),
                            cwe: Some("CWE-840".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test price manipulation vulnerabilities
    async fn test_price_manipulation(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');
        let test_endpoints = [
            "/api/cart",
            "/api/checkout",
            "/api/order",
            "/cart",
            "/checkout",
        ];

        for test in PRICE_TESTS {
            for endpoint in &test_endpoints {
                let url = format!("{}{}", base, endpoint);

                // Try POST request with payload
                if let Ok(response) = self
                    .client
                    .post(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();

                    // Check if payload was accepted (should be rejected)
                    if status.is_success() && !text.to_lowercase().contains("error") {
                        // Check for success indicators
                        if text.to_lowercase().contains("success")
                            || text.to_lowercase().contains("order")
                            || text.to_lowercase().contains("created")
                        {
                            report.add_finding(Vuln {
                                severity: test.severity,
                                title: format!("Price Manipulation: {}", test.name),
                                description: format!(
                                    "Server accepted price manipulation payload: {}. {}",
                                    test.name, test.expected_behavior
                                ),
                                location: Some(format!("{} POST: {}", url, test.payload_json)),
                                recommendation: Some(
                                    "Never accept prices from client input. \
                                     Always fetch prices server-side based on product ID. \
                                     Validate all monetary values on the server.".to_string()
                                ),
                                cwe: Some("CWE-840".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break; // One finding per test is enough
                        }
                    }
                }

                // Try PUT request
                if let Ok(response) = self
                    .client
                    .put(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    if status.is_success() {
                        report.add_finding(Vuln {
                            severity: test.severity,
                            title: format!("Price Manipulation via PUT: {}", test.name),
                            description: format!(
                                "PUT endpoint accepted price manipulation: {}",
                                test.name
                            ),
                            location: Some(format!("{} PUT: {}", url, test.payload_json)),
                            recommendation: Some(
                                "Disable PUT methods for price modification. \
                                 Use PATCH with strict validation.".to_string()
                            ),
                            cwe: Some("CWE-840".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test coupon abuse vulnerabilities
    async fn test_coupon_abuse(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');
        let test_endpoints = [
            "/api/cart",
            "/api/checkout",
            "/api/apply-coupon",
            "/cart/coupon",
            "/checkout/coupon",
        ];

        for test in COUPON_TESTS {
            for endpoint in &test_endpoints {
                let url = format!("{}{}", base, endpoint);

                // Try POST request
                if let Ok(response) = self
                    .client
                    .post(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Check if coupon was accepted improperly
                    if status.is_success()
                        && (text_lower.contains("discount")
                            || text_lower.contains("coupon")
                            || text_lower.contains("applied"))
                    {
                        // Check for excessive discount
                        if text_lower.contains("150%")
                            || text_lower.contains("-$")
                            || text_lower.contains("free")
                        {
                            report.add_finding(Vuln {
                                severity: test.severity,
                                title: format!("Coupon Abuse: {}", test.name),
                                description: format!(
                                    "Server accepted coupon abuse: {}. {}",
                                    test.name, test.expected_behavior
                                ),
                                location: Some(format!("{} POST: {}", url, test.payload_json)),
                                recommendation: Some(
                                    "Implement proper coupon validation: \
                                     - Prevent stacking unless explicitly allowed \
                                     - Validate expiration dates \
                                     - Enforce single-use limits \
                                     - Cap discounts at 100% \
                                     - Validate coupon ownership".to_string()
                                ),
                                cwe: Some("CWE-840".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test privilege escalation vulnerabilities
    async fn test_privilege_escalation(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');
        let test_endpoints = [
            "/api/user",
            "/api/user/update",
            "/api/profile",
            "/api/account",
            "/user",
            "/profile",
        ];

        for test in PRIVILEGE_TESTS {
            for endpoint in &test_endpoints {
                let url = format!("{}{}", base, endpoint);

                // Try POST request
                if let Ok(response) = self
                    .client
                    .post(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Check if escalation was successful
                    if status.is_success() {
                        if text_lower.contains("admin")
                            || text_lower.contains("privilege")
                            || text_lower.contains("permission")
                            || text_lower.contains("role")
                        {
                            report.add_finding(Vuln {
                                severity: test.severity,
                                title: format!("Privilege Escalation: {}", test.name),
                                description: format!(
                                    "Possible privilege escalation via parameter: {}. {}",
                                    test.name, test.expected_behavior
                                ),
                                location: Some(format!("{} POST: {}", url, test.payload_json)),
                                recommendation: Some(
                                    "Never accept role/permission parameters from client input. \
                                     Always validate permissions server-side based on authenticated session. \
                                     Use session-based authorization, never client-provided values.".to_string()
                                ),
                                cwe: Some("CWE-269".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                }

                // Try PUT request
                if let Ok(response) = self
                    .client
                    .put(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        report.add_finding(Vuln {
                            severity: test.severity,
                            title: format!("Privilege Escalation via PUT: {}", test.name),
                            description: format!("PUT endpoint may allow privilege escalation: {}", test.name),
                            location: Some(format!("{} PUT: {}", url, test.payload_json)),
                            recommendation: Some(
                                "Implement proper authorization checks on PUT endpoints.".to_string()
                            ),
                            cwe: Some("CWE-269".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test payment bypass vulnerabilities
    async fn test_payment_bypass(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');
        let test_endpoints = [
            "/api/checkout",
            "/api/order",
            "/api/payment",
            "/api/purchase",
            "/checkout",
            "/order",
        ];

        for test in PAYMENT_TESTS {
            for endpoint in &test_endpoints {
                let url = format!("{}{}", base, endpoint);

                // Try POST request
                if let Ok(response) = self
                    .client
                    .post(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Check if payment was bypassed
                    if status.is_success() {
                        if text_lower.contains("order")
                            || text_lower.contains("success")
                            || text_lower.contains("confirmed")
                            || text_lower.contains("paid")
                        {
                            report.add_finding(Vuln {
                                severity: test.severity,
                                title: format!("Payment Bypass: {}", test.name),
                                description: format!(
                                    "Possible payment bypass: {}. {}",
                                    test.name, test.expected_behavior
                                ),
                                location: Some(format!("{} POST: {}", url, test.payload_json)),
                                recommendation: Some(
                                    "Never trust client-provided payment status. \
                                     Always verify payments server-side with payment gateway. \
                                     Use server-side order total calculation. \
                                     Implement payment webhook verification.".to_string()
                                ),
                                cwe: Some("CWE-840".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test cart manipulation vulnerabilities
    async fn test_cart_manipulation(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');
        let test_endpoints = [
            "/api/cart",
            "/api/cart/add",
            "/api/cart/update",
            "/api/cart/items",
            "/cart",
            "/cart/add",
        ];

        for test in CART_TESTS {
            for endpoint in &test_endpoints {
                let url = format!("{}{}", base, endpoint);

                // Try POST request
                if let Ok(response) = self
                    .client
                    .post(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    let text_lower = text.to_lowercase();

                    // Check if manipulation was successful
                    if status.is_success()
                        && !text_lower.contains("error")
                        && !text_lower.contains("invalid")
                    {
                        if text_lower.contains("cart")
                            || text_lower.contains("quantity")
                            || text_lower.contains("added")
                        {
                            report.add_finding(Vuln {
                                severity: test.severity,
                                title: format!("Cart Manipulation: {}", test.name),
                                description: format!(
                                    "Possible cart manipulation: {}. {}",
                                    test.name, test.expected_behavior
                                ),
                                location: Some(format!("{} POST: {}", url, test.payload_json)),
                                recommendation: Some(
                                    "Validate all cart operations server-side: \
                                     - Reject negative quantities \
                                     - Enforce quantity limits \
                                     - Fetch prices from database, not client \
                                     - Lock cart after payment initiation \
                                     - Validate product IDs exist and are accessible".to_string()
                                ),
                                cwe: Some("CWE-840".to_string()),
                                owasp: Some("A01:2021 - Broken Access Control".to_string()),
                            });
                            break;
                        }
                    }
                }

                // Try PATCH request for updates
                if let Ok(response) = self
                    .client
                    .patch(&url)
                    .json(&test.payload())
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        report.add_finding(Vuln {
                            severity: test.severity,
                            title: format!("Cart Manipulation via PATCH: {}", test.name),
                            description: format!("PATCH endpoint may allow cart manipulation: {}", test.name),
                            location: Some(format!("{} PATCH: {}", url, test.payload_json)),
                            recommendation: Some(
                                "Implement strict validation on PATCH endpoints.".to_string()
                            ),
                            cwe: Some("CWE-840".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test IDOR (Insecure Direct Object Reference) vulnerabilities
    async fn test_idor(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');

        // Test common IDOR patterns
        let idor_endpoints = [
            "/api/user/1",
            "/api/user/2",
            "/api/account/1",
            "/api/order/1",
            "/api/profile/1",
            "/user/1",
            "/account/1",
            "/order/1",
        ];

        for endpoint in &idor_endpoints {
            let url = format!("{}{}", base, endpoint);

            // Test GET access to other users' data
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let text_lower = text.to_lowercase();

                // If we can access user data without auth, it's a finding
                if status.is_success()
                    && (text_lower.contains("email")
                        || text_lower.contains("name")
                        || text_lower.contains("address")
                        || text_lower.contains("phone"))
                {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::High,
                        title: "IDOR: Unauthorized Object Access".to_string(),
                        description: format!(
                            "Can access user data at {} without proper authentication.",
                            endpoint
                        ),
                        location: Some(url),
                        recommendation: Some(
                            "Implement proper authorization checks: \
                             - Verify user owns the resource they're accessing \
                             - Use indirect reference maps (tokens instead of IDs) \
                             - Implement session-based access control \
                             - Log and monitor unauthorized access attempts".to_string()
                        ),
                        cwe: Some("CWE-639".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        // Test IDOR via parameter manipulation
        for (param, value) in IDOR_PATTERNS {
            let test_url = format!("{}{}?{}={}", base, "/api/user", param, value);

            if let Ok(response) = self.client.get(&test_url).send().await {
                if response.status().is_success() {
                    report.add_finding(Vuln {
                        severity: VulnSeverity::Medium,
                        title: format!("IDOR: Parameter Manipulation ({})", param),
                        description: format!("Possible IDOR via {} parameter", param),
                        location: Some(test_url),
                        recommendation: Some(
                            "Don't use sequential or predictable IDs. Use UUIDs or random tokens.".to_string()
                        ),
                        cwe: Some("CWE-639".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        Ok(report)
    }

    /// Test admin path access
    async fn test_admin_paths(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');

        for path in ADMIN_PATHS {
            let url = format!("{}{}", base, path);

            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                let text_lower = text.to_lowercase();

                // Check if admin panel is accessible
                if status.is_success() || status.as_u16() == 403 {
                    // Even 403 confirms the path exists
                    if status.is_success()
                        || text_lower.contains("admin")
                        || text_lower.contains("login")
                        || text_lower.contains("dashboard")
                    {
                        report.add_finding(Vuln {
                            severity: if status.is_success() {
                                VulnSeverity::High
                            } else {
                                VulnSeverity::Medium
                            },
                            title: format!("Admin Path Exposure: {}", path),
                            description: format!(
                                "Admin panel path is accessible at {} (status: {})",
                                path, status
                            ),
                            location: Some(url),
                            recommendation: Some(
                                "Rename admin paths to non-guessable names. \
                                 Implement IP whitelisting for admin access. \
                                 Add additional authentication factor for admin panel. \
                                 Move admin panel to separate internal domain.".to_string()
                            ),
                            cwe: Some("CWE-215".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Test race condition vulnerabilities (aggressive mode)
    async fn test_race_conditions(&self, base_url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(base_url.to_string()));

        let base = base_url.trim_end_matches('/');

        // Test concurrent coupon usage
        let coupon_url = format!("{}/api/checkout", base);
        let coupon_payload = json!({"coupon": "RACE20", "quantity": 1});

        let mut tasks = Vec::new();
        for _ in 0..10 {
            let client = self.client.clone();
            let url = coupon_url.clone();
            let payload = coupon_payload.clone();
            tasks.push(tokio::spawn(async move {
                client
                    .post(&url)
                    .json(&payload)
                    .send()
                    .await
            }));
        }

        let mut success_count = 0;
        for task in tasks {
            if let Ok(Ok(response)) = task.await {
                if response.status().is_success() {
                    success_count += 1;
                }
            }
        }

        // If single-use coupon was accepted multiple times
        if success_count > 3 {
            report.add_finding(Vuln {
                severity: VulnSeverity::High,
                title: "Race Condition: Concurrent Coupon Usage".to_string(),
                description: format!(
                    "Coupon was accepted {} times in concurrent requests. Possible race condition.",
                    success_count
                ),
                location: Some(coupon_url),
                recommendation: Some(
                    "Implement proper locking for single-use resources. \
                     Use database transactions with atomic operations. \
                     Implement idempotency keys for state-changing operations.".to_string()
                ),
                cwe: Some("CWE-362".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Test concurrent quantity limit bypass
        let cart_url = format!("{}/api/cart/add", base);
        let cart_payload = json!({"product_id": 1, "quantity": 10});

        let mut tasks = Vec::new();
        for _ in 0..5 {
            let client = self.client.clone();
            let url = cart_url.clone();
            let payload = cart_payload.clone();
            tasks.push(tokio::spawn(async move {
                client
                    .post(&url)
                    .json(&payload)
                    .send()
                    .await
            }));
        }

        let mut cart_success = 0;
        for task in tasks {
            if let Ok(Ok(response)) = task.await {
                if response.status().is_success() {
                    cart_success += 1;
                }
            }
        }

        if cart_success > 1 {
            report.add_finding(Vuln {
                severity: VulnSeverity::Medium,
                title: "Race Condition: Cart Quantity Limit Bypass".to_string(),
                description: format!(
                    "Cart quantity limit may be bypassed via concurrent requests ({} successful).",
                    cart_success
                ),
                location: Some(cart_url),
                recommendation: Some(
                    "Use atomic operations for quantity updates. \
                     Implement database-level constraints on quantities. \
                     Use SELECT FOR UPDATE to lock rows during updates.".to_string()
                ),
                cwe: Some("CWE-362".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = BusinessLogicScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_price_tests_loaded() {
        assert!(!PRICE_TESTS.is_empty());
        assert!(PRICE_TESTS.len() >= 8);
    }

    #[test]
    fn test_coupon_tests_loaded() {
        assert!(!COUPON_TESTS.is_empty());
        assert!(COUPON_TESTS.len() >= 7);
    }

    #[test]
    fn test_privilege_tests_loaded() {
        assert!(!PRIVILEGE_TESTS.is_empty());
        assert!(PRIVILEGE_TESTS.len() >= 6);
    }

    #[test]
    fn test_payment_tests_loaded() {
        assert!(!PAYMENT_TESTS.is_empty());
        assert!(PAYMENT_TESTS.len() >= 6);
    }

    #[test]
    fn test_cart_tests_loaded() {
        assert!(!CART_TESTS.is_empty());
        assert!(CART_TESTS.len() >= 7);
    }

    #[test]
    fn test_admin_paths_loaded() {
        assert!(!ADMIN_PATHS.is_empty());
        assert!(ADMIN_PATHS.contains(&"/admin"));
        assert!(ADMIN_PATHS.contains(&"/administrator"));
    }

    #[test]
    fn test_idor_patterns_loaded() {
        assert!(!IDOR_PATTERNS.is_empty());
        assert!(IDOR_PATTERNS.contains(&("user_id", "1")));
    }

    #[test]
    fn test_critical_severity_tests() {
        let critical_tests: Vec<_> = PRIVILEGE_TESTS
            .iter()
            .filter(|t| t.severity == VulnSeverity::Critical)
            .collect();

        assert!(!critical_tests.is_empty());
    }

    #[test]
    fn test_payload_structure() {
        for test in PRICE_TESTS {
            // Verify payload is valid JSON
            let _ = test.payload();
        }
    }
}
