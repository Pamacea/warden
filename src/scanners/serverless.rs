//! Serverless Security Scanner
//!
//! Detects security vulnerabilities in serverless functions across major cloud providers:
//! - AWS Lambda
//! - Azure Functions
//! - Google Cloud Functions
//!
//! Scans:
//! - Serverless configuration files (serverless.yml, serverless.json, template.yaml)
//! - Function code for injection vulnerabilities
//! - IAM roles and permissions
//! - Environment variable exposure
//! - Layer dependencies
//! - Timeout and memory configurations

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use regex::Regex;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Directories to exclude from serverless scanning
const EXCLUDED_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".idea",
    ".vscode",
    "coverage",
    ".next",
    ".nuxt",
    "out",
    ".terraform",
];

/// Serverless configuration files to scan
const SERVERLESS_CONFIGS: &[&str] = &[
    "serverless.yml",
    "serverless.yaml",
    "serverless.json",
    "template.yaml",
    "template.yml",
    "aws-sam.json",
    "serverless.ts",
    "serverless.js",
    "function.json",
    "host.json",
    "local.settings.json",
    "package.json", // For Azure Functions deployment
];

/// Function code extensions to scan
const FUNCTION_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", // Node.js
    "py", // Python
    "go", // Go
    "rb", // Ruby
    "java", // Java
    "cs", // C#
    "fs", // F#
];

/// Check if a path should be excluded from scanning
fn should_exclude_path(path: &Path) -> bool {
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .any(|component| EXCLUDED_DIRS.contains(&component))
}

pub struct ServerlessScanner {
    config: ScannerConfig,
}

impl ServerlessScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub async fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Scan serverless configuration files
        report.merge(self.scan_serverless_configs(path)?);

        // Scan function code for vulnerabilities
        report.merge(self.scan_function_code(path)?);

        // Scan for environment variable exposure
        report.merge(self.scan_environment_exposure(path)?);

        // Scan for IAM/role issues
        report.merge(self.scan_iam_roles(path)?);

        // Scan for layer/dependency issues
        report.merge(self.scan_layers(path)?);

        // Check timeout and memory configurations
        report.merge(self.scan_runtime_config(path)?);

        Ok(report)
    }

    /// Scan serverless configuration files
    fn scan_serverless_configs(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();
            let file_path = entry.path();

            // Check if it's a serverless config file
            if !SERVERLESS_CONFIGS.contains(&file_name.as_ref()) {
                continue;
            }

            let full_path = file_path.display().to_string();

            if let Ok(content) = fs::read_to_string(file_path) {
                // Analyze the config for security issues
                let findings = self.analyze_serverless_config(&content, &full_path, &file_name);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Analyze serverless configuration for security issues
    fn analyze_serverless_config(&self, content: &str, path: &str, filename: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // Check for exposed secrets in environment variables
        for (pattern_name, pattern) in self.get_secret_patterns() {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    findings.push(Vuln {
                        severity: VulnSeverity::Critical,
                        title: format!("Exposed Secret in {}: {}", filename, pattern_name),
                        description: format!(
                            "Potential {} exposed in serverless configuration",
                            pattern_name
                        ),
                        location: Some(path.to_string()),
                        recommendation: Some(
                            "Use environment variables from your cloud provider's secret management service. \
                            Never commit secrets to version control."
                                .to_string(),
                        ),
                        cwe: Some("CWE-798".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        // Check for overly permissive IAM roles
        if content.contains("iamRoleStatements")
            || content.contains("Role")
            || content.contains("IamRoleLambdaExecution")
        {
            // Check for wildcard permissions
            if (content.contains(r#"*"#) || content.contains(r#"*"#) || content.contains(r#"*""#))
                && (content.contains("Effect") || content.contains("Action"))
            {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Overly Permissive IAM Role in {}", filename),
                    description: "IAM role contains wildcard permissions. This grants excessive privileges to the Lambda function.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Use the principle of least privilege. Only grant specific permissions needed for the function. \
                        Avoid using '*' for actions or resources."
                            .to_string(),
                    ),
                    cwe: Some("CWE-269".to_string()),
                    owasp: Some("A01:2021 - Broken Access Control".to_string()),
                });
            }

            // Check for dangerous actions
            for dangerous_action in &[
                ("lambda:InvokeFunction", "Invoke arbitrary Lambda functions"),
                ("s3:*", "Full S3 access"),
                ("dynamodb:*", "Full DynamoDB access"),
                ("ec2:*", "Full EC2 access"),
                ("iam:*", "Full IAM access"),
                ("rds:*", "Full RDS access"),
                ("sns:*", "Full SNS access"),
                ("sqs:*", "Full SQS access"),
                ("kms:*", "Full KMS access"),
                ("secretsmanager:*", "Full Secrets Manager access"),
                ("ssm:*", "Full SSM access"),
            ] {
                if content.contains(dangerous_action.0) {
                    findings.push(Vuln {
                        severity: VulnSeverity::High,
                        title: format!("Dangerous IAM Permission in {}", filename),
                        description: format!("IAM role grants {} which may provide excessive access: {}", dangerous_action.0, dangerous_action.1),
                        location: Some(path.to_string()),
                        recommendation: Some(
                            "Restrict IAM permissions to specific resources and actions only. \
                            Use resource-level permissions where possible."
                                .to_string(),
                        ),
                        cwe: Some("CWE-269".to_string()),
                        owasp: Some("A01:2021 - Broken Access Control".to_string()),
                    });
                }
            }
        }

        // Check for disabled authentication
        if (content.contains("httpApi") || content.contains("http"))
            && (content.contains("authorizer: false")
                || content.contains("cors: true")
                || content.contains("public: true"))
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: format!("Potentially Unprotected API Endpoint in {}", filename),
                description: "HTTP endpoint may be exposed without proper authentication.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Enable proper authentication for all HTTP endpoints. \
                    Use API Gateway authorizers, Cognito, or custom auth."
                        .to_string(),
                ),
                cwe: Some("CWE-306".to_string()),
                owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            });
        }

        // Check for CORS misconfiguration
        if content.contains("cors:")
            || content.contains("allowedOrigins")
            || content.contains("allowed_origins")
        {
            if content.contains("*'") || content.contains("\"*\"") {
                findings.push(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("Overly Permissive CORS in {}", filename),
                    description: "CORS configuration allows all origins (*), potentially exposing the API to CSRF attacks.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Restrict CORS to specific trusted origins only. \
                        Avoid using wildcard (*) in production."
                            .to_string(),
                    ),
                    cwe: Some("CWE-942".to_string()),
                    owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                });
            }
        }

        // Check for excessive timeout
        if content.contains("timeout") {
            let timeout_re = Regex::new(r"timeout[:\s]+(\d+)").unwrap();
            for mat in timeout_re.captures_iter(content) {
                if let Some(timeout) = mat.get(1) {
                    if let Ok(value) = timeout.as_str().parse::<u32>() {
                        if value > 300 {
                            // 5 minutes
                            findings.push(Vuln {
                                severity: VulnSeverity::Medium,
                                title: format!("Excessive Timeout in {}", filename),
                                description: format!("Function timeout is set to {} seconds, which may allow DoS attacks.", value),
                                location: Some(path.to_string()),
                                recommendation: Some(
                                    "Set timeout to the minimum required for your function. \
                                    Typical timeouts are 3-30 seconds."
                                        .to_string(),
                                ),
                                cwe: Some("CWE-770".to_string()),
                                owasp: Some("A04:2021 - Insecure Design".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Check for excessive memory
        if content.contains("memorySize") || content.contains("memory_size") {
            let memory_re = Regex::new(r"memorySize?[:\s]+(\d+)").unwrap();
            for mat in memory_re.captures_iter(content) {
                if let Some(memory) = mat.get(1) {
                    if let Ok(value) = memory.as_str().parse::<u32>() {
                        if value > 2048 {
                            // 2GB
                            findings.push(Vuln {
                                severity: VulnSeverity::Low,
                                title: format!("High Memory Allocation in {}", filename),
                                description: format!("Function memory is set to {}MB, which may increase cost and attack surface.", value),
                                location: Some(path.to_string()),
                                recommendation: Some(
                                    "Use the minimum memory required for your function. \
                                    Monitor and optimize memory usage."
                                        .to_string(),
                                ),
                                cwe: Some("CWE-770".to_string()),
                                owasp: Some("A04:2021 - Insecure Design".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // Check for dead letter queue issues
        if content.contains("deadLetterArn")
            || content.contains("dead_letter_arn")
            || content.contains("onError")
        {
            // Check if DLQ points to an unencrypted resource
            findings.push(Vuln {
                severity: VulnSeverity::Info,
                title: format!("Dead Letter Queue Configured in {}", filename),
                description: "Dead letter queue is configured. Ensure it's encrypted and access-controlled.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Use encrypted SQS/SNS for DLQ. \
                    Restrict access to the DLQ to specific IAM roles only."
                        .to_string(),
                ),
                cwe: Some("CWE-311".to_string()),
                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }

        // Check for reserved concurrency issues
        if content.contains("reservedConcurrency") || content.contains("reserved_concurrency") {
            if content.contains("reservedConcurrency: 0")
                || content.contains("reserved_concurrency: 0")
            {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Reserved Concurrency Disabled in {}", filename),
                    description: "Reserved concurrency is set to 0, which may cause throttling or prevent function execution.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Set appropriate reserved concurrency based on your needs. \
                        Use it to prevent runaway functions and ensure capacity."
                            .to_string(),
                    ),
                    cwe: Some("CWE-770".to_string()),
                    owasp: Some("A04:2021 - Insecure Design".to_string()),
                });
            }
        }

        // Check for environment variable encryption (AWS)
        if content.contains("environment:")
            || content.contains("environmentVariables")
            || content.contains("environment_variables")
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: format!("Environment Variables in {}", filename),
                description: "Environment variables are defined. Ensure sensitive values use secrets manager references.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Use AWS Secrets Manager or Parameter Store for sensitive values. \
                    Use placeholder references like ${ssm:/path/to/param} or ${secretsmanager:secret}."
                        .to_string(),
                ),
                cwe: Some("CWE-312".to_string()),
                owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
            });
        }

        // AWS Lambda specific checks
        if filename.contains("template") || filename.contains("sam") {
            // Check for tracing disabled
            if content.contains("TracingConfig") && content.contains("PassThrough") {
                findings.push(Vuln {
                    severity: VulnSeverity::Medium,
                    title: format!("X-Ray Tracing Disabled in {}", filename),
                    description: "AWS X-Ray tracing is disabled, reducing observability for security incidents.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Enable X-Ray tracing (Active mode) for better observability and security monitoring."
                            .to_string(),
                    ),
                    cwe: Some("CWE-215".to_string()),
                    owasp: Some("A09:2021 - Security Logging and Monitoring Failures".to_string()),
                });
            }
        }

        // Azure Functions specific checks
        if filename == "host.json" || filename == "function.json" {
            // Check for extension bundles
            if content.contains("extensionBundle") {
                findings.push(Vuln {
                    severity: VulnSeverity::Info,
                    title: format!("Extension Bundle in {}", filename),
                    description: "Extension bundle is configured. Ensure it's from a trusted source and kept updated.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Pin extension bundle versions. Regularly update for security patches."
                            .to_string(),
                    ),
                    cwe: Some("CWE-937".to_string()),
                    owasp: Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
                });
            }

            // Check for function level authentication
            if content.contains("authLevel") && content.contains("anonymous") {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Anonymous Access in {}", filename),
                    description: "Function allows anonymous access, bypassing authentication.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Set authLevel to 'function' or 'admin'. Never use 'anonymous' in production."
                            .to_string(),
                    ),
                    cwe: Some("CWE-306".to_string()),
                    owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                });
            }
        }

        findings
    }

    /// Scan function code for injection vulnerabilities
    fn scan_function_code(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(8)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|s| FUNCTION_EXTENSIONS.contains(&s.to_string_lossy().as_ref()))
                    .unwrap_or(false)
            });

        for entry in entries {
            let file_path = entry.path();
            let file_path_str = file_path.display().to_string();

            // Skip if file is too large
            if let Ok(metadata) = file_path.metadata() {
                if metadata.len() > 500_000 {
                    // 500KB
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(file_path) {
                let findings = self.analyze_function_code(&content, &file_path_str);
                for vuln in findings {
                    report.add_finding(vuln);
                }
            }
        }

        Ok(report)
    }

    /// Analyze function code for security issues
    fn analyze_function_code(&self, content: &str, path: &str) -> Vec<Vuln> {
        let mut findings = Vec::new();

        // Check for eval() usage - code injection
        if content.contains("eval(") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "Code Injection Risk: eval()".to_string(),
                description: "Use of eval() allows arbitrary code execution. This is extremely dangerous in serverless functions.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Never use eval(). Use safer alternatives like JSON.parse(), object property access, or compile-time code generation."
                        .to_string(),
                ),
                cwe: Some("CWE-94".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for Function() constructor
        if content.contains("new Function(") {
            findings.push(Vuln {
                severity: VulnSeverity::Critical,
                title: "Code Injection Risk: Function Constructor".to_string(),
                description: "Use of Function() constructor allows arbitrary code execution.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Never use Function() constructor. Use arrow functions or standard function declarations."
                        .to_string(),
                ),
                cwe: Some("CWE-94".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for user input in command execution
        for cmd_pattern in &[
            ("execSync(", "child_process.execSync"),
            ("exec(", "child_process.exec"),
            ("spawn(", "child_process.spawn"),
            ("subprocess.", "Python subprocess module"),
            ("os.system(", "Python os.system"),
            ("os.popen(", "Python os.popen"),
            ("commands.", "Python commands module"),
        ] {
            if content.contains(cmd_pattern.0) {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Command Injection Risk: {}", cmd_pattern.1),
                    description: "Function may execute system commands with user input, leading to command injection.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Never pass user input directly to command execution. \
                        Use parameterized commands, input validation, and allow-lists."
                            .to_string(),
                    ),
                    cwe: Some("CWE-78".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }

        // Check for SQL injection patterns
        if content.contains(".query(")
            || content.contains(".execute(")
            || content.contains("SELECT * FROM")
            || content.contains("db.query")
            || content.contains("db.execute")
            || content.contains("client.query")
        {
            // Look for string concatenation in queries
            if content.contains("' + ")
                || content.contains("\" + ")
                || content.contains("' + ")
                || content.contains("format(")
                || content.contains("f\"")
            {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: "SQL Injection Risk".to_string(),
                    description: "SQL queries may be constructed with string concatenation, leading to SQL injection.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Use parameterized queries or prepared statements. \
                        Never concatenate user input into SQL queries."
                            .to_string(),
                    ),
                    cwe: Some("CWE-89".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }

        // Check for NoSQL injection
        if content.contains("MongoClient")
            || content.contains("mongodb://")
            || content.contains(".find({")
        {
            if content.contains("eval:") || content.contains("$where:") {
                findings.push(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "NoSQL Injection Risk: $where operator".to_string(),
                    description: "MongoDB queries using $where or eval operators are vulnerable to NoSQL injection.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Never use $where or eval operators. Use strict query operators and validate all input."
                            .to_string(),
                    ),
                    cwe: Some("CWE-943".to_string()),
                    owasp: Some("A03:2021 - Injection".to_string()),
                });
            }
        }

        // Check for path traversal
        if content.contains("fs.readFile")
            || content.contains("fs.readFileSync")
            || content.contains("open(")
            || content.contains("Path.join(")
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "Path Traversal Risk".to_string(),
                description: "Function may read files based on user input, potentially leading to path traversal.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Validate and sanitize file paths. Use a allow-list of permitted files. \
                    Never use user input directly in file paths."
                        .to_string(),
                ),
                cwe: Some("CWE-22".to_string()),
                owasp: Some("A01:2021 - Broken Access Control".to_string()),
            });
        }

        // Check for SSRF
        if content.contains("axios.get(")
            || content.contains("fetch(")
            || content.contains("http.get(")
            || content.contains("https.get(")
            || content.contains("requests.get(")
            || content.contains("urllib")
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "SSRF Risk".to_string(),
                description: "Function makes HTTP requests based on user input, potentially leading to SSRF attacks.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Validate and restrict URLs. Use an allow-list of permitted domains. \
                    Disable redirects to internal resources."
                        .to_string(),
                ),
                cwe: Some("CWE-918".to_string()),
                owasp: Some("A10:2021 - Server-Side Request Forgery".to_string()),
            });
        }

        // Check for XXE (XML External Entity)
        if content.contains("libxmljs")
            || content.contains("xml2js")
            || content.contains("expat")
            || content.contains("lxml")
            || content.contains("xml.etree")
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "XXE Risk".to_string(),
                description: "Function processes XML without disabling external entities, potentially vulnerable to XXE attacks.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Disable external entities and DTD processing. Use secure XML parsers."
                        .to_string(),
                ),
                cwe: Some("CWE-611".to_string()),
                owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
            });
        }

        // Check for deserialization issues
        if content.contains("JSON.parse(")
            || content.contains("pickle.loads")
            || content.contains("yaml.load")
            || content.contains("marshal.loads")
        {
            // Check for unsafe YAML
            if content.contains("yaml.load(") && !content.contains("yaml.safeLoad") {
                findings.push(Vuln {
                    severity: VulnSeverity::High,
                    title: "Unsafe Deserialization: YAML.load".to_string(),
                    description: "Use of yaml.load() without safeLoad is vulnerable to arbitrary code execution.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Use yaml.safeLoad() or yaml.load() with SafeLoader. Never load untrusted YAML."
                            .to_string(),
                    ),
                    cwe: Some("CWE-502".to_string()),
                    owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
                });
            }

            // Check for unsafe pickle
            if content.contains("pickle.loads") || content.contains("pickle.load") {
                findings.push(Vuln {
                    severity: VulnSeverity::Critical,
                    title: "Unsafe Deserialization: Pickle".to_string(),
                    description: "Python pickle module can execute arbitrary code when deserializing untrusted data.".to_string(),
                    location: Some(path.to_string()),
                    recommendation: Some(
                        "Never use pickle with untrusted data. Use JSON or safer serialization formats."
                            .to_string(),
                    ),
                    cwe: Some("CWE-502".to_string()),
                    owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
                });
            }
        }

        // Check for template injection (SSTI)
        if content.contains("render(")
            || content.contains("render_template(")
            || content.contains("ejs.render")
            || content.contains("handlebars.compile")
            || content.contains("pug.render")
        {
            findings.push(Vuln {
                severity: VulnSeverity::High,
                title: "Template Injection Risk".to_string(),
                description: "Function renders templates with user input, potentially vulnerable to SSTI.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Never use user input as template names or in template expressions. \
                    Use context variables for data passing."
                        .to_string(),
                ),
                cwe: Some("CWE-94".to_string()),
                owasp: Some("A03:2021 - Injection".to_string()),
            });
        }

        // Check for hardcoded secrets in code
        for (pattern_name, pattern) in self.get_secret_patterns() {
            if let Ok(re) = Regex::new(pattern) {
                for mat in re.find_iter(content) {
                    findings.push(Vuln {
                        severity: VulnSeverity::Critical,
                        title: format!("Hardcoded Secret: {}", pattern_name),
                        description: format!("Potential {} hardcoded in function code", pattern_name),
                        location: Some(path.to_string()),
                        recommendation: Some(
                            "Remove hardcoded credentials. Use environment variables or secret management services."
                                .to_string(),
                        ),
                        cwe: Some("CWE-798".to_string()),
                        owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
                    });
                }
            }
        }

        // Check for logging of sensitive data
        if (content.contains("console.log(")
            || content.contains("console.error(")
            || content.contains("print(")
            || content.contains("logger.info")
            || content.contains("logger.debug"))
            && (content.contains("password")
                || content.contains("token")
                || content.contains("secret")
                || content.contains("api_key")
                || content.contains("apikey"))
        {
            findings.push(Vuln {
                severity: VulnSeverity::Medium,
                title: "Potential Sensitive Data Logging".to_string(),
                description: "Function may log sensitive data like passwords, tokens, or secrets.".to_string(),
                location: Some(path.to_string()),
                recommendation: Some(
                    "Never log sensitive data. Use structured logging with data redaction."
                        .to_string(),
                ),
                cwe: Some("CWE-532".to_string()),
                owasp: Some("A09:2021 - Security Logging and Monitoring Failures".to_string()),
            });
        }

        findings
    }

    /// Scan for environment variable exposure
    fn scan_environment_exposure(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Check for .env files
        let entries = WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();

            if file_name.starts_with(".env") || file_name.contains("env.") {
                let full_path = entry.path().display().to_string();
                report.add_finding(Vuln {
                    severity: VulnSeverity::High,
                    title: format!("Environment File: {}", file_name),
                    description: format!(
                        "File {} may contain sensitive environment variables",
                        full_path
                    ),
                    location: Some(full_path),
                    recommendation: Some(
                        "Ensure .env files are excluded from version control. \
                        Use cloud provider secret management for serverless functions."
                            .to_string(),
                    ),
                    cwe: Some("CWE-312".to_string()),
                    owasp: Some("A02:2021 - Cryptographic Failures".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Scan for IAM role issues
    fn scan_iam_roles(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();
            let file_path = entry.path();

            // Check IAM policy files
            if file_name.contains("policy")
                || file_name.contains("iam")
                || file_name.contains("role")
                || file_name.ends_with(".json")
            {
                if let Ok(content) = fs::read_to_string(file_path) {
                    let full_path = file_path.display().to_string();

                    // Check for wildcard permissions
                    if content.contains("\"Effect\": \"Allow\"")
                        && content.contains("\"Action\": \"*\"")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: format!("Wildcard IAM Permission in {}", file_name),
                            description: "IAM policy grants all actions (*), providing excessive privileges.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Restrict to specific actions only. Use the principle of least privilege."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-269".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }

                    // Check for wildcard resources
                    if content.contains("\"Resource\": \"*\"") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: format!("Wildcard Resource in {}", file_name),
                            description: "IAM policy applies to all resources (*), potentially exceeding intended scope.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Specify exact resource ARNs. Use wildcards only when necessary and safe."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-269".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }

                    // Check for PassRole permission
                    if content.contains("iam:PassRole") && content.contains("\"Resource\": \"*\"") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Critical,
                            title: format!("Unrestricted PassRole in {}", file_name),
                            description: "iam:PassRole with wildcard resource allows privilege escalation.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Restrict iam:PassRole to specific role ARNs only."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-269".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Scan for layer/dependency issues
    fn scan_layers(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        // Check for layers directory
        let layers_dir = path.join("layers");
        if layers_dir.exists() {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Lambda Layers Detected".to_string(),
                description: "Custom Lambda layers found. Ensure layers are scanned for vulnerabilities and kept updated.".to_string(),
                location: Some(layers_dir.display().to_string()),
                recommendation: Some(
                    "Regularly scan layer dependencies for vulnerabilities. \
                    Use dependency scanning tools and keep layers updated."
                        .to_string(),
                ),
                cwe: Some("CWE-937".to_string()),
                owasp: Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
            });
        }

        // Check for requirements files in layer contexts
        let entries = WalkDir::new(path)
            .max_depth(4)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();

            if file_name == "requirements.txt"
                || file_name == "Pipfile"
                || file_name == "poetry.lock"
                || file_name == "package.json"
                || file_name == "package-lock.json"
                || file_name == "yarn.lock"
                || file_name == "pnpm-lock.yaml"
                || file_name == "go.mod"
                || file_name == "go.sum"
            {
                let full_path = entry.path().display().to_string();

                report.add_finding(Vuln {
                    severity: VulnSeverity::Info,
                    title: format!("Dependency File: {}", file_name),
                    description: format!(
                        "Dependency file found at {}. Run dependency scanning for vulnerabilities.",
                        full_path
                    ),
                    location: Some(full_path),
                    recommendation: Some(
                        "Use 'warden scan dependencies' to check for known vulnerabilities."
                            .to_string(),
                    ),
                    cwe: Some("CWE-937".to_string()),
                    owasp: Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
                });
            }
        }

        Ok(report)
    }

    /// Scan runtime configuration issues
    fn scan_runtime_config(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Path(path.to_path_buf()));

        let entries = WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| !should_exclude_path(e.path()))
            .filter(|e| e.file_type().is_file());

        for entry in entries {
            let file_name = entry.file_name().to_string_lossy();
            let file_path = entry.path();

            if SERVERLESS_CONFIGS.contains(&file_name.as_ref()) {
                if let Ok(content) = fs::read_to_string(file_path) {
                    let full_path = file_path.display().to_string();

                    // Check for missing timeout (defaults to 6 seconds, but explicit is better)
                    if !content.contains("timeout") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("Missing Timeout in {}", file_name),
                            description: "No explicit timeout configured. Function will use default timeout.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Set an explicit timeout appropriate for your function's needs."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-770".to_string()),
                            owasp: Some("A04:2021 - Insecure Design".to_string()),
                        });
                    }

                    // Check for missing memory size
                    if !content.contains("memorySize") && !content.contains("memory_size") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("Missing Memory Size in {}", file_name),
                            description: "No explicit memory size configured. Function will use default memory.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Set an explicit memory size appropriate for your function's needs."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-770".to_string()),
                            owasp: Some("A04:2021 - Insecure Design".to_string()),
                        });
                    }

                    // Check for production stage issues
                    if content.contains("stage: prod")
                        || content.contains("stage: production")
                        || content.contains("STAGE: prod")
                    {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Info,
                            title: format!("Production Stage in {}", file_name),
                            description: "Production stage detected. Ensure all security settings are properly configured.".to_string(),
                            location: Some(full_path.clone()),
                            recommendation: Some(
                                "Review security settings for production: enable tracing, encryption, and proper authentication."
                                    .to_string(),
                            ),
                            cwe: Some("CWE-215".to_string()),
                            owasp: Some("A09:2021 - Security Logging and Monitoring Failures".to_string()),
                        });
                    }
                }
            }
        }

        Ok(report)
    }

    /// Get regex patterns for detecting secrets
    fn get_secret_patterns(&self) -> Vec<(&'static str, &'static str)> {
        vec![
            ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
            ("AWS Secret Key", r"\b[A-Za-z0-9/+=]{40}\b"),
            ("Stripe API Key", r"\bsk_(live|test)_[a-zA-Z0-9]{24,}\b"),
            ("Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            ("GitHub Token", r"\bghp_[a-zA-Z0-9]{36}\b"),
            ("Slack Token", r"\bxox[baprs]-[0-9]-[0-9]{10}-[0-9]{10}-[a-zA-Z0-9]{24}\b"),
            ("Private Key", r"-----BEGIN [A-Z]+ PRIVATE KEY-----"),
            ("API Key", r#"(?i)api[_-]?key[\s"'=:]{1,5}["']?[a-zA-Z0-9_\-]{20,}"#),
            ("Secret Key", r#"(?i)secret[_-]?key[\s"'=:]{1,5}["']?[a-zA-Z0-9_\-]{20,}"#),
            ("Connection String", r#"(?i)(mongodb|mysql|postgres|redis)://[^\s"'<>]{10,}"#),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serverless_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = ServerlessScanner::new(config);
        assert_eq!(scanner.config.aggressive, false);
    }

    #[test]
    fn test_should_exclude_path() {
        assert!(should_exclude_path(Path::new("node_modules/test.js")));
        assert!(should_exclude_path(Path::new(".git/test.yml")));
        assert!(!should_exclude_path(Path::new("src/handler.js")));
    }

    #[test]
    fn test_serverless_configs() {
        assert!(SERVERLESS_CONFIGS.contains(&"serverless.yml"));
        assert!(SERVERLESS_CONFIGS.contains(&"template.yaml"));
        assert!(SERVERLESS_CONFIGS.contains(&"host.json"));
    }

    #[test]
    fn test_function_extensions() {
        assert!(FUNCTION_EXTENSIONS.contains(&"js"));
        assert!(FUNCTION_EXTENSIONS.contains(&"py"));
        assert!(FUNCTION_EXTENSIONS.contains(&"go"));
    }

    #[test]
    fn test_secret_patterns() {
        let config = ScannerConfig::new();
        let scanner = ServerlessScanner::new(config);
        let patterns = scanner.get_secret_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|(name, _)| name.contains("AWS")));
    }
}
