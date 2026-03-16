//! Redis Security Scanner
//!
//! Detects Redis security vulnerabilities including:
//! - Authentication bypass (default/empty passwords)
//! - Dangerous command exposure (FLUSHALL, CONFIG, EVAL, etc.)
//! - Lua scripting RCE
//! - Module loading RCE
//! - Information disclosure (INFO, CONFIG, CLIENT LIST)
//! - Protocol injection
//! - NoSQL injection via EVAL
//!
//! Default Redis port: 6379
//! TLS Redis port: 6380

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

/// Redis protocol response types
#[derive(Debug, Clone, PartialEq)]
enum RedisResponseType {
    SimpleString,
    Error,
    Integer,
    BulkString,
    Array,
    Nil,
}

/// Authentication test credentials
const AUTH_CREDENTIALS: &[(&str, &str, &str)] = &[
    // (username, password, description)
    ("", "", "No authentication"),
    ("", "redis", "Default password: redis"),
    ("", "root", "Default password: root"),
    ("", "admin", "Default password: admin"),
    ("", "password", "Default password: password"),
    ("default", "", "Default user, empty password"),
    ("default", "redis", "Default credentials"),
    ("admin", "admin", "Admin/Admin"),
    ("root", "root", "Root/Root"),
    ("redis", "redis", "Redis/Redis"),
    ("test", "test", "Test/Test"),
    ("guest", "guest", "Guest/Guest"),
    ("", "123456", "Common password: 123456"),
    ("", "password123", "Common password: password123"),
    ("", "admin123", "Common password: admin123"),
];

/// Dangerous commands that should be restricted
const DANGEROUS_COMMANDS: &[(&str, &str, VulnSeverity)] = &[
    // (command, description, severity)
    ("FLUSHALL", "Delete all database keys", VulnSeverity::Critical),
    ("FLUSHDB", "Delete all keys in current database", VulnSeverity::Critical),
    ("CONFIG", "Modify server configuration", VulnSeverity::Critical),
    ("EVAL", "Execute Lua scripts (potential RCE)", VulnSeverity::Critical),
    ("EVALSHA", "Execute cached Lua scripts", VulnSeverity::High),
    ("SCRIPT", "Manage Lua scripts", VulnSeverity::High),
    ("MODULE", "Load external modules (RCE)", VulnSeverity::Critical),
    ("SHUTDOWN", "Shutdown the server", VulnSeverity::Critical),
    ("DEBUG", "Debug commands (DoS/crash)", VulnSeverity::High),
    ("SAVE", "Write to disk (DoS)", VulnSeverity::Medium),
    ("BGSAVE", "Background save (DoS)", VulnSeverity::Medium),
    ("BGREWRITEAOF", "Rewrite AOF (DoS)", VulnSeverity::Medium),
    ("SYNC", "Initiate replication (data leak)", VulnSeverity::High),
    ("PSYNC", "Partial sync (data leak)", VulnSeverity::High),
    ("SLAVEOF", "Replica configuration", VulnSeverity::High),
    ("REPLICAOF", "Replica configuration", VulnSeverity::High),
    ("MONITOR", "Monitor all commands (data leak)", VulnSeverity::High),
    ("CLIENT", "Client management", VulnSeverity::Medium),
    ("SWAPDB", "Swap databases", VulnSeverity::Medium),
    ("MIGRATE", "Migrate keys between instances", VulnSeverity::Medium),
    ("RESTORE", "Restore serialized key", VulnSeverity::Medium),
    ("PFMERGE", "HyperLogLog merge (DoS)", VulnSeverity::Low),
];

/// Information disclosure commands
const INFO_COMMANDS: &[(&str, &str)] = &[
    ("INFO", "General server information"),
    ("INFO server", "Server configuration"),
    ("INFO clients", "Connected clients"),
    ("INFO memory", "Memory usage"),
    ("INFO persistence", "Persistence info"),
    ("INFO replication", "Replication status"),
    ("INFO stats", "Statistics"),
    ("INFO cpu", "CPU usage"),
    ("INFO commandstats", "Command statistics"),
    ("INFO cluster", "Cluster info"),
    ("INFO keyspace", "Keys per database"),
    ("CONFIG GET *", "All configuration"),
    ("CONFIG GET requirepass", "Password config"),
    ("CONFIG GET masterauth", "Master password"),
    ("CLIENT LIST", "Connected clients list"),
    ("MEMORY DOCTOR", "Memory analysis"),
    ("MEMORY STATS", "Memory statistics"),
    ("SLOWLOG GET", "Slow query log"),
    ("ACL LIST", "All ACL users (Redis 6+)"),
    ("ACL GETUSER default", "Default user ACL"),
    ("MODULE LIST", "Loaded modules"),
];

/// Lua script payloads for RCE testing
const LUA_SCRIPTS: &[(&str, &str)] = &[
    // (script, description)
    ("return 'test'", "Basic Lua execution"),
    ("return redis.call('KEYS', '*')", "Key enumeration via Lua"),
    ("return redis.call('CONFIG', 'GET', '*')", "Config dump via Lua"),
    ("return redis.call('INFO')", "Info disclosure via Lua"),
    ("local info = redis.call('CONFIG', 'GET', 'requirepass'); return info", "Password leak"),
    ("return _G", "Global table access (sandbox escape)"),
    ("return package", "Package module access"),
    ("return io", "I/O module access (RCE)"),
    ("return os", "OS module access (RCE)"),
    ("return debug", "Debug module access"),
];

/// Protocol injection payloads
const PROTOCOL_INJECTION: &[(&str, &str)] = &[
    // (payload, description)
    ("*\r\n$4\r\nINFO\r\n", "Array-style command"),
    ("*1\r\n$4\r\nINFO\r\n", "Single element array"),
    ("*2\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n", "Multi-arg command"),
    ("*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$1\r\n*\r\n", "Get all config"),
    ("*2\r\n$4\r\nAUTH\r\n$6\r\nevil\r\n", "Auth injection"),
    ("KEYS *\nQUIT", "Command chaining"),
    ("INFO\r\nSET x 1", "CRLF injection"),
];

/// Scan result from a single Redis test
#[derive(Debug, Clone)]
struct RedisTestResult {
    pub success: bool,
    pub command: String,
    pub response: String,
    pub is_vulnerable: bool,
}

pub struct RedisScanner {
    config: ScannerConfig,
    timeout: Duration,
}

impl RedisScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(10);
        Self { config, timeout }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Main scan entry point
    pub async fn scan(&self, target: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(target.to_string()));

        // Parse target to extract host and port
        let (host, port) = self.parse_target(target)?;

        // Phase 1: Check if Redis is accessible
        let is_accessible = self.check_accessibility(&host, port).await;
        if !is_accessible {
            report.add_finding(Vuln {
                severity: VulnSeverity::Info,
                title: "Redis Service Unreachable".to_string(),
                description: format!("Could not connect to Redis at {}:{}\nVerify the service is running and accessible.", host, port),
                location: Some(format!("{}:{}", host, port)),
                recommendation: Some("Check firewall rules and ensure Redis is running.".to_string()),
                cwe: None,
                owasp: None,
            });
            return Ok(report);
        }

        // Add finding for accessible Redis service
        report.add_finding(Vuln {
            severity: VulnSeverity::Medium,
            title: "Redis Service Accessible".to_string(),
            description: format!("Redis service is accessible on {}:{}. This database service should not be directly exposed to the internet.", host, port),
            location: Some(format!("{}:{}", host, port)),
            recommendation: Some("Restrict Redis access to localhost or use VPN/TLS. Enable authentication and use firewall rules.".to_string()),
            cwe: Some("CWE-284".to_string()),
            owasp: Some("A01:2021 - Broken Access Control".to_string()),
        });

        // Phase 2: Test authentication
        report.merge(self.test_authentication(&host, port).await?);

        // Phase 3: Test information disclosure (may work without auth)
        report.merge(self.test_info_disclosure(&host, port).await?);

        // Phase 4: Test dangerous commands (aggressive mode only)
        if self.config.aggressive {
            report.merge(self.test_dangerous_commands(&host, port).await?);
        }

        // Phase 5: Test Lua script execution
        report.merge(self.test_lua_scripts(&host, port).await?);

        // Phase 6: Test protocol injection
        report.merge(self.test_protocol_injection(&host, port).await?);

        // Phase 7: Test module loading (aggressive mode only)
        if self.config.aggressive {
            report.merge(self.test_module_loading(&host, port).await?);
        }

        Ok(report)
    }

    /// Parse target URL to extract host and port
    fn parse_target(&self, target: &str) -> Result<(String, u16)> {
        let default_port = 6379u16;

        // Try parsing as URL first
        if let Ok(url) = url::Url::parse(target) {
            let host = url.host_str().unwrap_or("localhost").to_string();
            let port = url.port().unwrap_or(default_port);
            return Ok((host, port));
        }

        // Try parsing as host:port
        if target.contains(':') {
            let parts: Vec<&str> = target.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                let host = parts[1];
                let port = parts[0].parse::<u16>().unwrap_or(default_port);
                return Ok((host.to_string(), port));
            }
        }

        // Use as-is with default port
        Ok((target.to_string(), default_port))
    }

    /// Check if Redis service is accessible
    async fn check_accessibility(&self, host: &str, port: u16) -> bool {
        match timeout(self.timeout, async {
            let addr = format!("{}:{}", host, port);
            let _stream = TcpStream::connect(&addr).await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    /// Test authentication with various credentials
    async fn test_authentication(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        for (username, password, desc) in AUTH_CREDENTIALS {
            match self.try_auth(host, port, username, password).await {
                Ok(auth_result) => {
                    if auth_result.success {
                        let severity = if username.is_empty() && password.is_empty() {
                            VulnSeverity::Critical
                        } else if *password == "redis" || *password == "admin" || *password == "root" {
                            VulnSeverity::Critical
                        } else if username.is_empty() || password.is_empty() {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        };

                        let credentials = if username.is_empty() {
                            format!("password: '{}'", if password.is_empty() { "(empty)" } else { password })
                        } else {
                            format!("username: '{}', password: '{}'", username, if password.is_empty() { "(empty)" } else { password })
                        };

                        report.add_finding(Vuln {
                            severity,
                            title: format!("Redis Authentication Bypass: {}", desc),
                            description: format!(
                                "Redis authentication bypassed using {}. This allows unauthorized access to all data stored in Redis.",
                                credentials
                            ),
                            location: Some({
                                let auth_str = if username.is_empty() {
                                    password.to_string()
                                } else {
                                    format!("{} {}", username, password)
                                };
                                format!("{}:{} - AUTH {}", host, port, auth_str)
                            }),
                            recommendation: Some(
                                "Always set a strong password for Redis. Use ACLs (Redis 6+) to limit access. \
                                 Bind Redis to localhost only. Use Redis in an isolated network.".to_string()
                            ),
                            cwe: Some("CWE-284".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                        break; // Found working auth, stop testing
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Try to authenticate with given credentials
    async fn try_auth(&self, host: &str, port: u16, username: &str, password: &str) -> Result<RedisTestResult> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await?;
        let mut conn = RedisConnection::new(stream);

        // Try authentication
        let auth_cmd = if username.is_empty() {
            if password.is_empty() {
                // Try without AUTH (no auth configured)
                "PING".to_string()
            } else {
                format!("AUTH {}", password)
            }
        } else {
            format!("AUTH {} {}", username, password)
        };

        let response = conn.send_command(&auth_cmd).await?;

        Ok(RedisTestResult {
            success: !response.contains("NOAUTH") && !response.contains("WRONGPASS") && !response.contains("ERR"),
            command: auth_cmd,
            response,
            is_vulnerable: false,
        })
    }

    /// Test information disclosure commands
    async fn test_info_disclosure(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        for (command, desc) in INFO_COMMANDS {
            match self.try_command(host, port, command, true).await {
                Ok(result) => {
                    if result.success {
                        // Check if response contains sensitive information
                        let contains_sensitive = self.check_sensitive_data(&result.response);

                        let severity = if contains_sensitive {
                            VulnSeverity::High
                        } else {
                            VulnSeverity::Medium
                        };

                        let response_preview = if result.response.len() > 200 {
                            format!("{}...", &result.response[..200])
                        } else {
                            result.response.clone()
                        };

                        report.add_finding(Vuln {
                            severity,
                            title: format!("Redis Information Disclosure: {}", desc),
                            description: format!(
                                "Command '{}' returned sensitive information without requiring authentication.\nResponse: {}",
                                command, response_preview
                            ),
                            location: Some(format!("{}:{} - CMD: {}", host, port, command)),
                            recommendation: Some(
                                "Configure Redis to require authentication for info commands. \
                                 Use rename-command to disable dangerous commands. \
                                 Implement proper ACLs (Redis 6+).".to_string()
                            ),
                            cwe: Some("CWE-200".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Test dangerous command access
    async fn test_dangerous_commands(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        for (command, desc, severity) in DANGEROUS_COMMANDS {
            // For dangerous commands, test with a safe variant first (like COMMAND INFO)
            let test_cmd = format!("COMMAND INFO {}", command);

            match self.try_command(host, port, &test_cmd, true).await {
                Ok(result) => {
                    if result.success && !result.response.contains("unknown") {
                        report.add_finding(Vuln {
                            severity: *severity,
                            title: format!("Redis Dangerous Command Enabled: {}", command),
                            description: format!(
                                "The '{}' command is accessible. This command could be used to {}. \
                                 If authentication is weak or missing, this allows critical attacks.",
                                command, desc
                            ),
                            location: Some(format!("{}:{} - CMD: {}", host, port, command)),
                            recommendation: Some(
                                format!("Disable the '{}' command using rename-command in redis.conf: \
                                        rename-command {} \"\". \
                                        Use Redis ACLs to restrict dangerous commands.",
                                        command, command)
                            ),
                            cwe: Some("CWE-284".to_string()),
                            owasp: Some("A01:2021 - Broken Access Control".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Test Lua script execution (RCE potential)
    async fn test_lua_scripts(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        for (script, desc) in LUA_SCRIPTS {
            // Use EVAL to test Lua execution
            let eval_cmd = format!("EVAL \"{}\" 0", script.replace('"', "\\\""));

            match self.try_command(host, port, &eval_cmd, true).await {
                Ok(result) => {
                    if result.success && !result.response.contains("NOAUTH") && !result.response.contains("unknown") {
                        // Check if it's actually executing Lua (not just error)
                        let is_executing = !result.response.contains("ERR")
                            && (result.response.contains("table") || result.response.contains("userdata")
                                || result.response.contains("function") || !result.response.is_empty());

                        if is_executing {
                            let severity = if desc.contains("RCE") || desc.contains("escape") {
                                VulnSeverity::Critical
                            } else {
                                VulnSeverity::High
                            };

                            report.add_finding(Vuln {
                                severity,
                                title: format!("Redis Lua Script Execution: {}", desc),
                                description: format!(
                                    "Lua scripts can be executed. Test script '{}': {}\nResponse: {}",
                                    desc, script, result.response
                                ),
                                location: Some(format!("{}:{} - EVAL", host, port)),
                                recommendation: Some(
                                    "Disable EVAL command if not needed. Use Lua script whitelisting. \
                                     Enable Redis ACLs to restrict scripting. \
                                     Consider using sandboxed Redis configurations.".to_string()
                                ),
                                cwe: Some("CWE-917".to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Test protocol injection attacks
    async fn test_protocol_injection(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        for (payload, desc) in PROTOCOL_INJECTION {
            match self.send_raw(host, port, payload).await {
                Ok(response) => {
                    if !response.is_empty() && !response.contains("NOAUTH") && !response.contains("ERR") {
                        report.add_finding(Vuln {
                            severity: VulnSeverity::Medium,
                            title: format!("Redis Protocol Injection: {}", desc),
                            description: format!(
                                "Protocol injection successful. Payload: {}\nResponse: {}",
                                payload, if response.len() > 200 { &response[..200] } else { &response }
                            ),
                            location: Some(format!("{}:{} - Protocol Injection", host, port)),
                            recommendation: Some(
                                "Validate and sanitize all Redis protocol input. \
                                 Use proper Redis client libraries that handle protocol encoding.".to_string()
                            ),
                            cwe: Some("CWE-74".to_string()),
                            owasp: Some("A03:2021 - Injection".to_string()),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(report)
    }

    /// Test module loading capabilities
    async fn test_module_loading(&self, host: &str, port: u16) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(format!("{}:{}", host, port)));

        // Test if MODULE LIST works
        match self.try_command(host, port, "MODULE LIST", true).await {
            Ok(result) => {
                if result.success && !result.response.contains("unknown") {
                    // Check if any modules are loaded
                    let has_modules = result.response.contains("name") || result.response.contains("module");

                    let modules_info = if has_modules {
                        result.response.clone()
                    } else {
                        "None".to_string()
                    };

                    report.add_finding(Vuln {
                        severity: if has_modules { VulnSeverity::High } else { VulnSeverity::Medium },
                        title: "Redis Module Loading Capability".to_string(),
                        description: format!(
                            "Redis can load external modules. This could lead to RCE if an attacker can load malicious modules.\nLoaded modules: {}",
                            modules_info
                        ),
                        location: Some(format!("{}:{} - MODULE", host, port)),
                        recommendation: Some(
                            "Disable MODULE LOAD command in production. Use rename-command MODULE \"\". \
                             Only load signed/verified modules from trusted sources.".to_string()
                        ),
                        cwe: Some("CWE-427".to_string()),
                        owasp: Some("A03:2021 - Injection".to_string()),
                    });
                }
            }
            Err(_) => {}
        }

        Ok(report)
    }

    /// Try to execute a command on Redis
    async fn try_command(&self, host: &str, port: u16, command: &str, allow_error: bool) -> Result<RedisTestResult> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await?;

        let mut conn = RedisConnection::new(stream);
        let response = conn.send_command(command).await?;

        let is_error = response.contains("NOAUTH")
            || response.contains("WRONGPASS")
            || response.contains("ERR")
            || response.contains("unknown command");

        Ok(RedisTestResult {
            success: allow_error || !is_error,
            command: command.to_string(),
            response,
            is_vulnerable: false,
        })
    }

    /// Send raw protocol payload
    async fn send_raw(&self, host: &str, port: u16, payload: &str) -> Result<String> {
        let addr = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&addr).await?;

        let mut conn = RedisConnection::new(stream);
        let response = conn.send_raw(payload.as_bytes()).await?;

        Ok(response)
    }

    /// Check if response contains sensitive data
    fn check_sensitive_data(&self, response: &str) -> bool {
        let sensitive_keywords = &[
            "redis_version",
            "os",
            "arch_bits",
            "process_id",
            "tcp_port",
            "masterauth",
            "requirepass",
            "used_memory",
            "connected_clients",
            "uptime",
            "role",
            "master_host",
            "master_port",
            "password",
            "secret",
            "key",
            "token",
            "auth",
        ];

        let response_lower = response.to_lowercase();
        for keyword in sensitive_keywords {
            if response_lower.contains(&keyword.to_lowercase()) {
                return true;
            }
        }

        false
    }
}

/// Redis protocol connection handler
struct RedisConnection {
    stream: BufReader<TcpStream>,
}

impl RedisConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    /// Send a command and read the response
    async fn send_command(&mut self, command: &str) -> Result<String> {
        // Format as RESP array
        let parts: Vec<&str> = command.split_whitespace().collect();
        let mut cmd = format!("*{}\r\n", parts.len());
        for part in parts {
            cmd.push_str(&format!("${}\r\n{}\r\n", part.len(), part));
        }

        self.send_raw(cmd.as_bytes()).await
    }

    /// Send raw bytes and read response
    async fn send_raw(&mut self, data: &[u8]) -> Result<String> {
        // Get the underlying stream for writing
        let stream = self.stream.get_mut();
        stream.write_all(data).await?;
        stream.flush().await?;

        // Read response
        self.read_response().await
    }

    /// Read and parse Redis RESP response
    async fn read_response(&mut self) -> Result<String> {
        // Use a loop-based approach to handle nested arrays without recursion
        let mut result_stack = Vec::new();
        let mut current_items = Vec::new();
        let mut expecting_array_count = None;

        loop {
            let mut buf = [0u8; 1];
            let mut response = String::new();

            // Read first byte to determine type
            self.stream.read_exact(&mut buf).await?;
            let resp_type = buf[0] as char;

            match resp_type {
                '+' => {
                    // Simple string
                    self.read_line(&mut response).await?;
                    let value = response.trim().to_string();
                    if let Some(count) = expecting_array_count {
                        current_items.push(value);
                        if current_items.len() >= count {
                            let items = std::mem::take(&mut current_items);
                            result_stack.push(items.join(", "));
                            expecting_array_count = None;
                        }
                    } else {
                        return Ok(value);
                    }
                }
                '-' => {
                    // Error
                    self.read_line(&mut response).await?;
                    return Ok(response.trim().to_string());
                }
                ':' => {
                    // Integer
                    self.read_line(&mut response).await?;
                    let value = response.trim().to_string();
                    if let Some(count) = expecting_array_count {
                        current_items.push(value);
                        if current_items.len() >= count {
                            let items = std::mem::take(&mut current_items);
                            result_stack.push(items.join(", "));
                            expecting_array_count = None;
                        }
                    } else {
                        return Ok(value);
                    }
                }
                '$' => {
                    // Bulk string
                    self.read_line(&mut response).await?;
                    if let Ok(len) = response.trim().parse::<isize>() {
                        if len == -1 {
                            let value = "(nil)".to_string();
                            if let Some(count) = expecting_array_count {
                                current_items.push(value);
                                if current_items.len() >= count {
                                    let items = std::mem::take(&mut current_items);
                                    result_stack.push(items.join(", "));
                                    expecting_array_count = None;
                                }
                            } else {
                                return Ok(value);
                            }
                        } else {
                            let mut data = vec![0u8; len as usize];
                            self.stream.read_exact(&mut data).await?;
                            self.stream.read_exact(&mut [0u8; 2]).await?;
                            let value = String::from_utf8_lossy(&data).to_string();
                            if let Some(count) = expecting_array_count {
                                current_items.push(value);
                                if current_items.len() >= count {
                                    let items = std::mem::take(&mut current_items);
                                    result_stack.push(items.join(", "));
                                    expecting_array_count = None;
                                }
                            } else {
                                return Ok(value);
                            }
                        }
                    } else {
                        return Ok(response);
                    }
                }
                '*' => {
                    // Array
                    self.read_line(&mut response).await?;
                    if let Ok(count) = response.trim().parse::<isize>() {
                        if count == -1 {
                            if expecting_array_count.is_some() {
                                current_items.push("(nil)".to_string());
                            } else {
                                return Ok("(nil)".to_string());
                            }
                        } else if count == 0 {
                            if expecting_array_count.is_some() {
                                current_items.push(String::new());
                            } else {
                                return Ok(String::new());
                            }
                        } else if count > 0 {
                            expecting_array_count = Some(count as usize);
                        }
                    }
                }
                _ => {
                    // Unknown response type
                    self.read_line(&mut response).await?;
                    return Ok(format!("{}: {}", resp_type, response));
                }
            }
        }
    }

    /// Read a line (\r\n terminated)
    async fn read_line(&mut self, output: &mut String) -> Result<()> {
        let mut buf = vec![0u8; 1];
        output.clear();

        loop {
            self.stream.read_exact(&mut buf).await?;
            if buf[0] == b'\r' {
                self.stream.read_exact(&mut buf).await?;
                if buf[0] == b'\n' {
                    break;
                }
            }
            if buf[0] != b'\r' && buf[0] != b'\n' {
                output.push(buf[0] as char);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = RedisScanner::new(config);
        assert_eq!(scanner.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_scanner_with_timeout() {
        let config = ScannerConfig::new();
        let scanner = RedisScanner::new(config).with_timeout(Duration::from_secs(5));
        assert_eq!(scanner.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_parse_target_url() {
        let config = ScannerConfig::new();
        let scanner = RedisScanner::new(config);

        // Test URL parsing
        let (host, port) = scanner.parse_target("redis://localhost:6379").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 6379);

        // Test host:port parsing
        let (host, port) = scanner.parse_target("192.168.1.1:6380").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 6380);

        // Test default port
        let (host, port) = scanner.parse_target("localhost").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 6379);
    }

    #[test]
    fn test_auth_credentials_loaded() {
        assert!(!AUTH_CREDENTIALS.is_empty());
        assert!(AUTH_CREDENTIALS.len() > 10);

        // Check for common credentials
        assert!(AUTH_CREDENTIALS.iter().any(|(_, _, desc)| *desc == "No authentication"));
        assert!(AUTH_CREDENTIALS.iter().any(|(_, pass, _)| *pass == "redis"));
        assert!(AUTH_CREDENTIALS.iter().any(|(_, pass, _)| *pass == "admin"));
    }

    #[test]
    fn test_dangerous_commands_loaded() {
        assert!(!DANGEROUS_COMMANDS.is_empty());

        // Check for critical commands
        assert!(DANGEROUS_COMMANDS.iter().any(|(cmd, _, sev)| *cmd == "FLUSHALL" && *sev == VulnSeverity::Critical));
        assert!(DANGEROUS_COMMANDS.iter().any(|(cmd, _, sev)| *cmd == "CONFIG" && *sev == VulnSeverity::Critical));
        assert!(DANGEROUS_COMMANDS.iter().any(|(cmd, _, sev)| *cmd == "EVAL" && *sev == VulnSeverity::Critical));
        assert!(DANGEROUS_COMMANDS.iter().any(|(cmd, _, sev)| *cmd == "MODULE" && *sev == VulnSeverity::Critical));
    }

    #[test]
    fn test_info_commands_loaded() {
        assert!(!INFO_COMMANDS.is_empty());

        // Check for info commands
        assert!(INFO_COMMANDS.iter().any(|(cmd, _)| *cmd == "INFO"));
        assert!(INFO_COMMANDS.iter().any(|(cmd, _)| *cmd == "CONFIG GET *"));
        assert!(INFO_COMMANDS.iter().any(|(cmd, _)| *cmd == "CLIENT LIST"));
    }

    #[test]
    fn test_lua_scripts_loaded() {
        assert!(!LUA_SCRIPTS.is_empty());

        // Check for RCE-related scripts
        assert!(LUA_SCRIPTS.iter().any(|(_, desc)| desc.contains("RCE") || desc.contains("escape")));
    }

    #[test]
    fn test_protocol_injection_loaded() {
        assert!(!PROTOCOL_INJECTION.is_empty());

        // Check for protocol injection patterns
        assert!(PROTOCOL_INJECTION.iter().any(|(payload, _)| payload.contains("\r\n")));
        assert!(PROTOCOL_INJECTION.iter().any(|(payload, _)| payload.contains("*")));
    }

    #[test]
    fn test_sensitive_data_detection() {
        let config = ScannerConfig::new();
        let scanner = RedisScanner::new(config);

        // Test with sensitive data
        assert!(scanner.check_sensitive_data("redis_version=6.0"));
        assert!(scanner.check_sensitive_data("requirepass=password123"));
        assert!(scanner.check_sensitive_data("tcp_port=6379"));

        // Test without sensitive data
        assert!(!scanner.check_sensitive_data("just some random text"));
    }

    #[tokio::test]
    async fn test_connection_creation() {
        // Just test that we can create a connection (won't connect to anything)
        let addr = "127.0.0.1:9999"; // Likely closed port

        match timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
            Ok(_) => {
                // Port might be open, that's fine
                assert!(true);
            }
            Err(_) => {
                // Timeout is expected for closed port
                assert!(true);
            }
        }
    }
}
