# Warden Security Scan Report

> **AI Agent Instructions:** This report is structured for systematic security fixes.
> Each finding includes file path, line numbers, and actionable recommendations.

**Target:** .
**Scan Time:** 2026-03-22T18:09:30.069014400+00:00
**Warden Version:** 0.8.2

## 📊 Scan Summary

| Severity | Count | Priority |
|----------|-------|----------|
| 🔴 CRITICAL | 0 | Fix Immediately |
| 🔴 HIGH | 0 | Fix Soon |
| 🟡 MEDIUM | 0 | Fix Priority |
| 🔵 LOW | 68 | Fix When Possible |
| ⚪ INFO | 7 | Review |
| **Total** | **75** |

## 📁 Files to Fix

🟡 [`.\src\daemon\continuous.rs`](.\src\daemon\continuous.rs) - 1 issue(s)
🟡 [`.\src\scanners\recon.rs`](.\src\scanners\recon.rs) - 1 issue(s)
🟡 [`.\src\reporters\markdown.rs`](.\src\reporters\markdown.rs) - 1 issue(s)
🟡 [`.\src\auth\rbac.rs`](.\src\auth\rbac.rs) - 1 issue(s)
🟡 [`.\src\daemon\webhook.rs`](.\src\daemon\webhook.rs) - 1 issue(s)
🟡 [`.\src\scanners\api.rs`](.\src\scanners\api.rs) - 1 issue(s)
🟡 [`.\src\detection\framework.rs`](.\src\detection\framework.rs) - 1 issue(s)
🟡 [`.\src\scoring\categories\headers.rs`](.\src\scoring\categories\headers.rs) - 1 issue(s)
🟡 [`.\src\scanners\waf.rs`](.\src\scanners\waf.rs) - 1 issue(s)
🟡 [`.\src\scanners\mongodb.rs`](.\src\scanners\mongodb.rs) - 1 issue(s)
🟡 [`.\src\scanners\terraform.rs`](.\src\scanners\terraform.rs) - 1 issue(s)
🟡 [`.\src\audit\immutable.rs`](.\src\audit\immutable.rs) - 1 issue(s)
🟡 [`.\tests\integration_test.rs`](.\tests\integration_test.rs) - 1 issue(s)
🟡 [`.\examples\vulnerable_app\src\main.rs`](.\examples\vulnerable_app\src\main.rs) - 1 issue(s)
🟡 [`.\src\scanners\ddos.rs`](.\src\scanners\ddos.rs) - 1 issue(s)
🟡 [`.\src\scanners\enumeration.rs`](.\src\scanners\enumeration.rs) - 1 issue(s)
🟡 [`.\src\scanners\business_logic.rs`](.\src\scanners\business_logic.rs) - 1 issue(s)
🟡 [`.\src\scanners\race_condition.rs`](.\src\scanners\race_condition.rs) - 1 issue(s)
🟡 [`.\src\utils\network.rs`](.\src\utils\network.rs) - 1 issue(s)
🟡 [`.\src\audit\alerting.rs`](.\src\audit\alerting.rs) - 1 issue(s)
🟡 [`.\src\detection\mod.rs`](.\src\detection\mod.rs) - 1 issue(s)
🟡 [`.\src\payloads\smart.rs`](.\src\payloads\smart.rs) - 1 issue(s)
🟡 [`.\src\scanners\port.rs`](.\src\scanners\port.rs) - 1 issue(s)
🟡 [`.\src\scanners\kubernetes.rs`](.\src\scanners\kubernetes.rs) - 1 issue(s)
🟡 [`.\src\scanners\stress.rs`](.\src\scanners\stress.rs) - 1 issue(s)
🟡 [`.\src\scoring\categories\code_quality.rs`](.\src\scoring\categories\code_quality.rs) - 1 issue(s)
🟡 [`.\src\daemon\config.rs`](.\src\daemon\config.rs) - 1 issue(s)
🟡 [`.\src\scanners\http.rs`](.\src\scanners\http.rs) - 2 issue(s)
🟡 [`.\src\detection\language.rs`](.\src\detection\language.rs) - 1 issue(s)
🟡 [`.\src\utils\fs.rs`](.\src\utils\fs.rs) - 1 issue(s)
🟡 [`.\src\reporters\html.rs`](.\src\reporters\html.rs) - 1 issue(s)
🟡 [`.\src\scanners\path_traversal.rs`](.\src\scanners\path_traversal.rs) - 1 issue(s)
🟡 [`.\src\audit\siem.rs`](.\src\audit\siem.rs) - 1 issue(s)
🟡 [`.\src\integrations\mod.rs`](.\src\integrations\mod.rs) - 1 issue(s)
🟡 [`.\src\scanners\mod.rs`](.\src\scanners\mod.rs) - 1 issue(s)
🟡 [`.\src\audit\logger.rs`](.\src\audit\logger.rs) - 1 issue(s)
🟡 [`.\src\integrations\github.rs`](.\src\integrations\github.rs) - 1 issue(s)
🟡 [`.\src\analysis\false_positives.rs`](.\src\analysis\false_positives.rs) - 1 issue(s)
🟡 [`.\tests\scanner_tests.rs`](.\tests\scanner_tests.rs) - 2 issue(s)
🟡 [`.\src\scanners\dependencies.rs`](.\src\scanners\dependencies.rs) - 1 issue(s)
🟡 [`.\src\scanners\cors.rs`](.\src\scanners\cors.rs) - 1 issue(s)
🟡 [`.\src\scanners\ssrf.rs`](.\src\scanners\ssrf.rs) - 1 issue(s)
🟡 [`.\src\scanners\file_upload.rs`](.\src\scanners\file_upload.rs) - 1 issue(s)
🟡 [`.\src\main.rs`](.\src\main.rs) - 1 issue(s)
🟡 [`.\src\reporters\mod.rs`](.\src\reporters\mod.rs) - 1 issue(s)
🟡 [`.\src\scanners\ldap.rs`](.\src\scanners\ldap.rs) - 1 issue(s)
🟡 [`.\src\scanners\cloud_metadata.rs`](.\src\scanners\cloud_metadata.rs) - 1 issue(s)
🟡 [`.\src\audit\mod.rs`](.\src\audit\mod.rs) - 1 issue(s)
🟡 [`.\src\scanners\ssti.rs`](.\src\scanners\ssti.rs) - 1 issue(s)
🟡 [`.\src\reporters\ai.rs`](.\src\reporters\ai.rs) - 1 issue(s)
🟡 [`.\src\reporters\json.rs`](.\src\reporters\json.rs) - 1 issue(s)
🟡 [`.\src\reporters\console.rs`](.\src\reporters\console.rs) - 1 issue(s)
🟡 [`.\src\scanners\smb.rs`](.\src\scanners\smb.rs) - 1 issue(s)
🟡 [`.\src\daemon\scheduler.rs`](.\src\daemon\scheduler.rs) - 1 issue(s)
🟡 [`.\src\scanners\redis.rs`](.\src\scanners\redis.rs) - 1 issue(s)
🟡 [`.\src\daemon\monitor.rs`](.\src\daemon\monitor.rs) - 1 issue(s)
🟡 [`.\src\scanners\grpc.rs`](.\src\scanners\grpc.rs) - 1 issue(s)
🟡 [`.\src\scanners\rdp.rs`](.\src\scanners\rdp.rs) - 1 issue(s)
🟡 [`.\src\scanners\deserialization.rs`](.\src\scanners\deserialization.rs) - 2 issue(s)
🟡 [`.\src\scanners\graphql.rs`](.\src\scanners\graphql.rs) - 1 issue(s)
🟡 [`.\src\scanners\parser_cache.rs`](.\src\scanners\parser_cache.rs) - 1 issue(s)
🟡 [`.\src\scanners\static_analyzer.rs`](.\src\scanners\static_analyzer.rs) - 2 issue(s)
🟡 [`.\src\auth\saml.rs`](.\src\auth\saml.rs) - 1 issue(s)
🟡 [`.\src\scanners\xxe.rs`](.\src\scanners\xxe.rs) - 1 issue(s)
🟡 [`.\src\scanners\elasticsearch.rs`](.\src\scanners\elasticsearch.rs) - 1 issue(s)
🟡 [`.\src\integrations\jenkins.rs`](.\src\integrations\jenkins.rs) - 1 issue(s)
🟡 [`.\src\scanners\disclosure.rs`](.\src\scanners\disclosure.rs) - 1 issue(s)
🟡 [`.\src\scanners\serverless.rs`](.\src\scanners\serverless.rs) - 2 issue(s)
🟡 [`.\src\recon\smart.rs`](.\src\recon\smart.rs) - 1 issue(s)
🟡 [`.\src\scanners\open_redirect.rs`](.\src\scanners\open_redirect.rs) - 1 issue(s)

## 🔍 Detailed Findings

### 🔵 1. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\examples\vulnerable_app\src\main.rs`

> **AI:** Use `Read` tool to view `.\examples\vulnerable_app\src\main.rs`

**Description:**

File contains unwrap/expect calls: .\examples\vulnerable_app\src\main.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 2. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\analysis\false_positives.rs`

> **AI:** Use `Read` tool to view `.\src\analysis\false_positives.rs`

**Description:**

File contains unwrap/expect calls: .\src\analysis\false_positives.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 3. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\audit\alerting.rs`

> **AI:** Use `Read` tool to view `.\src\audit\alerting.rs`

**Description:**

File contains unwrap/expect calls: .\src\audit\alerting.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 4. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\audit\immutable.rs`

> **AI:** Use `Read` tool to view `.\src\audit\immutable.rs`

**Description:**

File contains unwrap/expect calls: .\src\audit\immutable.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 5. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\audit\logger.rs`

> **AI:** Use `Read` tool to view `.\src\audit\logger.rs`

**Description:**

File contains unwrap/expect calls: .\src\audit\logger.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 6. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\audit\mod.rs`

> **AI:** Use `Read` tool to view `.\src\audit\mod.rs`

**Description:**

File contains unwrap/expect calls: .\src\audit\mod.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 7. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\audit\siem.rs`

> **AI:** Use `Read` tool to view `.\src\audit\siem.rs`

**Description:**

File contains unwrap/expect calls: .\src\audit\siem.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 8. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\auth\rbac.rs`

> **AI:** Use `Read` tool to view `.\src\auth\rbac.rs`

**Description:**

File contains unwrap/expect calls: .\src\auth\rbac.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 9. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\auth\saml.rs`

> **AI:** Use `Read` tool to view `.\src\auth\saml.rs`

**Description:**

File contains unwrap/expect calls: .\src\auth\saml.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 10. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\daemon\config.rs`

> **AI:** Use `Read` tool to view `.\src\daemon\config.rs`

**Description:**

File contains unwrap/expect calls: .\src\daemon\config.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 11. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\daemon\continuous.rs`

> **AI:** Use `Read` tool to view `.\src\daemon\continuous.rs`

**Description:**

File contains unwrap/expect calls: .\src\daemon\continuous.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 12. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\daemon\monitor.rs`

> **AI:** Use `Read` tool to view `.\src\daemon\monitor.rs`

**Description:**

File contains unwrap/expect calls: .\src\daemon\monitor.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 13. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\daemon\scheduler.rs`

> **AI:** Use `Read` tool to view `.\src\daemon\scheduler.rs`

**Description:**

File contains unwrap/expect calls: .\src\daemon\scheduler.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 14. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\daemon\webhook.rs`

> **AI:** Use `Read` tool to view `.\src\daemon\webhook.rs`

**Description:**

File contains unwrap/expect calls: .\src\daemon\webhook.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 15. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\detection\framework.rs`

> **AI:** Use `Read` tool to view `.\src\detection\framework.rs`

**Description:**

File contains unwrap/expect calls: .\src\detection\framework.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 16. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\detection\language.rs`

> **AI:** Use `Read` tool to view `.\src\detection\language.rs`

**Description:**

File contains unwrap/expect calls: .\src\detection\language.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 17. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\detection\mod.rs`

> **AI:** Use `Read` tool to view `.\src\detection\mod.rs`

**Description:**

File contains unwrap/expect calls: .\src\detection\mod.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 18. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\integrations\github.rs`

> **AI:** Use `Read` tool to view `.\src\integrations\github.rs`

**Description:**

File contains unwrap/expect calls: .\src\integrations\github.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 19. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\integrations\jenkins.rs`

> **AI:** Use `Read` tool to view `.\src\integrations\jenkins.rs`

**Description:**

File contains unwrap/expect calls: .\src\integrations\jenkins.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 20. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\integrations\mod.rs`

> **AI:** Use `Read` tool to view `.\src\integrations\mod.rs`

**Description:**

File contains unwrap/expect calls: .\src\integrations\mod.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 21. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\main.rs`

> **AI:** Use `Read` tool to view `.\src\main.rs`

**Description:**

File contains unwrap/expect calls: .\src\main.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 22. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\payloads\smart.rs`

> **AI:** Use `Read` tool to view `.\src\payloads\smart.rs`

**Description:**

File contains unwrap/expect calls: .\src\payloads\smart.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 23. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\recon\smart.rs`

> **AI:** Use `Read` tool to view `.\src\recon\smart.rs`

**Description:**

File contains unwrap/expect calls: .\src\recon\smart.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 24. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\ai.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\ai.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\ai.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 25. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\console.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\console.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\console.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 26. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\html.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\html.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\html.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 27. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\json.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\json.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\json.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 28. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\markdown.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\markdown.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\markdown.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 29. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\reporters\mod.rs`

> **AI:** Use `Read` tool to view `.\src\reporters\mod.rs`

**Description:**

File contains unwrap/expect calls: .\src\reporters\mod.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 30. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\api.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\api.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\api.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 31. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\business_logic.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\business_logic.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\business_logic.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 32. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\cloud_metadata.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\cloud_metadata.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\cloud_metadata.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 33. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\cors.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\cors.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\cors.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 34. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\ddos.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\ddos.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\ddos.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 35. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\dependencies.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\dependencies.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\dependencies.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 36. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\deserialization.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\deserialization.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\deserialization.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 37. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\disclosure.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\disclosure.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\disclosure.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 38. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\elasticsearch.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\elasticsearch.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\elasticsearch.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 39. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\enumeration.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\enumeration.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\enumeration.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 40. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\file_upload.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\file_upload.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\file_upload.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 41. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\graphql.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\graphql.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\graphql.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 42. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\grpc.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\grpc.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\grpc.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 43. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\http.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\http.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\http.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 44. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\kubernetes.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\kubernetes.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\kubernetes.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 45. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\ldap.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\ldap.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\ldap.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 46. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\mod.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\mod.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\mod.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 47. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\mongodb.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\mongodb.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\mongodb.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 48. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\open_redirect.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\open_redirect.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\open_redirect.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 49. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\parser_cache.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\parser_cache.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\parser_cache.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 50. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\path_traversal.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\path_traversal.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\path_traversal.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 51. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\port.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\port.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\port.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 52. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\race_condition.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\race_condition.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\race_condition.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 53. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\rdp.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\rdp.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\rdp.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 54. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\recon.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\recon.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\recon.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 55. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\redis.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\redis.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\redis.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 56. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\serverless.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\serverless.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\serverless.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 57. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\smb.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\smb.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\smb.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 58. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\ssrf.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\ssrf.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\ssrf.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 59. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\ssti.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\ssti.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\ssti.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 60. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\static_analyzer.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\static_analyzer.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\static_analyzer.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 61. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\stress.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\stress.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\stress.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 62. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\terraform.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\terraform.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\terraform.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 63. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\waf.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\waf.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\waf.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 64. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\scanners\xxe.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\xxe.rs`

**Description:**

File contains unwrap/expect calls: .\src\scanners\xxe.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 65. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\utils\fs.rs`

> **AI:** Use `Read` tool to view `.\src\utils\fs.rs`

**Description:**

File contains unwrap/expect calls: .\src\utils\fs.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 66. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\src\utils\network.rs`

> **AI:** Use `Read` tool to view `.\src\utils\network.rs`

**Description:**

File contains unwrap/expect calls: .\src\utils\network.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 67. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\tests\integration_test.rs`

> **AI:** Use `Read` tool to view `.\tests\integration_test.rs`

**Description:**

File contains unwrap/expect calls: .\tests\integration_test.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### 🔵 68. Potential panic with unwrap/expect

**Priority:** 📝 **LOW** - Fix when possible

**Location:** `.\tests\scanner_tests.rs`

> **AI:** Use `Read` tool to view `.\tests\scanner_tests.rs`

**Description:**

File contains unwrap/expect calls: .\tests\scanner_tests.rs

**Fix:**

Consider using pattern matching or ? operator

**CWE:** `CWE-720`

---

### ⚪ 69. Unsafe Rust code detected (12 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scanners\deserialization.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\deserialization.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scanners\deserialization.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 70. Unsafe Rust code detected (10 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scanners\http.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\http.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scanners\http.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 71. Unsafe Rust code detected (2 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scanners\serverless.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\serverless.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scanners\serverless.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 72. Unsafe Rust code detected (10 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scanners\static_analyzer.rs`

> **AI:** Use `Read` tool to view `.\src\scanners\static_analyzer.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scanners\static_analyzer.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 73. Unsafe Rust code detected (6 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scoring\categories\code_quality.rs`

> **AI:** Use `Read` tool to view `.\src\scoring\categories\code_quality.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scoring\categories\code_quality.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 74. Unsafe Rust code detected (2 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\src\scoring\categories\headers.rs`

> **AI:** Use `Read` tool to view `.\src\scoring\categories\headers.rs`

**Description:**

File contains unsafe Rust blocks: .\src\scoring\categories\headers.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

### ⚪ 75. Unsafe Rust code detected (15 occurrences)

**Priority:** ℹ️ **INFO** - Review

**Location:** `.\tests\scanner_tests.rs`

> **AI:** Use `Read` tool to view `.\tests\scanner_tests.rs`

**Description:**

File contains unsafe Rust blocks: .\tests\scanner_tests.rs

**Fix:**

Review unsafe code for memory safety issues

**CWE:** `CWE-119`

---

## 🤖 Suggested Fix Order


*Generated by [Warden](https://github.com/Pamacea/warden) v0.8.2* - AI-Readable Report
