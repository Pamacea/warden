# Warden + Claude Code - Tutoriel d'Intégration

> Guide complet pour utiliser Warden avec Claude Code afin de scanner, détecter et corriger automatiquement les vulnérabilités de sécurité.

---

## 📋 Table des matières

1. [Installation](#1-installation)
2. [Premier scan](#2-premier-scan)
3. [Lecture du rapport par Claude Code](#3-lecture-du-rapport-par-claude-code)
4. [Correction des vulnérabilités](#4-correction-des-vulnérabilités)
5. [Vérification des corrections](#5-vérification-des-corrections)
6. [Workflow complet automatisé](#6-workflow-complet-automatisé)
7. [Bonnes pratiques](#7-bonnes-pratiques)

---

## 1. Installation

### 1.1 Installer Warden

```bash
# Depuis crates.io
cargo install warden-sec

# Ou depuis le source
cd /path/to/warden
cargo install --path .
```

### 1.2 Vérifier l'installation

```bash
warden --version
# Output: Warden v0.6.1
```

---

## 2. Premier Scan

### 2.1 Scanner un projet

```bash
# Se placer dans le projet
cd /path/to/your-project

# Lancer le scan
warden scan
```

**Ce qui se passe :**
1. Warden analyse le projet
2. Détecte les frameworks et langages
3. Scanne le code pour les vulnérabilités
4. **Crée automatiquement `WARDEN_SECURITY_REPORT.md`** dans le répertoire

### 2.2 Sortie console

```
╔═══════════════════════════════════════╗
║   Warden                         ║
║   v0.6.1                         ║
║   Security Review                         ║
╚═══════════════════════════════════════╝

Warden Security Scan v0.6.1
────────────────────────────────────────────────────────────
→ 📁 Target: your-project
→ 🔍 Detected: Rust, Axum

Starting Scan
────────────────────────────────────────────────────────────
📄 Found 5 potential issues (review required)

✓ AI report saved to /path/to/your-project/WARDEN_SECURITY_REPORT.md
```

---

## 3. Lecture du rapport par Claude Code

### 3.1 Structure du rapport généré

Le fichier `WARDEN_SECURITY_REPORT.md` contient :

```markdown
# Warden Security Scan Report

> **AI Agent Instructions:** This report is structured for systematic security fixes.
> Each finding includes file path, line numbers, and actionable recommendations.

## 📊 Scan Summary

| Severity | Count | Priority |
|----------|-------|----------|
| 🔴 CRITICAL | 2 | Fix Immediately |
| 🔴 HIGH | 1 | Fix Soon |
| 🟡 MEDIUM | 2 | Fix Priority |
| **Total** | **5** |

## 📁 Files to Fix

🔴 [`src/main.rs`](src/main.rs) - 3 issue(s)
🟡 [`src/auth.rs`](src/auth.rs) - 2 issue(s)

## 🔍 Detailed Findings

### 🔴 1. SQL Injection

**Priority:** 🚨 **CRITICAL** - Fix immediately

**Location:** `src/main.rs:42`

> **AI:** Use `Read` tool to view `src/main.rs`

**Description:**
User input directly concatenated into SQL query...

**Fix:**
Use parameterized queries with prepared statements...

**CWE:** `CWE-89`

---

## 🤖 Suggested Fix Order

### Phase 1: Critical & High (Do First)

1. [`src/main.rs:42`](src/main.rs:42) - SQL Injection
2. [`src/auth.rs:15`](src/auth.rs:15) - Missing authentication

### Phase 2: Medium (Do Next)

3. [`src/utils.rs:78`](src/utils.rs:78) - Unsafe unwrap
```

### 3.2 Demander à Claude Code de lire le rapport

**Option 1 - Mentionner le fichier directement :**

```
Peux-tu lire WARDEN_SECURITY_REPORT.md et me dire quelles vulnérabilités ont été trouvées ?
```

**Option 2 - Laisser Claude Code le découvrir :**

Claude Code peut lire automatiquement les fichiers markdown dans le projet.

---

## 4. Correction des vulnérabilités

### 4.1 Claude Code lit les fichiers concernés

Après avoir lu le rapport, Claude Code proposera :

```
Je vais examiner les fichiers vulnérables. Commençons par src/main.rs.
```

**Claude Code utilise l'outil Read :**

```
Reading file: src/main.rs
Lines 40-45:
```

### 4.2 Claude Code corrige les failles

**Exemple de correction SQL Injection :**

```rust
// ❌ AVANT (vulnérable)
fn get_user(id: &str) -> User {
    let query = format!("SELECT * FROM users WHERE id = {}", id);
    // ...
}

// ✅ APRÈS (corrigé)
fn get_user(id: &str) -> Result<User, Error> {
    let query = "SELECT * FROM users WHERE id = $1";
    // Utilisation de requêtes préparées
}
```

---

## 5. Vérification des corrections

### 5.1 Re-scanner après corrections

```bash
warden scan
```

### 5.2 Vérifier les résultats

```
✓ AI report saved to WARDEN_SECURITY_REPORT.md
```

Le rapport est mis à jour avec les nouvelles trouvailles (ou confirme que tout est corrigé).

---

## 6. Workflow complet automatisé

### 6.1 Script bash pour le workflow complet

```bash
#!/bin/bash
# warden-workflow.sh

set -e

echo "🛡️  Warden Security Scan Workflow"

# 1. Scanner
echo "📋 Step 1: Scanning..."
warden scan --format ai

# 2. Compter les vulnérabilités
TOTAL=$(grep -c "### 🔴\|### 🟡\|### 🔵" WARDEN_SECURITY_REPORT.md || echo 0)
echo "📊 Found $TOTAL issues"

# 3. Si des vulnérabilités sont trouvées
if [ "$TOTAL" -gt 0 ]; then
    echo "⚠️  Vulnerabilities found!"
    echo "📝 Report: WARDEN_SECURITY_REPORT.md"
    echo ""
    echo "Next steps:"
    echo "  1. Ask Claude Code to read the report"
    echo "  2. Fix the vulnerabilities"
    echo "  3. Run: $0 to verify"
else
    echo "✅ No vulnerabilities found!"
fi
```

### 6.2 Utilisation

```bash
chmod +x warden-workflow.sh
./warden-workflow.sh
```

---

## 7. Bonnes pratiques

### 7.1 Avant chaque commit

```bash
# Faire un scan avant de committer
warden scan --quick

# Si tout est OK, committer
git add .
git commit -m "feat: new feature"
```

### 7.2 Dans CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo install warden-sec
      - run: warden scan --format json --output warden-report.json
      - uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: warden-report.json
```

### 7.3 Options utiles

```bash
# Scan silencieux (pas de requêtes actives)
warden scan --mode passive

# Scan rapide
warden scan --profile quick

# Format JSON pour parsing
warden scan --format json --output report.json

# Générer des fixes structurés
warden scan --format ai --generate-fixes
```

---

## 8. Exemple complet

### 8.1 Projet Rust vulnérable

```rust
// src/main.rs
async fn login(username: &str, password: &str) -> Result<User> {
    let query = format!(
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        username, password  // ❌ SQL Injection!
    );
    // ...
}
```

### 8.2 Scan Warden

```bash
$ warden scan
✓ AI report saved to WARDEN_SECURITY_REPORT.md
```

### 8.3 Claude Code lit et corrige

```
Claude: "Je détecte une injection SQL dans src/main.rs:12.
Je vais corriger en utilisant des requêtes préparées..."
```

### 8.4 Vérification

```bash
$ warden scan
✓ No vulnerabilities found!
```

---

## 9. Démarrage rapide

### 9.1 Commandes essentielles

```bash
# Installer
cargo install warden-sec

# Scanner (auto-sauvegarde le rapport)
warden scan

// Dans Claude Code:
"Lis WARDEN_SECURITY_REPORT.md et corrige les failles trouvées"

// Re-scanner
warden scan
```

### 9.2 Fichiers générés

```
your-project/
├── src/
├── WARDEN_SECURITY_REPORT.md     ← Rapport principal (auto-généré)
└── WARDEN_SECURITY_REPORT_fixes.json  ← Données structurées (optionnel)
```

---

## 10. Prochaines étapes

1. **Installer Warden** : `cargo install warden-sec`
2. **Scanner votre projet** : `warden scan`
3. **Lire le rapport** : `WARDEN_SECURITY_REPORT.md`
4. **Demander à Claude Code** de corriger les failles
5. **Re-scanner** pour vérifier

---

**Pour plus d'informations :**
- GitHub : https://github.com/Pamacea/warden
- Documentation : https://github.com/Pamacea/warden/blob/main/README.md
- Changelog : https://github.com/Pamacea/warden/blob/main/CHANGELOG.md
