# Warden Security VS Code Extension - Publication Guide

## 📦 Package créé

**Fichier:** `warden-security-0.8.0.vsix` (368 KB)

## 🧪 Tester localement

```bash
# Installer l'extension localement
code --install-extension warden-security-0.8.0.vsix

# Ou depuis VS Code: Extensions → ... → Install from VSIX
```

## 🚀 Publier sur le Marketplace

### 1. Créer un compte Publisher

1. Aller sur https://marketplace.visualstudio.com/manage
2. Créer un publisher "warden-security" (ou votre nom)
3. Noter le Personal Access Token (PAT)

### 2. Installer vsce (si pas déjà fait)

```bash
npm install -g @vscode/vsce
```

### 3. Se connecter

```bash
# Créer un PAT depuis: https://marketplace.visualstudio.com/manage
vsce login warden-security
```

### 4. Publier

```bash
# Depuis le dossier vscode-extension
vsce publish
```

### 5. Alternative: Publier avec un token existant

```bash
vsce publish --pat <VOTRE_TOKEN>
```

## 📋 Configuration du Publisher

Sur https://marketplace.visualstudio.com/manage:

1. **Publisher ID:** warden-security
2. **Display Name:** Warden Security
3. **Description:** AI-powered security review tool for web applications
4. **Extensions:** Warden Security Scanner

## 📝 Après publication

L'extension sera disponible à:
- https://marketplace.visualstudio.com/items?itemName=warden-security.warden-security

## 🔧 Pour les futures versions

1. Mettre à jour `version` dans `package.json`
2. Lancer `npm run compile`
3. Lancer `vsce package`
4. Lancer `vsce publish`

## 📌 Notes

- L'extension nécessite le CLI `warden` installé et disponible dans le PATH
- Les utilisateurs peuvent configurer le chemin vers `warden` dans les settings VS Code
