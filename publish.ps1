#!/usr/bin/env pwsh
# Warden v0.8.0 Enterprise Edition - Publication Script
#
# Ce script publie le crate sur crates.io avec toutes les vérifications nécessaires

Write-Host "🚀 Warden v0.8.0 Enterprise Edition - Publication" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier que cargo est installé
Write-Host "📋 Vérification de l'environnement..." -ForegroundColor Yellow
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "❌ cargo n'est pas installé ou pas dans le PATH" -ForegroundColor Red
    exit 1
}

# Vérifier le token crates.io
Write-Host "🔑 Vérification du token crates.io..." -ForegroundColor Yellow
$cargo_config = Join-Path $env:USERPROFILE ".cargo\config.toml"
if (-not (Test-Path $cargo_config)) {
    Write-Host "⚠️  Fichier config.toml non trouvé. Veuillez configurer votre token crates.io:" -ForegroundColor Yellow
    Write-Host "   cargo login" -ForegroundColor White
    exit 1
}

# Nettoyer le build précédent
Write-Host "🧹 Nettoyage des builds précédents..." -ForegroundColor Yellow
cargo clean

# Linter et formattage
Write-Host "✅ Vérification du formatage..." -ForegroundColor Yellow
cargo fmt -- --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Le code n'est pas formaté. Exécutez: cargo fmt" -ForegroundColor Yellow
    $answer = Read-Host "Continuer quand même? (y/N)"
    if ($answer -ne "y") { exit 1 }
}

# Clippy
Write-Host "🔍 Exécution de Clippy..." -ForegroundColor Yellow
cargo clippy -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Clippy a trouvé des problèmes. Veuillez les corriger." -ForegroundColor Yellow
    $answer = Read-Host "Continuer quand même? (y/N)"
    if ($answer -ne "y") { exit 1 }
}

# Tests
Write-Host "🧪 Exécution des tests..." -ForegroundColor Yellow
cargo test --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Les tests ont échoué. Abandon de la publication." -ForegroundColor Red
    exit 1
}

# Build release
Write-Host "🔨 Build release..." -ForegroundColor Yellow
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Le build a échoué. Abandon de la publication." -ForegroundColor Red
    exit 1
}

# Vérifier la taille du binaire
$binary = "target\release\warden.exe"
if (Test-Path $binary) {
    $size = (Get-Item $binary).Length / 1MB
    Write-Host "📦 Taille du binaire: $($size.ToString('F2')) MB" -ForegroundColor Green
    if ($size -gt 10) {
        Write-Host "⚠️  Le binaire dépasse 10 MB. Considérez l'optimisation." -ForegroundColor Yellow
    }
}

# Dry-run de la publication
Write-Host ""
Write-Host "📋 Dry-run de la publication..." -ForegroundColor Yellow
cargo publish --dry-run
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Le dry-run a échoué. Abandon de la publication." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "✅ Toutes les vérifications sont passées !" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Informations de publication:" -ForegroundColor Cyan
Write-Host "   Crate: warden-sec" -ForegroundColor White
Write-Host "   Version: 0.8.0" -ForegroundColor White
Write-Host ""

# Confirmation finale
$confirm = Read-Host "🚀 Publier sur crates.io? (yes/NO)"
if ($confirm -eq "yes") {
    Write-Host ""
    Write-Host "📤 Publication en cours..." -ForegroundColor Yellow
    cargo publish
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "🎉 Publication réussie !" -ForegroundColor Green
        Write-Host ""
        Write-Host "📌 Prochaines étapes:" -ForegroundColor Cyan
        Write-Host "   1. Créer un GitHub Release avec le tag v0.8.0" -ForegroundColor White
        Write-Host "   2. Attacher le binaire: target\release\warden.exe" -ForegroundColor White
        Write-Host "   3. Mettre à jour la documentation" -ForegroundColor White
    } else {
        Write-Host "❌ La publication a échoué." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "❌ Publication annulée." -ForegroundColor Yellow
}
