$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

py -3 -m PyInstaller `
  --noconfirm `
  --clean `
  --onedir `
  --noconsole `
  --name Fibula `
  --add-data "index.html;." `
  --add-data "logo.png;." `
  main.py

Write-Host ""
Write-Host "Build complete:"
Write-Host "dist\\Fibula\\Fibula.exe"
