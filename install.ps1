# httpxer installer for Windows — PowerShell.
#
# Usage:
#   irm https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.ps1 | iex
#
# Or saved-and-run:
#   .\install.ps1
#
# Installs to $env:USERPROFILE\bin\httpxer.exe by default (override with
# $env:INSTALL_DIR before invoking).
#
# After install, manage with the binary itself:
#   httpxer -c   # check-update
#   httpxer -U   # install latest in place
#   httpxer -X   # uninstall

$ErrorActionPreference = 'Stop'

$Repo  = 'assassin-marcos/httpxer'
$Asset = 'httpxer-x86_64-pc-windows-msvc.zip'
$Url   = "https://github.com/$Repo/releases/latest/download/$Asset"

$InstallDir = if ($env:INSTALL_DIR) { $env:INSTALL_DIR } else { "$env:USERPROFILE\bin" }

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$Tmp = Join-Path $env:TEMP ("httpxer-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
    Write-Host "==> Downloading $Asset"
    Invoke-WebRequest -Uri $Url -OutFile (Join-Path $Tmp 'httpxer.zip') -UseBasicParsing

    Write-Host "==> Extracting"
    Expand-Archive -Path (Join-Path $Tmp 'httpxer.zip') -DestinationPath $Tmp -Force

    Write-Host "==> Installing to $InstallDir\httpxer.exe"
    Move-Item -Force (Join-Path $Tmp 'httpxer.exe') (Join-Path $InstallDir 'httpxer.exe')
} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# Ensure $InstallDir is on PATH for the current and future sessions.
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not ($UserPath -split ';' | Where-Object { $_ -eq $InstallDir })) {
    [Environment]::SetEnvironmentVariable('Path', "$UserPath;$InstallDir", 'User')
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "==> Added $InstallDir to user PATH (new sessions will pick it up automatically)"
}

Write-Host ""
Write-Host "Installed. Try it out:"
Write-Host "    httpxer --version"
Write-Host "    httpxer -c                       # check for updates"
Write-Host "    httpxer -U                       # install latest"
Write-Host "    httpxer -l urls.txt -o out.jsonl   # run a probe"
