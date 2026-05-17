#!/usr/bin/env pwsh
# pq-diary CI smoke test (Windows / PowerShell)
#
# Usage:
#   pwsh -File ci/smoke-test.ps1 [-Bin <path>]
#
# Verifies:
#   1. `--help` exit 0 for every public top-level subcommand.
#   2. The root `--help` output does NOT advertise `legacy` / `daemon`
#      (TASK-0095: those subcommands must remain hidden).
#   3. Minimum E2E flow: init -> new -> list -> info -> export.
#
# The E2E flow uses `PQ_DIARY_HOME` to redirect the config root to a
# temporary directory and `PQ_DIARY_PASSWORD` to bypass the interactive
# password prompt, so the script can run unattended in CI.

[CmdletBinding()]
param(
    [string]$Bin = "./target/release/pq-diary.exe"
)

# Do NOT use `Stop` here: we rely on `$LASTEXITCODE` to inspect native exit
# codes, and we want native non-zero exits to fall through to our handlers
# rather than turn into terminating exceptions.
$ErrorActionPreference = "Continue"

$script:Pass = 0
$script:Fail = 0

function Assert-Pass([string]$Name) {
    Write-Host "[PASS] $Name"
    $script:Pass++
}

function Assert-Fail([string]$Name) {
    Write-Host "[FAIL] $Name" -ForegroundColor Red
    $script:Fail++
}

if (-not (Test-Path $Bin)) {
    Write-Host "[FATAL] binary not found: $Bin" -ForegroundColor Red
    exit 2
}

# ---------------------------------------------------------------------------
# 1. All public subcommands respond to --help with exit 0
# ---------------------------------------------------------------------------
$subcommands = @(
    'init', 'sync', 'change-password', 'info', 'export',
    'new', 'list', 'show', 'edit', 'delete',
    'today', 'search', 'stats', 'import', 'vault',
    'git-init', 'git-push', 'git-pull', 'git-sync', 'git-status',
    'template', 'legacy', 'legacy-access'
)

foreach ($cmd in $subcommands) {
    & $Bin $cmd --help *> $null
    if ($LASTEXITCODE -eq 0) {
        Assert-Pass "$cmd --help"
    } else {
        Assert-Fail "$cmd --help (exit $LASTEXITCODE)"
    }
}

# ---------------------------------------------------------------------------
# 2. Root --help advertises legacy / legacy-access (S12) but not daemon
# ---------------------------------------------------------------------------
$helpText = (& $Bin --help 2>&1 | Out-String)
if ($helpText -match '(?i)legacy') {
    Assert-Pass "help advertises 'legacy'"
} else {
    Assert-Fail "help missing 'legacy'"
}
if ($helpText -match '(?i)daemon') {
    Assert-Fail "help contains 'daemon' (must stay hidden)"
} else {
    Assert-Pass "help no 'daemon'"
}

# Legacy subcommand listing.
$legacyHelp = (& $Bin legacy --help 2>&1 | Out-String)
if ($legacyHelp -match 'init') {
    Assert-Pass "legacy --help lists 'init'"
} else {
    Assert-Fail "legacy --help missing 'init'"
}

# ---------------------------------------------------------------------------
# 3. E2E flow: init -> new -> list -> info -> export
# ---------------------------------------------------------------------------
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "pqd-smoke-$(Get-Random)")

# Stash any pre-existing values so the CI environment is left untouched.
$prevHome     = $env:PQ_DIARY_HOME
$prevPassword = $env:PQ_DIARY_PASSWORD

try {
    $env:PQ_DIARY_HOME     = $tmp.FullName
    $env:PQ_DIARY_PASSWORD = "SmokeTest123!"
    # `get_password` removes PQ_DIARY_PASSWORD from the env after each call,
    # so we re-assign it before every subsequent invocation that needs it.

    $vaultDir = Join-Path $tmp.FullName "vaults\default"

    & $Bin init *> $null
    if ($LASTEXITCODE -eq 0) { Assert-Pass "E2E: init" } else { Assert-Fail "E2E: init (exit $LASTEXITCODE)" }

    $env:PQ_DIARY_PASSWORD = "SmokeTest123!"
    & $Bin --vault $vaultDir new "smoke" --body "smoke body" *> $null
    if ($LASTEXITCODE -eq 0) { Assert-Pass "E2E: new" } else { Assert-Fail "E2E: new (exit $LASTEXITCODE)" }

    $env:PQ_DIARY_PASSWORD = "SmokeTest123!"
    $listOutput = (& $Bin --vault $vaultDir list 2>&1 | Out-String)
    if ($listOutput -match 'smoke') {
        Assert-Pass "E2E: list contains smoke"
    } else {
        Assert-Fail "E2E: list contains smoke"
    }

    $env:PQ_DIARY_PASSWORD = "SmokeTest123!"
    & $Bin --vault $vaultDir info *> $null
    if ($LASTEXITCODE -eq 0) { Assert-Pass "E2E: info" } else { Assert-Fail "E2E: info (exit $LASTEXITCODE)" }

    $outDir = Join-Path $tmp.FullName "out"
    New-Item -ItemType Directory -Path $outDir | Out-Null
    $env:PQ_DIARY_PASSWORD = "SmokeTest123!"
    "y" | & $Bin --vault $vaultDir export $outDir *> $null
    $count = (Get-ChildItem -Path $outDir -File -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($count -eq 1) {
        Assert-Pass "E2E: export 1 file"
    } else {
        Assert-Fail "E2E: export (expected 1 file, got $count)"
    }
}
finally {
    Remove-Item -Recurse -Force $tmp.FullName -ErrorAction SilentlyContinue
    if ($null -eq $prevHome) {
        Remove-Item Env:PQ_DIARY_HOME -ErrorAction SilentlyContinue
    } else {
        $env:PQ_DIARY_HOME = $prevHome
    }
    if ($null -eq $prevPassword) {
        Remove-Item Env:PQ_DIARY_PASSWORD -ErrorAction SilentlyContinue
    } else {
        $env:PQ_DIARY_PASSWORD = $prevPassword
    }
}

Write-Host "===== $script:Pass passed, $script:Fail failed ====="
if ($script:Fail -ne 0) {
    exit 1
}
exit 0
