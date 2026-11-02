# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at
# https://oss.oracle.com/licenses/upl.
#
# Execute the actual documented Windows procedure in PowerShell with local fixtures.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Root = Split-Path $PSScriptRoot
$Guide = Get-Content -Raw (Join-Path $Root 'docs/installation/installation.adoc')
$Snippet = [regex]::Match($Guide, '(?s)\[source,powershell[^\r\n]*\]\r?\n----\r?\n(.*?)\r?\n----').Groups[1].Value
if (-not $Snippet) { throw 'Windows procedure not found' }
$Version = [regex]::Match((Get-Content -Raw (Join-Path $Root 'Makefile')), '(?m)^VERSION \?= ([^\r\n]+)').Groups[1].Value
$TestRoot = Join-Path ([IO.Path]::GetTempPath()) ('cohctl-doc-test-' + [Guid]::NewGuid())
$null = New-Item -ItemType Directory -Path $TestRoot
$script:Count = 0

function Invoke-WebRequest {
    [CmdletBinding()]
    param([string]$Uri, [string]$OutFile)
    $script:DownloadDirectories += Split-Path $OutFile
    $IsManifest = $Uri.EndsWith('checksums.txt')
    if (($script:Mode -eq 'manifest-download' -and $IsManifest) -or
        ($script:Mode -eq 'binary-download' -and -not $IsManifest)) {
        Write-Error 'Simulated nonterminating download error'
        return
    }
    $Data = if ($IsManifest) { $script:Metadata } else { 'Windows executable fixture' }
    [IO.File]::WriteAllText($OutFile, $Data)
}

function Get-FileHash {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Algorithm)
    if ($script:Mode -eq 'hash-failure') {
        Write-Error 'Simulated nonterminating hashing error'
        return
    }
    $script:Operations += 'hash'
    Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
}

function Copy-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$Destination)
    if ($script:Operations -notcontains 'hash') { throw 'Copy occurred before hashing' }
    if ($Destination -ne 'C:\path\on\your\PATH\cohctl.exe') { throw 'Unexpected installation destination' }
    $script:Operations += 'copy'
    if ($script:Mode -eq 'copy-failure') { Write-Error 'Simulated installation error'; return }
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination (Join-Path $TestRoot 'installed.exe')
}

try {
    $Fixture = Join-Path $TestRoot 'fixture'
    [IO.File]::WriteAllText($Fixture, 'Windows executable fixture')
    $Digest = (Microsoft.PowerShell.Utility\Get-FileHash $Fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach ($Arch in @('amd64', 'arm64')) {
        foreach ($script:Mode in @('valid', 'missing', 'duplicate', 'malformed', 'extra-field', 'mismatch',
                                  'manifest-download', 'binary-download', 'hash-failure', 'copy-failure', 'invalid-version')) {
            $Asset = "cohctl-$Version-windows-$Arch.exe"
            $Entry = "$Digest  $Asset`n"
            $script:Metadata = switch ($script:Mode) {
                missing { "$Digest  unrelated`n" }
                duplicate { $Entry + $Entry }
                malformed { $Digest.ToUpperInvariant() + "  $Asset`n" }
                extra-field { "$Digest  $Asset extra`n" }
                mismatch { ('0' * 64) + "  $Asset`n" }
                default { $Entry }
            }
            $script:DownloadDirectories = @()
            $script:Operations = @()
            $Installed = Join-Path $TestRoot 'installed.exe'
            if (Test-Path $Installed) { Remove-Item $Installed }
            $CaseVersion = if ($script:Mode -eq 'invalid-version') { 'bad/version' } else { $Version }
            $Code = $Snippet.Replace('{cli-version}', $CaseVersion).Replace('windows-amd64.exe', "windows-$Arch.exe")
            $Failed = $false
            try { & ([scriptblock]::Create($Code)) } catch { $Failed = $true }
            if ($script:Mode -eq 'valid') {
                if ($Failed -or -not (Test-Path $Installed)) { throw "Valid $Arch procedure failed" }
                if ((Get-Content -Raw $Installed) -cne 'Windows executable fixture') { throw 'Installed content differs' }
                if (($script:Operations -join ',') -ne 'hash,copy') { throw 'Unexpected operation order' }
            } else {
                if (-not $Failed -or (Test-Path $Installed)) { throw "Expected failure for $Arch/$script:Mode" }
                if ($script:Mode -ne 'copy-failure' -and $script:Operations -contains 'copy') {
                    throw "Failure reached copy for $Arch/$script:Mode"
                }
            }
            foreach ($Directory in $script:DownloadDirectories) {
                if (Test-Path $Directory) { throw "Temporary files retained for $Arch/$script:Mode" }
            }
            $script:Count++
            Write-Output "PASS: Windows $Arch/$script:Mode"
        }
    }
    Write-Output "All $script:Count PowerShell procedure cases passed on $($PSVersionTable.PSVersion) ($($PSVersionTable.Platform))"
} finally {
    Remove-Item -LiteralPath $TestRoot -Recurse -Force
}
