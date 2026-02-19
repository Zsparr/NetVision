param(
    [switch]$OneDir,
    [switch]$Obfuscate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

Push-Location $PSScriptRoot
try {
    Write-Host "Cleaning previous outputs..."
    powershell -ExecutionPolicy Bypass -File ".\clean.ps1"
    Assert-LastExitCode "Clean step"

    Write-Host "Building application..."
    $buildArgs = @()
    if ($OneDir) { $buildArgs += "-OneDir" }
    if ($Obfuscate) { $buildArgs += "-Obfuscate" }
    powershell -ExecutionPolicy Bypass -File ".\build_exe.ps1" @buildArgs
    Assert-LastExitCode "Build step"

    $releaseRoot = Join-Path $PSScriptRoot ".release"
    $releaseDir = Join-Path $releaseRoot "NetVision-Windows"
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null

    if ($OneDir) {
        Copy-Item -Recurse -Force ".\dist\NetVision" $releaseDir
        $artifactPath = Join-Path $releaseDir "NetVision"
    }
    else {
        Copy-Item -Force ".\dist\NetVision.exe" $releaseDir
        $artifactPath = Join-Path $releaseDir "NetVision.exe"
    }

    $hash = Get-FileHash -Algorithm SHA256 $artifactPath
    $hashLine = "$($hash.Algorithm)  $([System.IO.Path]::GetFileName($artifactPath))  $($hash.Hash)"
    Set-Content -Path (Join-Path $releaseDir "SHA256.txt") -Value $hashLine

    $readme = @(
        "# NetVision Windows Release",
        "",
        "## Files",
        "- NetVision executable build",
        "- SHA256.txt hash file",
        "",
        "## Run",
        "Double-click NetVision.exe",
        "",
        "## Notes",
        "- Some features require Administrator permissions.",
        "- Packet capture requires Npcap/WinPcap."
    )
    Set-Content -Path (Join-Path $releaseDir "RELEASE_NOTES.txt") -Value $readme

    $zipPath = Join-Path $releaseRoot "NetVision-Windows.zip"
    if (Test-Path $zipPath) {
        Remove-Item -Force $zipPath
    }
    Compress-Archive -Path (Join-Path $releaseDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

    Write-Host ""
    Write-Host "Release package ready:"
    Write-Host $zipPath
}
finally {
    Pop-Location
}
