Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    $targets = @(
        "build",
        "dist",
        "__pycache__",
        ".obf",
        ".obfpack",
        ".pyarmor",
        ".release"
    )

    foreach ($target in $targets) {
        if (Test-Path $target) {
            Remove-Item -Recurse -Force -ErrorAction Stop $target
            Write-Host "Removed $target"
        }
    }

    Get-ChildItem -Filter "*.spec" -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item -Force -ErrorAction Stop $_.FullName
            Write-Host "Removed $($_.Name)"
        }
}
finally {
    Pop-Location
}
