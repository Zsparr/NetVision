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
    Write-Host "Installing/updating build dependencies..."
    $deps = @("-r", "requirements.txt", "pyinstaller")
    if ($Obfuscate) {
        $deps += "pyarmor"
    }
    python -m pip install @deps
    Assert-LastExitCode "Dependency installation"

    $packagingMode = if ($OneDir) { "--onedir" } else { "--onefile" }
    $pyarmorPackMode = if ($OneDir) { "onedir" } else { "onefile" }
    $assetsDir = Join-Path $PSScriptRoot "assets"
    $iconPng = Join-Path $assetsDir "netvision_logo.png"
    $iconIco = Join-Path $assetsDir "netvision_logo.ico"

    if ((Test-Path $iconPng) -and -not (Test-Path $iconIco)) {
        Write-Host "Generating ICO from PNG logo..."
        python -c "from PIL import Image; img = Image.open(r'$iconPng').convert('RGBA'); img.save(r'$iconIco', format='ICO', sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])"
        Assert-LastExitCode "Icon generation"
    }

    if ($Obfuscate) {
        $obfPackDir = Join-Path $PSScriptRoot ".obfpack"
        if (Test-Path $obfPackDir) {
            Remove-Item -Recurse -Force $obfPackDir
        }
        Write-Host "Building obfuscated executable with PyArmor ($pyarmorPackMode)..."
        pyarmor gen --pack $pyarmorPackMode -O $obfPackDir main.py ui.py scanner.py
        Assert-LastExitCode "PyArmor pack build"

        if (Test-Path "dist") {
            Remove-Item -Recurse -Force "dist"
        }
        New-Item -ItemType Directory -Path "dist" | Out-Null

        if ($OneDir) {
            Copy-Item -Recurse -Force ".obfpack\main" ".\dist\NetVision"
            Write-Host ""
            Write-Host "Build complete."
            Write-Host "Output folder: $PSScriptRoot\dist\NetVision"
        }
        else {
            Copy-Item -Force ".obfpack\main.exe" ".\dist\NetVision.exe"
            Write-Host ""
            Write-Host "Build complete."
            Write-Host "Output file:   $PSScriptRoot\dist\NetVision.exe"
        }
        return
    }

    Write-Host "Building NetVision.exe ($packagingMode, obfuscate=$Obfuscate)..."
    $pyiArgs = @(
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name", "NetVision",
        $packagingMode,
        "--add-data", "assets;assets"
    )

    if (Test-Path $iconIco) {
        $pyiArgs += @("--icon", $iconIco)
    }

    $pyiArgs += "main.py"
    python -m PyInstaller @pyiArgs
    Assert-LastExitCode "PyInstaller build"

    Write-Host ""
    Write-Host "Build complete."
    if ($OneDir) {
        Write-Host "Output folder: $PSScriptRoot\dist\NetVision"
    }
    else {
        Write-Host "Output file:   $PSScriptRoot\dist\NetVision.exe"
    }
}
finally {
    Pop-Location
}
