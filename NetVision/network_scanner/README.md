# NetVision

## Run Normally (Python)

```powershell
pip install -r requirements.txt
python main.py
```

## Build Windows EXE

```powershell
.\build_exe.ps1
```

This creates:

- `dist\NetVision.exe` (`--onefile` default)

Optional `--onedir` build:

```powershell
.\build_exe.ps1 -OneDir
```

This creates:

- `dist\NetVision\` folder (faster startup, easier debugging)

Optional obfuscated build (for binary release hardening):

```powershell
.\build_exe.ps1 -Obfuscate
```

## Clean Build Files

```powershell
.\clean.ps1
```

## Create GitHub Release ZIP

```powershell
.\make_release.ps1
```

Obfuscated release ZIP:

```powershell
.\make_release.ps1 -Obfuscate
```

This creates:

- `.release\NetVision-Windows.zip`
- `.release\NetVision-Windows\SHA256.txt`

## Notes

- Packet capture and some scans may require running as Administrator.
- Npcap/WinPcap driver support is required for Scapy sniffing on Windows.
- App icon files are read from `assets\netvision_logo.png` / `assets\netvision_logo.ico`.
- If you push source code to GitHub, it cannot be truly encrypted. Use `-Obfuscate` for release binaries only.
- `-Obfuscate` uses PyArmor trial by default; check license limits before commercial release.
