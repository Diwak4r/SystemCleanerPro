# System Cleaner Pro v2.0.0

A professional-grade Windows system cleaner built with PowerShell. Replaces the need for CCleaner, BleachBit, or similar tools with a lightweight, transparent, open-source script.

## Features

- **3 Tiered Cleaning Modes** — Quick (daily), Deep (weekly), Full (monthly)
- **30+ Cleaning Categories** — temp files, browser caches, Windows Update, dev tool caches, app caches, and more
- **Space Measurement** — before/after disk space with per-category breakdown
- **Process Detection** — warns if browsers/apps are running before cleaning their caches
- **Timestamped Logs** — every run logged to `Desktop\CleanerLogs\`
- **Color-Coded Output** — green/yellow/red/cyan status indicators
- **Auto-Elevation** — the .bat launcher requests admin rights automatically
- **Safe by Design** — `Test-Path` + `try/catch` around every operation; locked files silently skipped

## Quick Start

1. Download `SystemCleaner.bat` and `SystemCleaner.ps1` to the same folder
2. **Double-click** `SystemCleaner.bat`
3. Select a mode (1=Quick, 2=Deep, 3=Full)

Or run from terminal with a preset mode:
```powershell
.\SystemCleaner.bat Quick
```

## Cleaning Modes

### Quick Mode (~30 sec) — Daily Safe Cleanup
| Step | What it cleans |
|------|----------------|
| 1 | User temp files (`%TEMP%`) |
| 2 | System temp files (`%SystemRoot%\Temp`) |
| 3 | Browser caches — Chrome, Edge, Brave, Firefox (all profiles) |
| 4 | Crash dumps and Windows Error Reporting |
| 5 | Thumbnail and icon cache |
| 6 | DirectX shader cache |
| 7 | Recent files list |
| 8 | Temp internet files (INetCache) |
| 9 | Downloaded program files |
| 10 | DNS cache flush |
| 11 | Clipboard and notification DB |

### Deep Mode (~2-5 min) — Weekly Thorough Clean
Includes everything in Quick, plus:
| Step | What it cleans |
|------|----------------|
| D1 | Prefetch files |
| D2 | Windows Update download cache |
| D3 | Delivery Optimization files |
| D4 | Windows log files (CBS, DISM, setup) |
| D5 | Memory dumps (MEMORY.DMP, minidumps) |
| D6 | Recycle Bin (all drives) |
| D7 | Font cache |
| D8 | Windows Store cache |
| D9 | Windows Defender old scan data |
| D10 | BITS transfer cache |
| D11 | Developer caches (npm, pip, yarn, NuGet, Gradle, Maven, Composer, pnpm) |
| D12 | Application caches (VS Code, Discord, Spotify, Teams, Adobe, Steam, Java) |
| D13 | SSD TRIM optimization |

### Full Mode (~5-15 min) — Monthly Deep System Clean
Includes everything in Deep, plus:
| Step | What it cleans |
|------|----------------|
| F1 | DISM component cleanup |
| F2 | Event log clearing |
| F3 | Windows.old folder (with confirmation) |
| F4 | Windows upgrade leftovers (`$Windows.~BT`, `$Windows.~WS`) |
| F5 | Installer patch cache |
| F6 | Automated Windows Disk Cleanup (cleanmgr) |
| F7 | Old restore points — keeps latest (with confirmation) |
| F8 | System File Checker (sfc /scannow) |

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (built into Windows)
- Administrator privileges (auto-requested)

## Safety

**The script NEVER touches:**
- System32, WinSxS (manually), boot files
- Registry hives, credentials, encryption certificates
- Passwords, bookmarks, or browser settings
- Installed programs or their data
- `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`

**Every operation:**
- Checks `Test-Path` before deleting
- Wrapped in `try/catch` — locked files silently skipped
- Services stopped/restarted gracefully with timeout
- Full mode destructive items require individual confirmation

## Logs

Logs are saved to `Desktop\CleanerLogs\` with format:
```
SystemCleaner_2026-02-06_143022.log
```

Each log contains:
- System info (OS, hostname, user)
- Every action with `[OK]`, `[SKIP]`, `[FAIL]` status
- Space freed per category
- Final summary with total space reclaimed

## License

MIT License — free to use, modify, and distribute.
