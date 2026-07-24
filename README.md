<div align="center">

# SystemCleanerPro

**Lightweight, Transparent Windows Optimization Engine**

[![Windows](https://img.shields.io/badge/OS-Windows_10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white)](https://microsoft.com/powershell)
[![Author](https://img.shields.io/badge/Author-Diwakar_Yadav-000000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Diwak4r)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

### Overview

**SystemCleanerPro** is a transparent, open-source Windows maintenance solution built with **PowerShell** and **Batch**. Designed as a lightweight alternative to proprietary utility tools, it automates daily, weekly, and monthly system purges across 30+ categories without compromising user privacy or critical system registries.

### Cleanup Execution Pipeline

```mermaid
graph LR
    Launch([SystemCleaner.bat]) --> Admin{Elevated?}
    Admin -- No --> Request[Auto-Request Admin Privileges]
    Admin -- Yes --> ModeSel[Select Cleaning Tier]
    
    ModeSel --> Quick[Quick Mode: Daily Temps & Caches]
    ModeSel --> Deep[Deep Mode: Logs & Dev Artifacts]
    ModeSel --> Full[Full Mode: DISM & Component Purge]
    
    Quick --> Log[Generate Timestamped Log]
    Deep --> Log
    Full --> Log
```

### Cleaning Tiers Matrix

| Tier | Duration | Scope & Target Artifacts |
| :--- | :--- | :--- |
| **Quick Mode** | ~30s | `%TEMP%`, `%SystemRoot%\Temp`, Browser Caches (Chrome, Edge, Firefox, Brave), DNS Cache Flush, DirectX Shader Cache, Icon/Thumbnail Caches. |
| **Deep Mode** | ~2-5m | Everything in Quick + Prefetch, Windows Update Downloads, Memory Dumps, Developer Caches (`npm`, `pip`, `yarn`, `NuGet`, `Maven`), Application Caches (`VS Code`, `Discord`, `Teams`). |
| **Full Mode** | ~5-15m | Everything in Deep + DISM Component Cleanup, Event Log Clearing, `$Windows.~BT` Upgrade Residuals, Automated `cleanmgr`, Restore Point Pruning. |

### Safety Principles

- 🔒 **Zero-Registry Mutation:** Does not modify registry hives or user credential stores.
- 🛡️ **Verification First:** Executes `Test-Path` checks before any file operation.
- 📜 **Full Audit Trace:** Writes detailed `[OK]`, `[SKIP]`, and `[FAIL]` status output to `Desktop\CleanerLogs\`.

### Quick Start

```powershell
# Run preset Quick mode from PowerShell (Admin required)
.\SystemCleaner.bat Quick
```

---

<div align="center">
  <sub>Maintained by <a href="https://github.com/Diwak4r">Diwakar Yadav</a></sub>
</div>
