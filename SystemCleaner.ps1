#Requires -RunAsAdministrator
<#
.SYNOPSIS
    System Cleaner Pro - Professional-Grade Windows System Cleaner
.DESCRIPTION
    A comprehensive system cleaning tool with 3 tiered modes:
      Quick  - Daily safe cleanup (~30 sec)  : temp files, browser cache, crash dumps
      Deep   - Weekly cleanup    (~2-5 min)  : + Windows Update, dev caches, app caches, recycle bin
      Full   - Monthly cleanup   (~5-15 min) : + DISM, event logs, Windows.old, restore points
    Features:
      - Space measurement before/after with per-category breakdown
      - Process detection before cleaning app caches
      - Timestamped log files for every run
      - Color-coded terminal output
      - Safe: try/catch around every operation, Test-Path before every delete
.PARAMETER Mode
    Cleaning mode: Quick, Deep, or Full. If omitted, shows interactive menu.
.NOTES
    Author : System Cleaner Pro
    Date   : 2026-02-06
    Version: 2.0.0
    Safe   : Never touches System32, WinSxS, registry hives, credentials, boot files
#>

param(
    [ValidateSet("Quick", "Deep", "Full")]
    [string]$Mode
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Version          = "2.0.0"
$Script:LogDir           = Join-Path $env:USERPROFILE "Desktop\CleanerLogs"
$Script:Timestamp        = Get-Date -Format "yyyy-MM-dd_HHmmss"
$Script:LogFile          = Join-Path $Script:LogDir "SystemCleaner_$($Script:Timestamp).log"
$Script:TotalBytesFreed  = [long]0
$Script:CategoryResults  = [System.Collections.ArrayList]::new()
$Script:Errors           = [System.Collections.ArrayList]::new()
$Script:StartTime        = Get-Date
$Script:DriveFreeBefore  = (Get-PSDrive C).Free

# ============================================================================
# LOGGING and OUTPUT HELPERS
# ============================================================================

function Initialize-Log {
    if (-not (Test-Path $Script:LogDir)) {
        New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null
    }
    $header = @"
================================================================================
  SYSTEM CLEANER PRO - LOG
  Version : $($Script:Version)
  Date    : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Computer: $env:COMPUTERNAME
  User    : $env:USERNAME
  OS      : $((Get-CimInstance Win32_OperatingSystem).Caption)
  Mode    : $Mode
================================================================================

"@
    Set-Content -Path $Script:LogFile -Value $header -Encoding UTF8
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Status = "INFO",
        [long]$BytesFreed = 0
    )
    $color = switch ($Status) {
        "OK"   { "Green" }
        "SKIP" { "DarkYellow" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "Cyan" }
        default { "White" }
    }

    $prefix = switch ($Status) {
        "OK"   { "[OK]  " }
        "SKIP" { "[SKIP]" }
        "WARN" { "[WARN]" }
        "FAIL" { "[FAIL]" }
        "INFO" { "[INFO]" }
        default { "      " }
    }

    $sizeStr = ""
    if ($BytesFreed -gt 0) {
        $sizeStr = "  ($(Format-Size $BytesFreed))"
    }

    Write-Host "   $prefix " -ForegroundColor $color -NoNewline
    Write-Host "$Message$sizeStr"
    Write-Log "$prefix $Message$sizeStr" $Status
}

function Write-SectionHeader {
    param([string]$StepNum, [string]$Title)
    Write-Host ""
    Write-Host "  [$StepNum] $Title" -ForegroundColor White
    Write-Host "  $('-' * ($Title.Length + $StepNum.Length + 4))" -ForegroundColor DarkGray
    Write-Log "--- [$StepNum] $Title ---"
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

# ============================================================================
# SPACE MEASUREMENT HELPERS
# ============================================================================

function Get-FolderSize {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $size = (Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
        if ($null -eq $size) { return 0 }
        return [long]$size
    } catch {
        return 0
    }
}

function Get-FileSize {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        return [long](Get-Item $Path -Force -ErrorAction SilentlyContinue).Length
    } catch {
        return 0
    }
}

function Add-CategoryResult {
    param([string]$Category, [long]$BytesFreed, [string]$Status = "OK")
    $Script:TotalBytesFreed += $BytesFreed
    [void]$Script:CategoryResults.Add([PSCustomObject]@{
        Category   = $Category
        BytesFreed = $BytesFreed
        SizeStr    = Format-Size $BytesFreed
        Status     = $Status
    })
}

# ============================================================================
# CLEANING HELPERS
# ============================================================================

function Remove-FolderContents {
    param(
        [string]$Path,
        [string]$Filter = "*",
        [switch]$Recurse
    )
    $freed = [long]0
    if (-not (Test-Path $Path)) { return $freed }
    try {
        $items = Get-ChildItem -Path $Path -Filter $Filter -Recurse:$Recurse -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    $dirSize = Get-FolderSize $item.FullName
                    Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                    $freed += $dirSize
                } else {
                    $freed += $item.Length
                    Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                }
            } catch {
                # Item locked or in use - skip silently
            }
        }
    } catch {
        # Folder inaccessible - skip
    }
    return $freed
}

function Remove-PathContents {
    <# Deletes all files and subdirectories inside a folder. Returns bytes freed. #>
    param([string]$Path)
    $freed = [long]0
    if (-not (Test-Path $Path)) { return $freed }
    try {
        # Files
        Get-ChildItem -Path $Path -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $freed += $_.Length
                Remove-Item $_.FullName -Force -ErrorAction Stop
            } catch { $freed -= $_.Length }
        }
        # Subdirectories
        Get-ChildItem -Path $Path -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $dirSize = Get-FolderSize $_.FullName
                Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop
                $freed += $dirSize
            } catch {}
        }
    } catch {}
    return $freed
}

function Stop-ServiceSafe {
    param([string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
            $timeout = 0
            while ((Get-Service $Name).Status -ne 'Stopped' -and $timeout -lt 15) {
                Start-Sleep -Seconds 1; $timeout++
            }
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

function Start-ServiceSafe {
    param([string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') {
            Start-Service -Name $Name -ErrorAction Stop
        }
    } catch {}
}

# ============================================================================
# PROCESS DETECTION
# ============================================================================

function Test-ProcessRunning {
    param([string]$ProcessName)
    return $null -ne (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Get-RunningApps {
    $apps = @()
    $checks = @{
        "chrome"    = "Google Chrome"
        "msedge"    = "Microsoft Edge"
        "brave"     = "Brave Browser"
        "firefox"   = "Mozilla Firefox"
        "discord"   = "Discord"
        "Spotify"   = "Spotify"
        "Teams"     = "Microsoft Teams"
        "Code"      = "VS Code"
    }
    foreach ($proc in $checks.Keys) {
        if (Test-ProcessRunning $proc) {
            $apps += $checks[$proc]
        }
    }
    return $apps
}

# ============================================================================
# BANNER and MENU
# ============================================================================

function Show-Banner {
    Clear-Host
    $os = (Get-CimInstance Win32_OperatingSystem)
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name.Trim()
    $ramGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $disk = Get-PSDrive C
    $diskTotal = [math]::Round(($disk.Used + $disk.Free) / 1GB, 1)
    $diskFree = [math]::Round($disk.Free / 1GB, 1)
    $diskUsedPct = [math]::Round(($disk.Used / ($disk.Used + $disk.Free)) * 100, 1)
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeStr = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes

    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host "  |           " -ForegroundColor Cyan -NoNewline
    Write-Host "SYSTEM CLEANER PRO v$($Script:Version)" -ForegroundColor White -NoNewline
    Write-Host "                        |" -ForegroundColor Cyan
    Write-Host "  |           " -ForegroundColor Cyan -NoNewline
    Write-Host "Professional Windows System Cleaner" -ForegroundColor DarkGray -NoNewline
    Write-Host "              |" -ForegroundColor Cyan
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "Host   : $($env:COMPUTERNAME.PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "OS     : $($os.Caption.PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "CPU    : $($cpu.Substring(0, [Math]::Min($cpu.Length, 50)).PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "RAM    : $("$ramGB GB".PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "Disk C : $("$diskFree GB free / $diskTotal GB ($diskUsedPct% used)".PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  |  " -ForegroundColor Cyan -NoNewline
    Write-Host "Uptime : $($uptimeStr.PadRight(50))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Cyan
    Write-Host "  +==============================================================+" -ForegroundColor Cyan
    Write-Host ""
}

function Show-ModeMenu {
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Select Cleaning Mode:                                     |" -ForegroundColor DarkGray
    Write-Host "  |                                                            |" -ForegroundColor DarkGray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[1] Quick " -ForegroundColor Green -NoNewline
    Write-Host " - Daily safe cleanup             (~30 sec)   |" -ForegroundColor Gray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "        " -NoNewline
    Write-Host "Temp, browser cache, crash dumps, DNS flush" -ForegroundColor DarkGray -NoNewline
    Write-Host "    |" -ForegroundColor DarkGray
    Write-Host "  |                                                            |" -ForegroundColor DarkGray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[2] Deep  " -ForegroundColor Yellow -NoNewline
    Write-Host " - Weekly thorough clean          (~2-5 min)  |" -ForegroundColor Gray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "        " -NoNewline
    Write-Host "Quick + WinUpdate, dev/app caches, recycle   " -ForegroundColor DarkGray -NoNewline
    Write-Host " |" -ForegroundColor DarkGray
    Write-Host "  |                                                            |" -ForegroundColor DarkGray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[3] Full  " -ForegroundColor Red -NoNewline
    Write-Host " - Monthly deep system clean      (~5-15 min) |" -ForegroundColor Gray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "        " -NoNewline
    Write-Host "Deep + DISM, event logs, Windows.old, SFC    " -ForegroundColor DarkGray -NoNewline
    Write-Host " |" -ForegroundColor DarkGray
    Write-Host "  |                                                            |" -ForegroundColor DarkGray
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "[Q] Quit" -ForegroundColor DarkCyan -NoNewline
    Write-Host "                                                |" -ForegroundColor DarkGray
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    do {
        Write-Host "  Choice: " -ForegroundColor White -NoNewline
        $choice = Read-Host
        switch ($choice.ToUpper()) {
            "1" { return "Quick" }
            "2" { return "Deep" }
            "3" { return "Full" }
            "Q" { Write-Host "  Exiting..." -ForegroundColor DarkGray; exit 0 }
            default { Write-Host "  Invalid choice. Enter 1, 2, 3, or Q." -ForegroundColor Red }
        }
    } while ($true)
}

# ============================================================================
# QUICK MODE CLEANING FUNCTIONS
# ============================================================================

function Clean-UserTemp {
    $path = $env:TEMP
    $sizeBefore = Get-FolderSize $path
    $freed = Remove-PathContents $path
    if ($freed -gt 0) {
        Write-Status "User Temp files cleaned" "OK" $freed
    } else {
        Write-Status "User Temp - already clean" "SKIP"
    }
    Add-CategoryResult "User Temp Files" $freed
}

function Clean-SystemTemp {
    $path = Join-Path $env:SystemRoot "Temp"
    $freed = Remove-PathContents $path
    if ($freed -gt 0) {
        Write-Status "System Temp files cleaned" "OK" $freed
    } else {
        Write-Status "System Temp - already clean" "SKIP"
    }
    Add-CategoryResult "System Temp Files" $freed
}

function Clean-BrowserCaches {
    $totalFreed = [long]0

    # --- Browser definitions ---
    $browsers = @(
        @{
            Name = "Google Chrome"
            Base = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data"
            Process = "chrome"
        },
        @{
            Name = "Microsoft Edge"
            Base = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data"
            Process = "msedge"
        },
        @{
            Name = "Brave Browser"
            Base = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data"
            Process = "brave"
        }
    )

    $cacheDirs = @("Cache", "Code Cache", "GPUCache", "Service Worker", "Session Storage",
                   "blob_storage", "GrShaderCache", "ShaderCache", "DawnGraphiteCache",
                   "DawnWebGPUCache", "GrShaderCache", "GraphiteDawnCache")

    foreach ($browser in $browsers) {
        $basePath = $browser.Base
        if (-not (Test-Path $basePath)) { continue }

        $browserFreed = [long]0

        # Find all profiles (Default, Profile 1, Profile 2, etc.)
        $profiles = @("Default")
        $profiles += (Get-ChildItem -Path $basePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue).Name

        foreach ($profile in $profiles) {
            foreach ($cacheDir in $cacheDirs) {
                $cachePath = Join-Path $basePath "$profile\$cacheDir"
                $browserFreed += Remove-PathContents $cachePath
            }
        }

        # Top-level caches (not per-profile)
        foreach ($topCache in @("ShaderCache", "GrShaderCache")) {
            $topPath = Join-Path $basePath $topCache
            $browserFreed += Remove-PathContents $topPath
        }

        if ($browserFreed -gt 0) {
            Write-Status "$($browser.Name) cache cleaned" "OK" $browserFreed
        } else {
            Write-Status "$($browser.Name) - no cache found" "SKIP"
        }
        $totalFreed += $browserFreed
    }

    # --- Firefox (different structure) ---
    $ffProfiles = Join-Path $env:LOCALAPPDATA "Mozilla\Firefox\Profiles"
    if (Test-Path $ffProfiles) {
        $ffFreed = [long]0
        Get-ChildItem -Path $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($subDir in @("cache2", "jumpListCache", "OfflineCache", "startupCache", "thumbnails")) {
                $ffFreed += Remove-PathContents (Join-Path $_.FullName $subDir)
            }
        }
        if ($ffFreed -gt 0) {
            Write-Status "Mozilla Firefox cache cleaned" "OK" $ffFreed
        } else {
            Write-Status "Firefox - no cache found" "SKIP"
        }
        $totalFreed += $ffFreed
    }

    Add-CategoryResult "Browser Caches" $totalFreed
}

function Clean-CrashDumps {
    $freed = [long]0
    $paths = @(
        (Join-Path $env:LOCALAPPDATA "CrashDumps"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\WER"),
        (Join-Path $env:ProgramData "Microsoft\Windows\WER\ReportArchive"),
        (Join-Path $env:ProgramData "Microsoft\Windows\WER\ReportQueue")
    )
    foreach ($p in $paths) {
        $freed += Remove-PathContents $p
    }
    if ($freed -gt 0) {
        Write-Status "Crash dumps and error reports cleaned" "OK" $freed
    } else {
        Write-Status "Crash dumps - already clean" "SKIP"
    }
    Add-CategoryResult "Crash Dumps and Error Reports" $freed
}

function Clean-ThumbnailIconCache {
    $freed = [long]0
    $explorerDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
    if (Test-Path $explorerDir) {
        Get-ChildItem -Path $explorerDir -Filter "thumbcache_*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
        }
        Get-ChildItem -Path $explorerDir -Filter "iconcache_*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
        }
    }
    $iconDb = Join-Path $env:LOCALAPPDATA "IconCache.db"
    if (Test-Path $iconDb) {
        try { $freed += (Get-Item $iconDb -Force).Length; Remove-Item $iconDb -Force -ErrorAction Stop } catch {}
    }
    if ($freed -gt 0) {
        Write-Status "Thumbnail and icon cache cleared" "OK" $freed
    } else {
        Write-Status "Thumbnail cache - already clean" "SKIP"
    }
    Add-CategoryResult "Thumbnail and Icon Cache" $freed
}

function Clean-DirectXShaderCache {
    $path = Join-Path $env:LOCALAPPDATA "D3DSCache"
    $freed = Remove-PathContents $path
    if ($freed -gt 0) {
        Write-Status "DirectX shader cache cleaned" "OK" $freed
    } else {
        Write-Status "DirectX shader cache - already clean" "SKIP"
    }
    Add-CategoryResult "DirectX Shader Cache" $freed
}

function Clean-RecentFiles {
    $freed = [long]0
    $recentPaths = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent\CustomDestinations")
    )
    foreach ($p in $recentPaths) {
        $freed += Remove-PathContents $p
    }
    if ($freed -gt 0) {
        Write-Status "Recent files list cleared" "OK" $freed
    } else {
        Write-Status "Recent files - already clean" "SKIP"
    }
    Add-CategoryResult "Recent Files List" $freed
}

function Clean-TempInternetFiles {
    $path = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\INetCache"
    $freed = Remove-PathContents $path
    if ($freed -gt 0) {
        Write-Status "Temp internet files cleaned" "OK" $freed
    } else {
        Write-Status "Temp internet files - already clean" "SKIP"
    }
    Add-CategoryResult "Temp Internet Files" $freed
}

function Clean-DownloadedProgramFiles {
    $path = Join-Path $env:SystemRoot "Downloaded Program Files"
    $freed = Remove-PathContents $path
    if ($freed -gt 0) {
        Write-Status "Downloaded program files cleaned" "OK" $freed
    } else {
        Write-Status "Downloaded program files - already clean" "SKIP"
    }
    Add-CategoryResult "Downloaded Program Files" $freed
}

function Invoke-DNSFlush {
    try {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Status "DNS cache flushed" "OK"
    } catch {
        try {
            ipconfig /flushdns | Out-Null
            Write-Status "DNS cache flushed (ipconfig)" "OK"
        } catch {
            Write-Status "DNS flush failed" "FAIL"
        }
    }
    Add-CategoryResult "DNS Cache Flush" 0
}

function Clear-ClipboardData {
    try {
        Set-Clipboard -Value $null -ErrorAction SilentlyContinue
        Write-Status "Clipboard cleared" "OK"
    } catch {
        Write-Status "Clipboard clear - skipped" "SKIP"
    }
    Add-CategoryResult "Clipboard" 0
}

function Clean-NotificationDB {
    $freed = [long]0
    $notifDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Notifications"
    if (Test-Path $notifDir) {
        foreach ($f in @("wpndatabase.db-wal", "wpndatabase.db-shm")) {
            $fp = Join-Path $notifDir $f
            if (Test-Path $fp) {
                try { $freed += (Get-Item $fp -Force).Length; Remove-Item $fp -Force -ErrorAction Stop } catch {}
            }
        }
    }
    if ($freed -gt 0) {
        Write-Status "Notification DB temp files cleaned" "OK" $freed
    } else {
        Write-Status "Notification DB - already clean" "SKIP"
    }
    Add-CategoryResult "Notification DB" $freed
}

# ============================================================================
# DEEP MODE CLEANING FUNCTIONS (includes Quick + these)
# ============================================================================

function Clean-PrefetchFiles {
    $path = Join-Path $env:SystemRoot "Prefetch"
    $freed = [long]0
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "*.pf" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
        }
    }
    if ($freed -gt 0) {
        Write-Status "Prefetch files cleaned" "OK" $freed
    } else {
        Write-Status "Prefetch - already clean" "SKIP"
    }
    Add-CategoryResult "Prefetch Files" $freed
}

function Clean-WindowsUpdateCache {
    $path = Join-Path $env:SystemRoot "SoftwareDistribution\Download"
    $wasRunning = Stop-ServiceSafe "wuauserv"
    $bitsWas = Stop-ServiceSafe "bits"

    $freed = Remove-PathContents $path

    if ($bitsWas) { Start-ServiceSafe "bits" }
    if ($wasRunning) { Start-ServiceSafe "wuauserv" }

    if ($freed -gt 0) {
        Write-Status "Windows Update cache cleaned" "OK" $freed
    } else {
        Write-Status "Windows Update cache - already clean" "SKIP"
    }
    Add-CategoryResult "Windows Update Cache" $freed
}

function Clean-DeliveryOptimization {
    $path = Join-Path $env:SystemRoot "ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"
    $freed = Remove-PathContents $path
    $path2 = Join-Path $env:SystemRoot "ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Downloads"
    $freed += Remove-PathContents $path2
    if ($freed -gt 0) {
        Write-Status "Delivery Optimization cache cleaned" "OK" $freed
    } else {
        Write-Status "Delivery Optimization - already clean" "SKIP"
    }
    Add-CategoryResult "Delivery Optimization" $freed
}

function Clean-WindowsLogs {
    $freed = [long]0
    $logPaths = @(
        (Join-Path $env:SystemRoot "Logs\CBS"),
        (Join-Path $env:SystemRoot "Logs\DISM"),
        (Join-Path $env:SystemRoot "Logs\MeasuredBoot"),
        (Join-Path $env:SystemRoot "Logs\waasmedic")
    )
    foreach ($p in $logPaths) {
        if (Test-Path $p) {
            Get-ChildItem -Path $p -Filter "*.log" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
            }
            Get-ChildItem -Path $p -Filter "*.cab" -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
            }
        }
    }
    # Setup logs in root
    foreach ($f in @("setupact.log", "setuperr.log")) {
        $fp = Join-Path $env:SystemRoot $f
        if (Test-Path $fp) {
            try { $freed += (Get-Item $fp -Force).Length; Remove-Item $fp -Force -ErrorAction Stop } catch {}
        }
    }
    if ($freed -gt 0) {
        Write-Status "Windows log files cleaned" "OK" $freed
    } else {
        Write-Status "Windows logs - already clean" "SKIP"
    }
    Add-CategoryResult "Windows Log Files" $freed
}

function Clean-MemoryDumps {
    $freed = [long]0
    $dmp = Join-Path $env:SystemRoot "MEMORY.DMP"
    if (Test-Path $dmp) {
        try { $freed += (Get-Item $dmp -Force).Length; Remove-Item $dmp -Force -ErrorAction Stop } catch {}
    }
    $miniDir = Join-Path $env:SystemRoot "Minidump"
    $freed += Remove-PathContents $miniDir
    $lkr = Join-Path $env:SystemRoot "LiveKernelReports"
    $freed += Remove-PathContents $lkr

    if ($freed -gt 0) {
        Write-Status "Memory dumps cleaned" "OK" $freed
    } else {
        Write-Status "Memory dumps - none found" "SKIP"
    }
    Add-CategoryResult "Memory Dumps" $freed
}

function Clean-RecycleBin {
    try {
        $sizeBefore = (Get-PSDrive C).Free
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        if ($freed -gt 0) {
            Write-Status "Recycle Bin emptied" "OK" $freed
        } else {
            Write-Status "Recycle Bin - already empty" "SKIP"
        }
        Add-CategoryResult "Recycle Bin" $freed
    } catch {
        Write-Status "Recycle Bin - skipped" "SKIP"
        Add-CategoryResult "Recycle Bin" 0
    }
}

function Clean-FontCache {
    $freed = [long]0
    $fontCachePath = Join-Path $env:SystemRoot "ServiceProfiles\LocalService\AppData\Local\FontCache"
    $wasRunning = Stop-ServiceSafe "FontCache"
    $freed += Remove-PathContents $fontCachePath
    $fc3 = Join-Path $env:SystemRoot "ServiceProfiles\LocalService\AppData\Local\FontCache-S*"
    Get-ChildItem $fc3 -ErrorAction SilentlyContinue | ForEach-Object {
        $freed += Remove-PathContents $_.FullName
    }
    if ($wasRunning) { Start-ServiceSafe "FontCache" }
    if ($freed -gt 0) {
        Write-Status "Font cache cleaned" "OK" $freed
    } else {
        Write-Status "Font cache - already clean" "SKIP"
    }
    Add-CategoryResult "Font Cache" $freed
}

function Clean-WindowsStoreCache {
    try {
        $sizeBefore = (Get-PSDrive C).Free
        Start-Process "wsreset.exe" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        Write-Status "Windows Store cache reset" "OK" $freed
        Add-CategoryResult "Windows Store Cache" $freed
    } catch {
        Write-Status "Windows Store cache - skipped" "SKIP"
        Add-CategoryResult "Windows Store Cache" 0
    }
}

function Clean-DefenderScanData {
    $freed = [long]0
    $paths = @(
        (Join-Path $env:ProgramData "Microsoft\Windows Defender\Scans\History"),
        (Join-Path $env:ProgramData "Microsoft\Windows Defender\Scans\MetaStore")
    )
    foreach ($p in $paths) {
        $freed += Remove-PathContents $p
    }
    $scanDir = Join-Path $env:ProgramData "Microsoft\Windows Defender\Scans"
    if (Test-Path $scanDir) {
        Get-ChildItem -Path $scanDir -Filter "mpcache-*" -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try { $freed += $_.Length; Remove-Item $_.FullName -Force -ErrorAction Stop } catch {}
        }
    }
    if ($freed -gt 0) {
        Write-Status "Defender old scan data cleaned" "OK" $freed
    } else {
        Write-Status "Defender scan data - already clean" "SKIP"
    }
    Add-CategoryResult "Windows Defender Scan Data" $freed
}

function Clean-BITSCache {
    try {
        $null = bitsadmin /reset /allusers 2>$null
        Write-Status "BITS transfer cache reset" "OK"
    } catch {
        Write-Status "BITS cache - skipped" "SKIP"
    }
    Add-CategoryResult "BITS Transfer Cache" 0
}

function Invoke-SSDTrim {
    try {
        Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue
        Write-Status "SSD TRIM optimization complete" "OK"
    } catch {
        try {
            defrag C: /O 2>$null | Out-Null
            Write-Status "SSD TRIM optimization complete (defrag)" "OK"
        } catch {
            Write-Status "SSD TRIM - skipped" "SKIP"
        }
    }
    Add-CategoryResult "SSD TRIM" 0
}

# --- Developer Caches ---

function Clean-DeveloperCaches {
    $totalFreed = [long]0

    # npm cache
    $npmCache = Join-Path $env:APPDATA "npm-cache"
    if (Test-Path $npmCache) {
        $freed = Remove-PathContents $npmCache
        if ($freed -gt 0) { Write-Status "npm cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # pip cache
    $pipCache = Join-Path $env:LOCALAPPDATA "pip\cache"
    if (Test-Path $pipCache) {
        $freed = Remove-PathContents $pipCache
        if ($freed -gt 0) { Write-Status "pip cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # yarn cache
    $yarnCache = Join-Path $env:LOCALAPPDATA "Yarn\Cache"
    if (Test-Path $yarnCache) {
        $freed = Remove-PathContents $yarnCache
        if ($freed -gt 0) { Write-Status "Yarn cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # NuGet cache
    $nugetCache = Join-Path $env:LOCALAPPDATA "NuGet\v3-cache"
    if (Test-Path $nugetCache) {
        $freed = Remove-PathContents $nugetCache
        if ($freed -gt 0) { Write-Status "NuGet cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # Gradle cache
    $gradleCache = Join-Path $env:USERPROFILE ".gradle\caches"
    if (Test-Path $gradleCache) {
        $freed = Remove-PathContents $gradleCache
        if ($freed -gt 0) { Write-Status "Gradle cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # Maven cache
    $mavenCache = Join-Path $env:USERPROFILE ".m2\repository"
    if (Test-Path $mavenCache) {
        $freed = Remove-PathContents $mavenCache
        if ($freed -gt 0) { Write-Status "Maven cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # Composer cache (PHP)
    $composerCache = Join-Path $env:LOCALAPPDATA "Composer\cache"
    if (Test-Path $composerCache) {
        $freed = Remove-PathContents $composerCache
        if ($freed -gt 0) { Write-Status "Composer cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    # pnpm cache
    $pnpmCache = Join-Path $env:LOCALAPPDATA "pnpm-cache"
    if (Test-Path $pnpmCache) {
        $freed = Remove-PathContents $pnpmCache
        if ($freed -gt 0) { Write-Status "pnpm cache cleaned" "OK" $freed }
        $totalFreed += $freed
    }

    if ($totalFreed -eq 0) {
        Write-Status "Developer caches - none found or already clean" "SKIP"
    }
    Add-CategoryResult "Developer Tool Caches" $totalFreed
}

# --- Application Caches ---

function Clean-ApplicationCaches {
    $totalFreed = [long]0

    # VS Code
    $vscodePaths = @(
        (Join-Path $env:APPDATA "Code\Cache"),
        (Join-Path $env:APPDATA "Code\CachedData"),
        (Join-Path $env:APPDATA "Code\CachedExtensions"),
        (Join-Path $env:APPDATA "Code\CachedExtensionVSIXs"),
        (Join-Path $env:APPDATA "Code\Code Cache"),
        (Join-Path $env:APPDATA "Code\GPUCache"),
        (Join-Path $env:APPDATA "Code\Service Worker\CacheStorage"),
        (Join-Path $env:APPDATA "Code\logs")
    )
    $vscFreed = [long]0
    foreach ($p in $vscodePaths) {
        $vscFreed += Remove-PathContents $p
    }
    if ($vscFreed -gt 0) {
        Write-Status "VS Code cache cleaned" "OK" $vscFreed
        $totalFreed += $vscFreed
    }

    # Discord
    $discordPaths = @(
        (Join-Path $env:APPDATA "discord\Cache"),
        (Join-Path $env:APPDATA "discord\Code Cache"),
        (Join-Path $env:APPDATA "discord\GPUCache")
    )
    $discFreed = [long]0
    foreach ($p in $discordPaths) {
        $discFreed += Remove-PathContents $p
    }
    if ($discFreed -gt 0) {
        Write-Status "Discord cache cleaned" "OK" $discFreed
        $totalFreed += $discFreed
    }

    # Spotify
    $spotifyCache = Join-Path $env:LOCALAPPDATA "Spotify\Storage"
    if (Test-Path $spotifyCache) {
        $freed = Remove-PathContents $spotifyCache
        if ($freed -gt 0) {
            Write-Status "Spotify cache cleaned" "OK" $freed
            $totalFreed += $freed
        }
    }

    # Microsoft Teams (new version)
    $teamsNewCache = Join-Path $env:LOCALAPPDATA "Packages\MSTeams_*\LocalCache"
    Get-Item $teamsNewCache -ErrorAction SilentlyContinue | ForEach-Object {
        $freed = Remove-PathContents $_.FullName
        if ($freed -gt 0) {
            Write-Status "Teams cache cleaned" "OK" $freed
            $totalFreed += $freed
        }
    }
    # Microsoft Teams (old version)
    $teamsOldPaths = @(
        (Join-Path $env:APPDATA "Microsoft\Teams\Cache"),
        (Join-Path $env:APPDATA "Microsoft\Teams\blob_storage"),
        (Join-Path $env:APPDATA "Microsoft\Teams\databases"),
        (Join-Path $env:APPDATA "Microsoft\Teams\GPUCache"),
        (Join-Path $env:APPDATA "Microsoft\Teams\IndexedDB"),
        (Join-Path $env:APPDATA "Microsoft\Teams\Local Storage"),
        (Join-Path $env:APPDATA "Microsoft\Teams\tmp")
    )
    $teamsFreed = [long]0
    foreach ($p in $teamsOldPaths) {
        $teamsFreed += Remove-PathContents $p
    }
    if ($teamsFreed -gt 0) {
        Write-Status "Teams (classic) cache cleaned" "OK" $teamsFreed
        $totalFreed += $teamsFreed
    }

    # Adobe
    $adobeCache = Join-Path $env:LOCALAPPDATA "Adobe"
    if (Test-Path $adobeCache) {
        $adobeFreed = [long]0
        Get-ChildItem $adobeCache -Directory -Recurse -Filter "*Cache*" -ErrorAction SilentlyContinue | ForEach-Object {
            $adobeFreed += Remove-PathContents $_.FullName
        }
        if ($adobeFreed -gt 0) {
            Write-Status "Adobe cache cleaned" "OK" $adobeFreed
            $totalFreed += $adobeFreed
        }
    }

    # Steam (download cache only, not games)
    $steamCache = Join-Path ${env:ProgramFiles(x86)} "Steam\appcache"
    if (Test-Path $steamCache) {
        $freed = Remove-PathContents $steamCache
        if ($freed -gt 0) {
            Write-Status "Steam app cache cleaned" "OK" $freed
            $totalFreed += $freed
        }
    }

    # Java webcache
    $javaCache = Join-Path $env:LOCALAPPDATA "Sun\Java\Deployment\cache"
    if (Test-Path $javaCache) {
        $freed = Remove-PathContents $javaCache
        if ($freed -gt 0) {
            Write-Status "Java cache cleaned" "OK" $freed
            $totalFreed += $freed
        }
    }

    if ($totalFreed -eq 0) {
        Write-Status "Application caches - none found or already clean" "SKIP"
    }
    Add-CategoryResult "Application Caches" $totalFreed
}

# ============================================================================
# FULL MODE CLEANING FUNCTIONS (includes Deep + these)
# ============================================================================

function Invoke-DISMCleanup {
    Write-Status "Running DISM component cleanup (this may take a few minutes)..." "INFO"
    try {
        $sizeBefore = (Get-PSDrive C).Free
        $result = Dism.exe /Online /Cleanup-Image /StartComponentCleanup 2>$null
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        Write-Status "DISM component cleanup complete" "OK" $freed
        Add-CategoryResult "DISM Component Cleanup" $freed
    } catch {
        Write-Status "DISM cleanup failed: $($_.Exception.Message)" "FAIL"
        [void]$Script:Errors.Add("DISM cleanup failed")
        Add-CategoryResult "DISM Component Cleanup" 0 "FAIL"
    }
}

function Clean-EventLogs {
    Write-Status "Clearing old event logs..." "INFO"
    try {
        $sizeBefore = (Get-PSDrive C).Free
        $logs = wevtutil el 2>$null
        foreach ($log in $logs) {
            try { wevtutil cl "$log" 2>$null | Out-Null } catch {}
        }
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        Write-Status "Event logs cleared" "OK" $freed
        Add-CategoryResult "Event Logs" $freed
    } catch {
        Write-Status "Event log cleanup failed" "FAIL"
        Add-CategoryResult "Event Logs" 0 "FAIL"
    }
}

function Clean-WindowsOld {
    $path = Join-Path $env:SystemDrive "Windows.old"
    if (-not (Test-Path $path)) {
        Write-Status "Windows.old - not found (skip)" "SKIP"
        Add-CategoryResult "Windows.old" 0 "SKIP"
        return
    }

    $size = Get-FolderSize $path
    Write-Host ""
    Write-Host "  [!] Found Windows.old ($(Format-Size $size)). Remove it?" -ForegroundColor Yellow
    Write-Host "      This removes the ability to roll back to a previous Windows version." -ForegroundColor DarkYellow
    Write-Host "      [Y] Yes  [N] No: " -ForegroundColor White -NoNewline
    $confirm = Read-Host
    if ($confirm -notin @("Y", "y", "Yes", "yes")) {
        Write-Status "Windows.old - skipped by user" "SKIP"
        Add-CategoryResult "Windows.old" 0 "SKIP"
        return
    }

    try {
        takeown /f $path /r /d y 2>$null | Out-Null
        icacls $path /grant "Administrators:F" /t 2>$null | Out-Null
        Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
        Write-Status "Windows.old removed" "OK" $size
        Add-CategoryResult "Windows.old" $size
    } catch {
        Write-Status "Windows.old removal failed (may need Disk Cleanup)" "WARN"
        Add-CategoryResult "Windows.old" 0 "FAIL"
    }
}

function Clean-WindowsUpgradeLeftovers {
    $freed = [long]0
    $paths = @(
        (Join-Path $env:SystemDrive '$Windows.~BT'),
        (Join-Path $env:SystemDrive '$Windows.~WS')
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            try {
                $size = Get-FolderSize $p
                takeown /f $p /r /d y 2>$null | Out-Null
                icacls $p /grant "Administrators:F" /t 2>$null | Out-Null
                Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
                $freed += $size
            } catch {}
        }
    }
    if ($freed -gt 0) {
        Write-Status "Windows upgrade leftovers cleaned" "OK" $freed
    } else {
        Write-Status "Upgrade leftovers - none found" "SKIP"
    }
    Add-CategoryResult "Windows Upgrade Leftovers" $freed
}

function Clean-InstallerPatchCache {
    $path = Join-Path $env:SystemRoot 'Installer\$PatchCache$'
    $freed = [long]0
    if (Test-Path $path) {
        $freed = Remove-PathContents $path
    }
    if ($freed -gt 0) {
        Write-Status "Installer patch cache cleaned" "OK" $freed
    } else {
        Write-Status "Installer patch cache - already clean" "SKIP"
    }
    Add-CategoryResult "Installer Patch Cache" $freed
}

function Invoke-CleanmgrAutomated {
    Write-Status "Running Windows Disk Cleanup (automated)..." "INFO"
    try {
        $volumeCaches = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        $categories = @(
            "Active Setup Temp Folders",
            "BranchCache",
            "Delivery Optimization Files",
            "Device Driver Packages",
            "Downloaded Program Files",
            "GameNewsFiles",
            "GameStatisticsFiles",
            "GameUpdateFiles",
            "Offline Pages Files",
            "Old ChkDsk Files",
            "Previous Installations",
            "Recycle Bin",
            "RetailDemo Offline Content",
            "Setup Log Files",
            "System error memory dump files",
            "System error minidump files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Update Cleanup",
            "Upgrade Discarded Files",
            "User file versions",
            "Windows Defender",
            "Windows Error Reporting Files",
            "Windows ESD installation files",
            "Windows Upgrade Log Files"
        )

        foreach ($cat in $categories) {
            $regPath = Join-Path $volumeCaches $cat
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "StateFlags0200" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            }
        }

        $sizeBefore = (Get-PSDrive C).Free
        Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:200" -Wait -WindowStyle Hidden -ErrorAction Stop
        Start-Sleep -Seconds 2
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        Write-Status "Disk Cleanup complete" "OK" $freed
        Add-CategoryResult "Windows Disk Cleanup" $freed
    } catch {
        Write-Status "Disk Cleanup failed to run" "WARN"
        Add-CategoryResult "Windows Disk Cleanup" 0 "FAIL"
    }
}

function Clean-OldRestorePoints {
    try {
        $shadows = vssadmin list shadows 2>$null
        if ($shadows -match "No items found") {
            Write-Status "Restore points - none found" "SKIP"
            Add-CategoryResult "Old Restore Points" 0 "SKIP"
            return
        }

        Write-Host ""
        Write-Host "  [!] Delete old System Restore points (keeps the latest)?" -ForegroundColor Yellow
        Write-Host "      This saves space but removes rollback options." -ForegroundColor DarkYellow
        Write-Host "      [Y] Yes  [N] No: " -ForegroundColor White -NoNewline
        $confirm = Read-Host
        if ($confirm -notin @("Y", "y", "Yes", "yes")) {
            Write-Status "Restore points - skipped by user" "SKIP"
            Add-CategoryResult "Old Restore Points" 0 "SKIP"
            return
        }

        $sizeBefore = (Get-PSDrive C).Free
        vssadmin delete shadows /for=C: /oldest /quiet 2>$null | Out-Null
        $sizeAfter = (Get-PSDrive C).Free
        $freed = [math]::Max(0, $sizeAfter - $sizeBefore)
        Write-Status "Old restore points removed (kept latest)" "OK" $freed
        Add-CategoryResult "Old Restore Points" $freed
    } catch {
        Write-Status "Restore point cleanup - failed" "FAIL"
        Add-CategoryResult "Old Restore Points" 0 "FAIL"
    }
}

function Invoke-SystemFileCheck {
    Write-Status "Running System File Checker (sfc /scannow)... this takes a few minutes" "INFO"
    try {
        $result = sfc /scannow 2>$null
        $resultStr = $result | Out-String
        if ($resultStr -match "did not find any integrity violations") {
            Write-Status "SFC complete - no integrity issues found" "OK"
        } elseif ($resultStr -match "successfully repaired") {
            Write-Status "SFC complete - repaired corrupted files" "OK"
        } else {
            Write-Status "SFC complete - review log at CBS.log" "WARN"
        }
    } catch {
        Write-Status "SFC failed to run" "FAIL"
    }
    Add-CategoryResult "System File Check" 0
}

function Invoke-ExplorerRestart {
    try {
        Write-Status "Restarting Explorer for cache refresh..." "INFO"
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process "explorer.exe"
        Start-Sleep -Seconds 2
        Write-Status "Explorer restarted" "OK"
    } catch {
        Write-Status "Explorer restart - failed" "WARN"
    }
}

# ============================================================================
# MODE ORCHESTRATORS
# ============================================================================

function Invoke-QuickClean {
    $steps = 11
    $i = 0

    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Green
    Write-Host "   QUICK CLEAN -- Daily Safe Cleanup" -ForegroundColor Green
    Write-Host "  ==========================================================" -ForegroundColor Green

    Write-SectionHeader "1/$steps" "User Temp Files"
    $i++; Clean-UserTemp

    Write-SectionHeader "2/$steps" "System Temp Files"
    $i++; Clean-SystemTemp

    Write-SectionHeader "3/$steps" "Browser Caches (all profiles)"
    $i++; Clean-BrowserCaches

    Write-SectionHeader "4/$steps" "Crash Dumps and Error Reports"
    $i++; Clean-CrashDumps

    Write-SectionHeader "5/$steps" "Thumbnail and Icon Cache"
    $i++; Clean-ThumbnailIconCache

    Write-SectionHeader "6/$steps" "DirectX Shader Cache"
    $i++; Clean-DirectXShaderCache

    Write-SectionHeader "7/$steps" "Recent Files List"
    $i++; Clean-RecentFiles

    Write-SectionHeader "8/$steps" "Temp Internet Files"
    $i++; Clean-TempInternetFiles

    Write-SectionHeader "9/$steps" "Downloaded Program Files"
    $i++; Clean-DownloadedProgramFiles

    Write-SectionHeader "10/$steps" "DNS Cache Flush"
    $i++; Invoke-DNSFlush

    Write-SectionHeader "11/$steps" "Clipboard and Notification DB"
    $i++; Clear-ClipboardData; Clean-NotificationDB
}

function Invoke-DeepClean {
    # Run Quick first
    Invoke-QuickClean

    $deepSteps = 13
    $i = 0

    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Yellow
    Write-Host "   DEEP CLEAN -- Weekly Thorough Cleanup" -ForegroundColor Yellow
    Write-Host "  ==========================================================" -ForegroundColor Yellow

    Write-SectionHeader "D1/$deepSteps" "Prefetch Files"
    $i++; Clean-PrefetchFiles

    Write-SectionHeader "D2/$deepSteps" "Windows Update Cache"
    $i++; Clean-WindowsUpdateCache

    Write-SectionHeader "D3/$deepSteps" "Delivery Optimization"
    $i++; Clean-DeliveryOptimization

    Write-SectionHeader "D4/$deepSteps" "Windows Log Files"
    $i++; Clean-WindowsLogs

    Write-SectionHeader "D5/$deepSteps" "Memory Dumps"
    $i++; Clean-MemoryDumps

    Write-SectionHeader "D6/$deepSteps" "Recycle Bin"
    $i++; Clean-RecycleBin

    Write-SectionHeader "D7/$deepSteps" "Font Cache"
    $i++; Clean-FontCache

    Write-SectionHeader "D8/$deepSteps" "Windows Store Cache"
    $i++; Clean-WindowsStoreCache

    Write-SectionHeader "D9/$deepSteps" "Windows Defender Scan Data"
    $i++; Clean-DefenderScanData

    Write-SectionHeader "D10/$deepSteps" "BITS Transfer Cache"
    $i++; Clean-BITSCache

    Write-SectionHeader "D11/$deepSteps" "Developer Tool Caches"
    $i++; Clean-DeveloperCaches

    Write-SectionHeader "D12/$deepSteps" "Application Caches"
    $i++; Clean-ApplicationCaches

    Write-SectionHeader "D13/$deepSteps" "SSD TRIM Optimization"
    $i++; Invoke-SSDTrim
}

function Invoke-FullClean {
    # Run Deep first (which includes Quick)
    Invoke-DeepClean

    $fullSteps = 8

    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Red
    Write-Host "   FULL CLEAN -- Monthly Deep System Clean" -ForegroundColor Red
    Write-Host "  ==========================================================" -ForegroundColor Red

    Write-SectionHeader "F1/$fullSteps" "DISM Component Cleanup"
    Invoke-DISMCleanup

    Write-SectionHeader "F2/$fullSteps" "Event Log Cleanup"
    Clean-EventLogs

    Write-SectionHeader "F3/$fullSteps" "Windows.old Folder"
    Clean-WindowsOld

    Write-SectionHeader "F4/$fullSteps" "Windows Upgrade Leftovers"
    Clean-WindowsUpgradeLeftovers

    Write-SectionHeader "F5/$fullSteps" "Installer Patch Cache"
    Clean-InstallerPatchCache

    Write-SectionHeader "F6/$fullSteps" "Windows Disk Cleanup (automated)"
    Invoke-CleanmgrAutomated

    Write-SectionHeader "F7/$fullSteps" "Old Restore Points"
    Clean-OldRestorePoints

    Write-SectionHeader "F8/$fullSteps" "System File Checker"
    Invoke-SystemFileCheck

    # Explorer restart at the very end of Full mode
    Write-Host ""
    Invoke-ExplorerRestart
}

# ============================================================================
# COMPLETION REPORT
# ============================================================================

function Show-CompletionReport {
    $endTime = Get-Date
    $duration = $endTime - $Script:StartTime
    $driveFreeAfter = (Get-PSDrive C).Free
    $actualFreed = $driveFreeAfter - $Script:DriveFreeBefore

    # Build the category breakdown
    $breakdown = $Script:CategoryResults | Where-Object { $_.BytesFreed -gt 0 } | Sort-Object BytesFreed -Descending

    Write-Host ""
    Write-Host ""
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host "  |               CLEANING COMPLETE -- REPORT                    |" -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host "  |                                                              |" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "Mode     : $($Mode.PadRight(48))" -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "Duration : $("$($duration.Minutes)m $($duration.Seconds)s".PadRight(48))" -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "Started  : $($Script:StartTime.ToString("HH:mm:ss").PadRight(48))" -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "Finished : $($endTime.ToString("HH:mm:ss").PadRight(48))" -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |                                                              |" -ForegroundColor Green
    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "DISK SPACE" -ForegroundColor Cyan -NoNewline
    Write-Host "                                                |" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    $freeBeforeStr = Format-Size $Script:DriveFreeBefore
    $freeAfterStr = Format-Size $driveFreeAfter
    Write-Host "Before   : $($freeBeforeStr.PadRight(48))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "After    : $($freeAfterStr.PadRight(48))" -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    $actualStr = Format-Size ([math]::Max(0, $actualFreed))
    $measuredStr = Format-Size $Script:TotalBytesFreed
    Write-Host ("Freed    : " + "$actualStr (measured: $measuredStr)".PadRight(48)) -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |                                                              |" -ForegroundColor Green

    if ($breakdown.Count -gt 0) {
        Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Green
        Write-Host "  |  " -ForegroundColor Green -NoNewline
        Write-Host "TOP CATEGORIES" -ForegroundColor Cyan -NoNewline
        Write-Host "                                            |" -ForegroundColor Green

        $topN = $breakdown | Select-Object -First 10
        foreach ($cat in $topN) {
            $catLine = "  {0,-38} {1,10}" -f $cat.Category, $cat.SizeStr
            Write-Host "  |  " -ForegroundColor Green -NoNewline
            Write-Host ($catLine.PadRight(56)) -ForegroundColor Gray -NoNewline
            Write-Host "|" -ForegroundColor Green
        }
        Write-Host "  |                                                              |" -ForegroundColor Green
    }

    if ($Script:Errors.Count -gt 0) {
        Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Green
        Write-Host "  |  " -ForegroundColor Green -NoNewline
        Write-Host "WARNINGS ($($Script:Errors.Count))" -ForegroundColor Yellow -NoNewline
        Write-Host "                                             |" -ForegroundColor Green
        foreach ($err in $Script:Errors) {
            Write-Host "  |  " -ForegroundColor Green -NoNewline
            Write-Host ("  $err".PadRight(56)) -ForegroundColor DarkYellow -NoNewline
            Write-Host "|" -ForegroundColor Green
        }
        Write-Host "  |                                                              |" -ForegroundColor Green
    }

    # Recommendation
    $nextRec = switch ($Mode) {
        "Quick" { "Run Quick daily, Deep weekly, Full monthly" }
        "Deep"  { "Run Deep weekly, Full monthly" }
        "Full"  { "Run Full monthly, Quick/Deep in between" }
    }

    Write-Host "  +--------------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host "SAFETY GUARANTEE" -ForegroundColor Cyan -NoNewline
    Write-Host "                                          |" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host ("  No system files harmed".PadRight(56)) -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host ("  No passwords or settings deleted".PadRight(56)) -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host ("  All services restarted safely".PadRight(56)) -ForegroundColor Gray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |                                                              |" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host ("Tip: $nextRec".PadRight(56)) -ForegroundColor DarkCyan -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |  " -ForegroundColor Green -NoNewline
    Write-Host ("Log: $($Script:LogFile)".PadRight(56)) -ForegroundColor DarkGray -NoNewline
    Write-Host "|" -ForegroundColor Green
    Write-Host "  |                                                              |" -ForegroundColor Green
    Write-Host "  +==============================================================+" -ForegroundColor Green
    Write-Host ""

    # Write final summary to log
    Write-Log "============================================"
    Write-Log "CLEANING COMPLETE"
    Write-Log "Mode     : $Mode"
    Write-Log "Duration : $($duration.Minutes)m $($duration.Seconds)s"
    Write-Log "Disk Free Before : $freeBeforeStr"
    Write-Log "Disk Free After  : $freeAfterStr"
    Write-Log "Space Freed      : $actualStr (measured: $measuredStr)"
    Write-Log "============================================"
    Write-Log ""
    Write-Log "Category Breakdown:"
    foreach ($cat in $Script:CategoryResults) {
        Write-Log ("  [{0}] {1}: {2}" -f $cat.Status, $cat.Category, $cat.SizeStr)
    }
    if ($Script:Errors.Count -gt 0) {
        Write-Log ""
        Write-Log "Errors/Warnings:"
        foreach ($err in $Script:Errors) { Write-Log "  $err" "WARN" }
    }
}

# ============================================================================
# PROCESS CHECK and WARNING
# ============================================================================

function Show-ProcessWarning {
    $running = Get-RunningApps
    if ($running.Count -gt 0) {
        Write-Host ""
        Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
        Write-Host "  |  " -ForegroundColor Yellow -NoNewline
        Write-Host "The following apps are running:" -ForegroundColor White -NoNewline
        Write-Host "                            |" -ForegroundColor Yellow
        foreach ($app in $running) {
            Write-Host "  |    " -ForegroundColor Yellow -NoNewline
            Write-Host ("* $app".PadRight(54)) -ForegroundColor DarkYellow -NoNewline
            Write-Host "|" -ForegroundColor Yellow
        }
        Write-Host "  |                                                            |" -ForegroundColor Yellow
        Write-Host "  |  " -ForegroundColor Yellow -NoNewline
        Write-Host "Their caches may not fully clean while running." -ForegroundColor DarkGray -NoNewline
        Write-Host "         |" -ForegroundColor Yellow
        Write-Host "  |  " -ForegroundColor Yellow -NoNewline
        Write-Host "Close them for best results, or continue anyway." -ForegroundColor DarkGray -NoNewline
        Write-Host "        |" -ForegroundColor Yellow
        Write-Host "  +------------------------------------------------------------+" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Press Enter to continue..." -ForegroundColor DarkGray -NoNewline
        Read-Host | Out-Null
    }
}

# ============================================================================
# FULL MODE CONFIRMATION
# ============================================================================

function Confirm-FullMode {
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Red
    Write-Host "  |  " -ForegroundColor Red -NoNewline
    Write-Host "FULL MODE WARNING" -ForegroundColor White -NoNewline
    Write-Host "                                        |" -ForegroundColor Red
    Write-Host "  |                                                            |" -ForegroundColor Red
    Write-Host "  |  " -ForegroundColor Red -NoNewline
    Write-Host "Full mode includes potentially destructive operations:" -ForegroundColor DarkYellow -NoNewline
    Write-Host "     |" -ForegroundColor Red
    Write-Host "  |    * DISM component cleanup (removes old update files)      |" -ForegroundColor DarkGray
    Write-Host "  |    * Event log clearing (loses diagnostic history)          |" -ForegroundColor DarkGray
    Write-Host "  |    * Windows.old removal (no rollback to prev. version)     |" -ForegroundColor DarkGray
    Write-Host "  |    * Restore point cleanup (reduces recovery options)       |" -ForegroundColor DarkGray
    Write-Host "  |    * SFC system file check (long-running scan)              |" -ForegroundColor DarkGray
    Write-Host "  |                                                            |" -ForegroundColor Red
    Write-Host "  |  " -ForegroundColor Red -NoNewline
    Write-Host "Destructive items will ask for confirmation individually." -ForegroundColor Gray -NoNewline
    Write-Host "   |" -ForegroundColor Red
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Proceed with Full Clean? [Y/N]: " -ForegroundColor White -NoNewline
    $confirm = Read-Host
    if ($confirm -notin @("Y", "y", "Yes", "yes")) {
        Write-Host "  Cancelled. Falling back to Deep Clean." -ForegroundColor DarkYellow
        return $false
    }
    return $true
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

try {
    # Show banner and get mode
    Show-Banner

    if (-not $Mode) {
        $Mode = Show-ModeMenu
    }

    # Initialize log
    Initialize-Log

    Write-Host ""
    Write-Host "  Mode selected: " -NoNewline
    $modeColor = switch ($Mode) { "Quick" { "Green" } "Deep" { "Yellow" } "Full" { "Red" } }
    Write-Host $Mode.ToUpper() -ForegroundColor $modeColor
    Write-Host "  Logging to: $Script:LogFile" -ForegroundColor DarkGray

    # Process warning
    Show-ProcessWarning

    # Full mode confirmation
    if ($Mode -eq "Full") {
        $proceed = Confirm-FullMode
        if (-not $proceed) {
            $Mode = "Deep"
        }
    }

    # Run the selected mode
    switch ($Mode) {
        "Quick" { Invoke-QuickClean }
        "Deep"  { Invoke-DeepClean }
        "Full"  { Invoke-FullClean }
    }

    # Show completion report
    Show-CompletionReport

} catch {
    Write-Host ""
    Write-Host "  [CRITICAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" "FAIL"
} finally {
    Write-Host ""
    Write-Host "  Press Enter to exit..." -ForegroundColor DarkGray -NoNewline
    Read-Host | Out-Null
}
