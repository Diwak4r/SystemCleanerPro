# System Cleaner Pro

[ v2.0.0 ]

A ruthless, transparent Windows cleaner. 
No bloat. No hidden operations. Just powershell and precision.

// Features
— 3 Tiered Modes: Quick, Deep, Full.
— 30+ Vectors: caches, temps, telemetry.
— Traceable: Every action logged. 
— Self-Elevating: Demands admin, skips locked files silently.

// Initialization
1. Acquire SystemCleaner.bat and SystemCleaner.ps1.
2. Execute SystemCleaner.bat.
3. Select your depth.

> .\SystemCleaner.bat Deep

// The Tiers

[ 1 ] Quick — Surface level.
%TEMP%, browser caches, DNS flush, clipboard DB.

[ 2 ] Deep — Weekly purge.
Prefetch, Windows Update cache, memory dumps, recycle bin, developer caches.

[ 3 ] Full — Scorched earth.
DISM cleanup, event logs, Windows.old, installer patch cache. 
(Requires confirmation for destructive paths)

// Safety Constraints
Protected zones: System32, Registry hives, user credentials.
Mechanism: Test-Path verified, try/catch wrapped.

// Logs
Located at Desktop\CleanerLogs\
Traces every OK, SKIP, and FAIL.

// License
MIT. Unrestricted.
