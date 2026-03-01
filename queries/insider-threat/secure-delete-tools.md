# Secure Delete / Anti-Forensics Tool Usage

## Description

Detects use of secure deletion and data wiping tools — indicators of an insider attempting to destroy evidence of their activity after exfiltrating data. Tools like SDelete (Sysinternals), Eraser, `cipher /w`, CCleaner with secure delete, and `dd` (via WSL) overwrite file contents before deletion to prevent forensic recovery. Running these tools after bulk file access, archiving, or USB activity is a strong anti-forensics signal.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion |
| **Technique** | T1070.004 — Indicator Removal: File Deletion |
| **Sub-technique** | T1485 — Data Destruction (secure wipe), T1070.001 — Clear Windows Event Logs |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Secure deletion after bulk data access is a strong anti-forensics indicator; treat as active evidence destruction.

## Query

```logscale
// Secure delete and data wiping tool execution
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "sdelete.exe", "sdelete64.exe",
    "Eraser.exe",
    "CCleaner.exe", "CCleaner64.exe",
    "BleachBit.exe",
    "FileShredder.exe",
    "Freeraser.exe",
    "WipeFile.exe",
    "DiskWipe.exe",
    "DBAN.exe",
    "nwipe.exe",
    "shred.exe"
  ])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Windows built-in secure overwrite (cipher /w)**

```logscale
// cipher.exe /w — overwrites free space to prevent file recovery
#event_simpleName=ProcessRollup2
| FileName=cipher.exe
| CommandLine=/\/w/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: SDelete targeting specific file types or directories**

```logscale
// SDelete run with specific paths — targeted evidence destruction
#event_simpleName=ProcessRollup2
| FileName=/(sdelete|sdelete64)\.exe/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Format command used to wipe drive**

```logscale
// format.exe used on non-system drive — potential evidence destruction on USB/data drive
#event_simpleName=ProcessRollup2
| FileName=format.com
| CommandLine=/\/[qp]/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: PowerShell-based file overwrite loops (custom wiping)**

```logscale
// PowerShell used to overwrite files with zeros/random data before deletion
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(
    \[byte\[\]\].*\(0\)|
    Random\].*GetBytes|
    \[IO\.File\]::WriteAllBytes|
    StreamWriter.*Flush|
    Remove-Item.*-Recurse.*-Force|
    Clear-Content.*-Force
  )/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: WSL dd or shred (Linux-based wiping through WSL)**

```logscale
// dd or shred commands through WSL — Linux secure delete bypassing Windows tool detection
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost|bash|sh)\.exe/i
| CommandLine=/(shred\s+-|dd\s+if=\/dev\/zero|dd\s+if=\/dev\/urandom)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Determine WHEN this ran relative to other suspicious activity — secure delete following bulk file access or USB activity is the critical correlation
2. Identify what was deleted — CrowdStrike's `FileDeleted` events in the same time window may show the target paths
3. For `cipher /w` and `sdelete` with free space wiping, focus on the timing rather than specific files (free space wiping is evidence destruction regardless of specific files)
4. Collect a forensic image of the endpoint immediately — even secure delete tools sometimes leave artifacts (file system metadata, VSS, prefetch)
5. Review the parent process — interactive user session vs. scheduled task/script running the wiper

**False positives:**
- IT teams run SDelete and cipher during endpoint decommissioning — check with IT ops
- CCleaner is widely used for routine cleanup — the standalone deletion feature is lower risk than aggressive wipe options
- Security-conscious users may use BleachBit or Eraser for personal privacy — policy context matters

## References

- https://attack.mitre.org/techniques/T1070/004/
- https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
- https://www.crowdstrike.com/blog/digital-forensics-anti-forensics/
