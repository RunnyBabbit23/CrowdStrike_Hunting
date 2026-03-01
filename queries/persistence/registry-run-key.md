# Registry Run Key Persistence

## Description

Detects modifications to common Windows autorun registry keys used by attackers to maintain persistence across reboots. Malware and post-exploitation frameworks frequently write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, the equivalent `HKLM` key, and other autostart locations to survive system restarts. This is one of the oldest and most common persistence mechanisms.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence |
| **Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **Sub-technique** | Registry Run Key |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `RegGenericValueUpdate`, `RegKeyCreated` |

## Severity

**High** — Modifications to autorun keys by non-standard processes are a reliable indicator of persistence installation.

## Query

```logscale
// Detect writes to common autorun registry keys
#event_simpleName=/RegGenericValueUpdate|RegKeyCreated/
| RegObjectName=/(
    Software\\Microsoft\\Windows\\CurrentVersion\\Run|
    Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|
    Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx|
    Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon|
    Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options|
    SYSTEM\\CurrentControlSet\\Services|
    Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders|
    Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders|
    Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run
  )/i
| table([ComputerName, UserName, RegObjectName, RegValueName, RegStringValue, FileName], limit=200)
```

**Variant: Filter to non-standard processes writing to run keys**

```logscale
// Run key writes by processes outside system directories
#event_simpleName=RegGenericValueUpdate
| RegObjectName=/Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
| FileName!=/\b(installer|setup|msiexec|msi|sccm|ccmsetup|onedrive|googlechrome|msedge|teams|zoom)\b/i
| table([ComputerName, UserName, FileName, RegObjectName, RegValueName, RegStringValue], limit=200)
```

## Response Notes

**Triage steps:**
1. Examine `RegStringValue` to identify the executable or command being set to autorun
2. Check the process (`FileName`) that wrote the key — installer processes are expected; shells, scripts, and unknown binaries are suspicious
3. Correlate the written value with file creation events (`PeFileWritten`) to confirm binary deployment
4. Pivot on `aid` to see the full activity chain preceding this write

**False positives:**
- Software installers routinely add run keys during installation — filter by known installer hashes
- OneDrive, Teams, Chrome, and other endpoint software write to run keys on update
- Baseline your environment for known-good entries before alerting

## References

- https://attack.mitre.org/techniques/T1547/001/
- https://www.sans.org/blog/autoruns-for-threat-hunting/
