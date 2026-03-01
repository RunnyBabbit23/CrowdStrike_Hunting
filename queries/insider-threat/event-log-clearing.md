# Windows Event Log Clearing

## Description

Detects deliberate clearing of Windows event logs — a classic anti-forensics technique used by both external attackers and malicious insiders to destroy audit trails. `wevtutil cl` and PowerShell's `Clear-EventLog` are the most common methods. Clearing the Security, System, or Application logs removes logon records, policy changes, and service activity. Insiders may clear logs after performing unauthorized access or data theft to eliminate the audit record.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion |
| **Technique** | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| **Sub-technique** | wevtutil, PowerShell Clear-EventLog |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Intentional event log clearing is a near-certain indicator of an attempt to destroy forensic evidence. Very few legitimate scenarios require clearing security or system logs.

## Query

```logscale
// wevtutil clear log command — most common log clearing method
#event_simpleName=ProcessRollup2
| FileName=wevtutil.exe
| CommandLine=/(cl|clear-log)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: PowerShell Clear-EventLog**

```logscale
// PowerShell-based event log clearing
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(Clear-EventLog|Remove-EventLog|Limit-EventLog.*OverwriteOlderThan)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Log service stopped or disabled**

```logscale
// Windows Event Log service stopped — prevents logging entirely
#event_simpleName=ProcessRollup2
| in(FileName, values=["sc.exe", "net.exe", "net1.exe"])
| CommandLine=/(stop|disable).*(eventlog|wevsvc|wevtutil|windows event log)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Log clearing via WMI**

```logscale
// WMI-based event log manipulation — bypasses direct wevtutil detection
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(Win32_NTEventlogFile|ClearEventLog|Invoke-WmiMethod.*eventlog)/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Bulk log file deletion (direct .evtx deletion)**

```logscale
// Direct deletion of .evtx log files from Windows/System32/winevt/Logs
#event_simpleName=FileDeleted
| FilePath=/\\Windows\\System32\\winevt\\Logs\\/i
| FileName=/\.evtx$/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: Audit policy disabled**

```logscale
// auditpol used to disable security auditing categories
#event_simpleName=ProcessRollup2
| FileName=auditpol.exe
| CommandLine=/(\/set.*\/success:disable|\/set.*\/failure:disable|\/clear|\/remove)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify which log channels were cleared from the `CommandLine` — Security log clearing is highest priority (contains logon records, privilege use, policy changes)
2. Review the process that ran the clear command — if it's a shell or script rather than an admin tool, this is highly suspicious
3. Check the timestamp — clearing logs immediately after suspicious activity (file access, USB insertion, after-hours logon) is the key correlation
4. Note: CrowdStrike captures this event from the kernel and does NOT rely on Windows Event Logs, so this detection survives log clearing
5. Initiate memory acquisition and forensic imaging immediately if confirmed malicious — VSS, pagefile, and process memory may still contain evidence

**False positives:**
- SIEM and log management solutions sometimes clear or rotate logs on schedule — verify by `ParentBaseFileName` (should be a service, not a user shell)
- Some compliance tasks involve log archiving followed by clearing — validate against change management
- This detection has very low false positive rates for interactive user sessions

## References

- https://attack.mitre.org/techniques/T1070/001/
- https://www.crowdstrike.com/blog/how-crowdstrike-detects-log-tampering/
- https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
