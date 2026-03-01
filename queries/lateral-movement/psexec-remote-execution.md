# PsExec and Remote Execution Tool Abuse

## Description

Detects use of PsExec and similar remote execution tools (`PsRemote`, `PAExec`, `RemCom`, `MoveIt`) to execute commands on remote systems. While PsExec is a legitimate Sysinternals tool, it is one of the most commonly abused utilities in ransomware and APT intrusions for lateral movement. Key indicators include the `PSEXESVC` service being created on the target, or PsExec being launched from unusual parent processes.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement |
| **Technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| **Sub-technique** | PsExec / remote service execution |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `RegGenericValueUpdate` |

## Severity

**High** — PsExec usage from non-IT systems or spawned by unexpected parent processes is a strong lateral movement indicator.

## Query

```logscale
// PsExec binary execution with remote target
#event_simpleName=ProcessRollup2
| FileName=/(psexec|psexec64|paexec|remcom)\.exe/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=200)
```

**Variant: PSEXESVC service creation on target (server-side detection)**

```logscale
// PSEXESVC service installed — indicates this host was a lateral movement target
#event_simpleName=ProcessRollup2
| FileName=PSEXESVC.exe
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Remote service creation from SMB (registry-based detection)**

```logscale
// Service registry key created by a network logon session (lateral movement via SC/PsExec)
#event_simpleName=RegKeyCreated
| RegObjectName=/SYSTEM\\CurrentControlSet\\Services\\PSEXE/i
| table([ComputerName, UserName, RegObjectName, FileName], limit=200)
```

**Variant: Commands run from unusual parent (PsExec shell on target)**

```logscale
// cmd.exe or powershell.exe spawned by PSEXESVC — command execution on lateral movement target
#event_simpleName=ProcessRollup2
| in(FileName, values=["cmd.exe", "powershell.exe"])
| ParentBaseFileName=PSEXESVC.exe
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. On the source host: identify what process launched PsExec and from what directory
2. On the target host: look for PSEXESVC service creation and subsequent child process execution
3. Examine `CommandLine` for the target hostname/IP and command being executed
4. Pivot on `UserName` — PsExec typically passes credentials explicitly or uses current token
5. Check for file drops from the lateral movement session: `PeFileWritten` events on the target

**False positives:**
- IT administrators may legitimately use PsExec for remote management — baseline by `UserName` and `ComputerName`
- Some managed service providers use PsExec for deployment scripts
- Consider restricting PsExec via AppLocker or WDAC and treating any execution as suspicious

## References

- https://attack.mitre.org/techniques/T1021/002/
- https://www.crowdstrike.com/blog/how-crowdstrike-detects-lateral-movement-techniques/
- https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
