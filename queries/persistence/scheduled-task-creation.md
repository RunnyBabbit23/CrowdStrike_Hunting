# Suspicious Scheduled Task Creation

## Description

Detects the creation of scheduled tasks via `schtasks.exe` or `at.exe` with suspicious configurations — particularly tasks pointing to executables in user-writable directories, tasks running scripts, or tasks using encoded/obfuscated commands. Scheduled tasks are a favored persistence mechanism because they survive reboots, can run under SYSTEM context, and blend in with legitimate administrative use.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence / Privilege Escalation |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Sub-technique** | schtasks.exe / Task Scheduler API |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Scheduled tasks created with non-standard executable paths or by unexpected parent processes are a strong persistence indicator.

## Query

```logscale
// Scheduled task creation pointing to suspicious locations or scripts
#event_simpleName=ProcessRollup2
| FileName=/(schtasks|at)\.exe/i
| CommandLine=/\/create/i
| CommandLine=/(\\temp\\|\\appdata\\|\\public\\|\\users\\public|powershell|cmd\.exe|wscript|cscript|mshta|\.vbs|\.js|\.hta|\.bat|\\downloads\\)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Any scheduled task creation (for baselining)**

```logscale
// All scheduled task creation events — use for baselining and anomaly detection
#event_simpleName=ProcessRollup2
| FileName=schtasks.exe
| CommandLine=/\/create/i
| groupBy([ComputerName, UserName, CommandLine], function=count())
| sort(count_, order=desc)
```

**Variant: Tasks scheduled to run at logon or SYSTEM level**

```logscale
// High-privilege or logon-triggered tasks — likely persistence
#event_simpleName=ProcessRollup2
| FileName=schtasks.exe
| CommandLine=/\/create/i
| CommandLine=/(\/ru\s+system|\/sc\s+onlogon|\/sc\s+onstart|\/rl\s+highest)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. Extract the task name (`/tn`) and the action executable (`/tr`) from `CommandLine`
2. Verify whether the executable in `/tr` exists and is signed — check with `PeFileWritten` events
3. Identify who created the task: expected admin tools vs shells, scripts, or suspicious parent processes
4. Check for scheduled task XML files in `C:\Windows\System32\Tasks\` via file creation events

**False positives:**
- Endpoint management tools (SCCM, Intune, Ansible) create scheduled tasks during deployment
- Software updaters (Chrome, Adobe, Java) register tasks for update checking
- Filter known management platforms: `| ParentBaseFileName!=/ccmexec|cmstp|msiexec/i`

## References

- https://attack.mitre.org/techniques/T1053/005/
- https://redcanary.com/threat-detection-report/techniques/scheduled-task/
