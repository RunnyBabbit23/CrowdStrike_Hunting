# Suspicious Service Installation

## Description

Detects the creation of new Windows services via `sc.exe`, `net.exe`, or direct service registry manipulation pointing to executables in user-writable or non-standard paths. Services run under SYSTEM by default and restart automatically, making them a highly effective persistence and privilege escalation mechanism. Many backdoors, RATs, and ransomware families install themselves as services.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence / Privilege Escalation |
| **Technique** | T1543.003 — Create or Modify System Process: Windows Service |
| **Sub-technique** | sc.exe / registry-based service creation |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `RegGenericValueUpdate` |

## Severity

**High** — New services created from non-system paths or by non-administrative tools are a reliable persistence indicator.

## Query

```logscale
// Service creation via sc.exe pointing to suspicious binary locations
#event_simpleName=ProcessRollup2
| FileName=sc.exe
| CommandLine=/create/i
| CommandLine=/(\\temp\\|\\appdata\\|\\public\\|\\users\\public|\\downloads\\|C:\\ProgramData\\[^\\]+\\[^\\]+\.exe)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Service binary path written via registry**

```logscale
// Direct registry write to service ImagePath — bypasses sc.exe detection
#event_simpleName=RegGenericValueUpdate
| RegObjectName=/SYSTEM\\CurrentControlSet\\Services\\/i
| RegValueName=/(ImagePath|ObjectName)/i
| RegStringValue=/(\\temp\\|\\appdata\\|\\public\\|\\users\\public|cmd\.exe|powershell|\.bat|\.ps1|\.vbs)/i
| table([ComputerName, UserName, RegObjectName, RegValueName, RegStringValue, FileName], limit=200)
```

**Variant: All new service registry keys (baseline)**

```logscale
// Any new service key created — for baselining and anomaly detection
#event_simpleName=RegKeyCreated
| RegObjectName=/SYSTEM\\CurrentControlSet\\Services\\/i
| groupBy([ComputerName, RegObjectName], function=count())
| sort(count_, order=desc)
```

## Response Notes

**Triage steps:**
1. Extract the service binary path from `CommandLine` (`binpath=`) or `RegStringValue`
2. Verify the binary: check `SHA256HashData` against threat intel, look for `PeFileWritten` events that dropped it
3. Check if the service was actually started with `sc start` or an equivalent after creation
4. Pivot on `aid` to see full context — what process created the service and what happened next

**False positives:**
- Legitimate software installers frequently create services — correlate with `msiexec` parent processes
- Endpoint security products and backup agents create services at install time
- Exclude known paths: `| RegStringValue!=/Program Files|Windows|System32/i` (adjust for your environment)

## References

- https://attack.mitre.org/techniques/T1543/003/
- https://pentestlab.blog/2017/11/20/windows-kernel-exploits/
