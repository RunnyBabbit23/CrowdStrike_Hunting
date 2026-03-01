# WMI-Based Lateral Movement

## Description

Detects Windows Management Instrumentation (WMI) being used to execute commands on remote hosts — a technique favored by APT actors because it uses a built-in Windows mechanism, generates minimal logs by default, and can be used without deploying any tools to the target. Common methods include `wmic /node:` for remote command execution, PowerShell's `Invoke-WmiMethod`, and CIM-based execution. Impacket's `wmiexec.py` also uses this technique.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement / Execution |
| **Technique** | T1021.006 — Remote Services: Windows Remote Management / T1047 — Windows Management Instrumentation |
| **Sub-technique** | WMI remote process creation |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Remote WMI execution from non-management systems is a strong lateral movement indicator, particularly when combined with unusual child processes.

## Query

```logscale
// WMIC remote execution (source side)
#event_simpleName=ProcessRollup2
| FileName=wmic.exe
| CommandLine=/\/node:/i
| CommandLine=/process call create/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: WMI Provider Host spawning shells (target-side detection)**

```logscale
// WmiPrvSE.exe spawning cmd.exe or powershell — WMI-based remote execution on this host
#event_simpleName=ProcessRollup2
| ParentBaseFileName=WmiPrvSE.exe
| in(FileName, values=["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: PowerShell WMI remote invocation**

```logscale
// PowerShell using WMI cmdlets for remote execution
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(Invoke-WmiMethod|Get-WmiObject|New-CimSession|Invoke-CimMethod)/i
| CommandLine=/(-ComputerName|-CimSession)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. For source-side detection: identify the target system from `/node:` in `CommandLine` and pivot to that host's events
2. For target-side detection (WmiPrvSE parent): this confirms WMI execution landed — examine the child process command line
3. Identify the credentials used — WMI typically requires explicit credentials or token impersonation
4. Look for file writes following WMI execution (payload deployment via `FileWritten`)
5. Check for follow-on network connections from the WMI-spawned process

**False positives:**
- System Center / SCCM uses WMI heavily for inventory and management — exclude known management servers by IP/hostname
- Monitoring solutions (Nagios, Zabbix, SolarWinds) may use WMI queries — these should not include `process call create`
- The `process call create` filter significantly reduces false positives compared to generic WMI detection

## References

- https://attack.mitre.org/techniques/T1047/
- https://www.crowdstrike.com/blog/how-crowdstrike-detects-wmi-based-attacks/
- https://www.fireeye.com/blog/threat-research/2019/03/time-psa-fireeye-and-crowdstrike-both-detect-wmi-based-lateral-movement.html
