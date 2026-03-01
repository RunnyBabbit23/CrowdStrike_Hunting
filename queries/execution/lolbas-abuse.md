# Living-Off-the-Land Binary (LOLBAS) Abuse

## Description

Detects abuse of legitimate Windows binaries to download, execute, or decode malicious payloads — a technique known as "Living Off the Land" (LOTL/LOLBAS). Attackers use pre-installed trusted binaries to evade application allowlisting and reduce their footprint. Common abused binaries include `certutil`, `mshta`, `regsvr32`, `rundll32`, `bitsadmin`, `wscript`, `cscript`, and `msiexec`.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Execution / Defense Evasion |
| **Technique** | T1218 — System Binary Proxy Execution |
| **Sub-technique** | T1218.005 (mshta), T1218.010 (regsvr32), T1218.011 (rundll32), T1218.003 (cmstp) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — LOLBAS abuse is a strong indicator of post-exploitation or initial access activity when combined with network connections or unusual parent processes.

## Query

```logscale
// Detect known LOLBAS binaries executing with suspicious arguments
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "wscript.exe",
    "cscript.exe",
    "msiexec.exe",
    "installutil.exe",
    "cmstp.exe",
    "ieexec.exe",
    "pcalua.exe",
    "msbuild.exe",
    "wmic.exe",
    "forfiles.exe",
    "regasm.exe",
    "regsvcs.exe"
  ])
| CommandLine=/(http|https|ftp|\\\\|\.js|\.vbs|\.hta|javascript:|vbscript:|scrobj|frombase64|decode)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=200)
```

## Response Notes

**Triage steps:**
1. Review `CommandLine` for URLs, UNC paths, or encoded content — these confirm active misuse
2. Check `ParentBaseFileName` — Office apps, browsers, or email clients spawning LOLBAS are high priority
3. Pivot on `aid` and look for follow-on `NetworkConnectIP4` or `FileWritten` events within the same time window
4. For `certutil -decode`, check the output file path for PE files written to disk

**False positives:**
- `msiexec` is heavily used by software deployment systems — filter by known installer paths
- `regsvr32` is used for COM registration — baseline legitimate use before alerting
- Exclude: `| ParentBaseFileName!=/msiexec|msi|installer/i` and known software paths

## References

- https://attack.mitre.org/techniques/T1218/
- https://lolbas-project.github.io/
- https://redcanary.com/threat-detection-report/techniques/mshta/
