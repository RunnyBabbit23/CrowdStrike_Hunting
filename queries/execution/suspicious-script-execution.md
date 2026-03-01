# Suspicious Script Interpreter Execution

## Description

Detects script interpreters (`wscript.exe`, `cscript.exe`, `mshta.exe`, `python.exe`, `perl.exe`) executing scripts from anomalous locations such as `%TEMP%`, `%APPDATA%`, `%PUBLIC%`, browser download directories, or directly from email attachment staging paths. Threat actors frequently deliver and execute scripts from these writable locations during initial access and execution phases.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Execution |
| **Technique** | T1059.005 — Visual Basic / T1059.006 — Python / T1059.007 — JavaScript |
| **Sub-technique** | Script execution from user-writable paths |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Scripts running from temp or download directories are rarely legitimate enterprise activity and frequently indicate initial access or dropper execution.

## Query

```logscale
// Script interpreter running a file from a suspicious location
#event_simpleName=ProcessRollup2
| in(FileName, values=["wscript.exe", "cscript.exe", "mshta.exe", "python.exe", "python3.exe", "perl.exe", "ruby.exe"])
| CommandLine=/(\\temp\\|\\tmp\\|\\appdata\\|\\public\\|\\downloads\\|\\desktop\\|\\users\\public|C:\\ProgramData\\)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Office macro spawning script interpreter**

```logscale
// Office applications spawning scripting engines (macro execution indicator)
#event_simpleName=ProcessRollup2
| in(FileName, values=["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "cmd.exe"])
| ParentBaseFileName=/(winword|excel|outlook|powerpnt|msaccess|onenote)\.exe/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the script file being executed from the `CommandLine` field and retrieve it for analysis
2. Check `ParentBaseFileName` — Office or email client parents are near-certain malicious execution
3. Search for the script file using `FileWritten` events in the same time window to identify how it arrived
4. Look for follow-on network connections or child processes (pivot on `aid` and `ProcessId`)

**False positives:**
- Developer environments may run Python from temp directories during builds (rare in enterprise)
- Some legitimate admin scripts may run from `%APPDATA%` — baseline by `UserName` and script path
- Exclude known developer machines by hostname or group tag

## References

- https://attack.mitre.org/techniques/T1059/005/
- https://attack.mitre.org/techniques/T1059/007/
- https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
