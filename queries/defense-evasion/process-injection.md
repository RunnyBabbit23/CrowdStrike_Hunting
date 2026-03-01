# Process Injection Detection

## Description

Detects indicators of process injection — a technique where attackers inject malicious code into the address space of a legitimate process to execute under its identity, bypass security tools, and blend network traffic into trusted applications. Common injection types include classic DLL injection (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`), process hollowing, reflective DLL loading, and thread hijacking. CrowdStrike captures these at the kernel level via `SuspiciousPageAllocated` and `InjectedThread` events.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Privilege Escalation |
| **Technique** | T1055 — Process Injection |
| **Sub-technique** | T1055.001 (DLL), T1055.002 (PE), T1055.012 (Hollowing) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `SuspiciousPageAllocated`, `InjectedThread` |

## Severity

**High** — Confirmed injection events from CrowdStrike's sensor are high-fidelity indicators of post-exploitation activity.

## Query

```logscale
// Suspicious memory allocation in another process (classic injection precursor)
#event_simpleName=SuspiciousPageAllocated
| table([ComputerName, UserName, FileName, TargetFileName, AllocationType, ProtectType], limit=200)
```

**Variant: Remote thread injection detected**

```logscale
// Remote thread created in another process — direct injection indicator
#event_simpleName=InjectedThread
| table([ComputerName, UserName, FileName, TargetFileName, StartAddress], limit=200)
```

**Variant: Unsigned module loaded into a signed process**

```logscale
// DLL loaded from temp or user-writable path into a legitimate process
#event_simpleName=ImageLoad
| ImageFilePath=/(\\temp\\|\\appdata\\|\\public\\|\\users\\public)/i
| FileName!=/temp|appdata/i
| table([ComputerName, UserName, FileName, ImageFilePath, SHA256HashData], limit=200)
```

**Variant: Process hollowing indicator — PE written to suspended process**

```logscale
// Unsigned PE written to disk and loaded shortly after process creation
// Correlate PeFileWritten with subsequent ProcessRollup2 from same aid
#event_simpleName=PeFileWritten
| FilePath=/(\\temp\\|\\appdata\\|\\public\\|\\users\\public)/i
| table([ComputerName, UserName, FileName, FilePath, SHA256HashData], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the injecting process (`FileName`) and target process (`TargetFileName`)
2. If injection target is a common host like `explorer.exe`, `svchost.exe`, or `notepad.exe`, escalate immediately
3. Check `FileName`'s parent process for the full execution chain
4. Look for network connections from the injection target following the event — C2 communication often starts after injection
5. Collect memory dump of the target process for forensic analysis if possible

**False positives:**
- Security products (EDR, AV, DLP) legitimately inject into processes for monitoring
- Application frameworks (Java, .NET) perform memory operations that can resemble injection
- CrowdStrike's own agent will appear as a known-good source — focus on non-security-tool injectors

## References

- https://attack.mitre.org/techniques/T1055/
- https://www.crowdstrike.com/blog/process-injection-techniques/
- https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All.pdf
