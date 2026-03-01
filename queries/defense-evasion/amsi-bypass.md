# AMSI Bypass Attempts

## Description

Detects attempts to bypass the Antimalware Scan Interface (AMSI) — the Windows API that security products hook to scan scripts and code before execution. Attackers patch `amsi.dll` in memory, use reflection to disable AMSI, or leverage known bypass strings to prevent PowerShell, JScript, and VBScript content from being scanned. Detection is based on PowerShell command lines containing known bypass patterns and suspicious reflection usage.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion |
| **Technique** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Sub-technique** | AMSI bypass / memory patching |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `CommandHistory` |

## Severity

**High** — AMSI bypass is a deliberate evasion action that almost always precedes malicious PowerShell script execution.

## Query

```logscale
// Known AMSI bypass strings and patterns in PowerShell command lines
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(
    amsiInitFailed|
    amsiContext|
    AmsiScanBuffer|
    AmsiScanString|
    amsi\.dll|
    \[Runtime\.InteropServices\.Marshal\]::Copy|
    SetLength\(0\)|
    GetDelegateForFunctionPointer|
    VirtualProtect.*amsi|
    \[Ref\]\.Assembly\.GetType.*Automation|
    System\.Management\.Automation.*amsi|
    NonPublic.*Static.*amsi|
    Matt.*Graeber|
    Bypass.*AMSI|
    Disable.*AMSI
  )/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Reflection-based AMSI patching (obfuscated detection)**

```logscale
// PowerShell using reflection to access non-public members of security-related assemblies
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(GetField|GetMethod|SetValue|GetValue)/i
| CommandLine=/(NonPublic|IgnoreCase|Static)/i
| CommandLine=/(Automation|SecurityZone|amsi|ScanContent)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Downgrade attack (force PowerShell v2 to avoid AMSI)**

```logscale
// PowerShell version downgrade to v2 — bypasses AMSI and script block logging
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(-version\s*2|-v\s*2\.0)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. Decode or examine the full `CommandLine` — AMSI bypass is typically a precursor; look for the actual payload that follows
2. Check `ParentBaseFileName` — if spawned by Office apps, browsers, or email clients, this is almost certainly a phishing-delivered payload
3. Review the `CommandHistory` event type for the same `aid` in a short time window after the AMSI bypass to see subsequent commands
4. Check if CrowdStrike AMSI protection triggered alongside this detection for additional context

**False positives:**
- Security researchers and red teamers running authorized assessments — correlate with pentest windows
- Some PowerShell modules mention AMSI in documentation strings loaded at runtime (rare)
- The specificity of the bypass strings makes false positives extremely rare in production environments

## References

- https://attack.mitre.org/techniques/T1562/001/
- https://www.crowdstrike.com/blog/amsi-how-windows-10-plans-to-stop-script-based-attacks/
- https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
