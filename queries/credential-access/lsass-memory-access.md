# LSASS Memory Access / Credential Dumping

## Description

Detects access to the Local Security Authority Subsystem Service (`lsass.exe`) process memory — the primary technique used by tools like Mimikatz, ProcDump, Task Manager (manual dump), and Cobalt Strike's `sekurlsa::logonpasswords` to extract plaintext credentials, NTLM hashes, and Kerberos tickets from memory. CrowdStrike's sensor captures these access events at the kernel level, providing high-fidelity visibility without requiring AV signatures.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Sub-technique** | Process memory read, minidump |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `SuspiciousPageAllocated` |

## Severity

**High** — Any non-SYSTEM/non-security-product access to LSASS memory is a critical incident indicator.

## Query

```logscale
// Processes accessing lsass.exe via command-line tools (procdump, taskmgr dump, etc.)
#event_simpleName=ProcessRollup2
| CommandLine=/lsass/i
| FileName!=/MsMpEng\.exe|csrss\.exe|lsm\.exe|werfault\.exe|wininit\.exe|services\.exe|winlogon\.exe/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=200)
```

**Variant: Procdump targeting LSASS**

```logscale
// ProcDump or ProcExp with lsass as target
#event_simpleName=ProcessRollup2
| FileName=/(procdump|procdump64|processhacker|processdump)\.exe/i
| CommandLine=/lsass/i
| table([ComputerName, UserName, FileName, CommandLine, SHA256HashData], limit=200)
```

**Variant: Task Manager manual dump**

```logscale
// lsass.dmp written to disk via Task Manager or similar
#event_simpleName=FileWritten
| FileName=/lsass.*\.dmp/i
| table([ComputerName, UserName, FileName, FilePath], limit=200)
```

**Variant: Suspicious memory allocation targeting LSASS (Mimikatz-style)**

```logscale
// Suspicious page allocations — memory injection or dumping
#event_simpleName=SuspiciousPageAllocated
| TargetFileName=/lsass\.exe/i
| table([ComputerName, UserName, FileName, TargetFileName, CommandLine], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the process accessing LSASS — any non-OS binary is highly suspicious
2. Check `SHA256HashData` — known-bad tools (Mimikatz, ProcDump with lsass arguments) should be flagged immediately
3. Check if a `.dmp` file was created via `FileWritten` events — indicates exfiltration risk
4. Pivot on `aid` to see follow-on network connections (credential use or exfil)
5. Determine if Credential Guard is enabled on affected hosts — if so, attacker likely has captured NTLM hashes only

**False positives:**
- CrowdStrike Falcon itself accesses LSASS for its own credential protection modules
- Windows error reporting (`WerFault.exe`) accesses LSASS on crash
- The filter above excludes most known-good processes; review any remaining hits manually

## References

- https://attack.mitre.org/techniques/T1003/001/
- https://www.crowdstrike.com/blog/credential-theft-mimikatz/
- https://posts.specterops.io/lsass-memory-dumps-are-stealthier-than-you-think-261fbe105b47
