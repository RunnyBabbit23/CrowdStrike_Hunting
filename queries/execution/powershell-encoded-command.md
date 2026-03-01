# PowerShell Encoded Command Execution

## Description

Detects PowerShell processes launched with base64-encoded command arguments (`-EncodedCommand` / `-enc`). Attackers commonly encode payloads to obfuscate malicious commands from casual inspection and bypass simple string-matching defenses. This is one of the most prevalent execution techniques seen in commodity malware, APT intrusions, and post-exploitation frameworks such as Cobalt Strike and Metasploit.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Execution |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Sub-technique** | Encoded/Obfuscated commands |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Encoded PowerShell is rarely used legitimately in interactive contexts; most enterprise tooling calls scripts by path rather than encoded inline commands.

## Query

```logscale
// Detect PowerShell launched with encoded command flags
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/([\s\-]+)(e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)[\s]+[A-Za-z0-9+/=]{20,}/i
| table([ComputerName, UserName, ParentBaseFileName, CommandLine, SHA256HashData], limit=200)
```

## Response Notes

**Triage steps:**
1. Decode the base64 payload and review the plaintext command — use `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...))` or CyberChef
2. Pivot on `aid` to see what the PowerShell process spawned and what network connections followed
3. Check `ParentBaseFileName` — Office applications, browsers, or `wscript.exe` as parent are high-confidence indicators of malicious activity
4. Review `SHA256HashData` against threat intel feeds

**False positives:**
- Some legitimate administrative tools (e.g., SCCM, third-party management agents) may use encoded commands
- Exclude known-good parent processes and hashes after baselining: `| ParentBaseFileName!=/sccm|configmgr/i`

## References

- https://attack.mitre.org/techniques/T1059/001/
- https://www.ired.team/offensive-security/code-execution/powershell-encoded-command
