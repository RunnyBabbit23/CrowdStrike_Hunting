# WSL Usage with Claude / AI Tools

## Description

Detects Windows Subsystem for Linux (WSL) being used to run Claude CLI (`claude`), interact with the Anthropic API, or execute AI-assisted workflows — relevant for insider threat monitoring, DLP, and policy enforcement. WSL provides a Linux environment that can bypass Windows DLP controls, endpoint monitoring gaps, and audit logging that relies on Win32 event paths. Attackers and insiders may also use WSL to obfuscate activity or bypass application allowlisting.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Exfiltration |
| **Technique** | T1202 — Indirect Command Execution / T1059.004 — Unix Shell |
| **Sub-technique** | T1567 — Exfiltration Over Web Service (via WSL process) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `DnsRequest`, `NetworkConnectIP4` |

## Severity

**Medium** — WSL itself is a legitimate developer tool; severity is elevated when combined with AI tool access, data staging, or policy violation context.

## Query

```logscale
// WSL process spawning claude CLI or python with Anthropic SDK
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost|wslservice|bash|sh|zsh)\.exe/i
| CommandLine=/(claude|anthropic|api\.anthropic\.com|sk-ant-)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: WSL making outbound DNS queries for Anthropic domains**

```logscale
// DNS queries originating from WSL processes
#event_simpleName=DnsRequest
| FileName=/(wsl|wslhost|wslservice|vmmemwsl)/i
| DomainName=/(anthropic\.com|claude\.ai)/i
| table([ComputerName, UserName, DomainName, FileName, @timestamp], limit=200)
```

**Variant: Claude Code running inside WSL**

```logscale
// Claude Code CLI invocation through WSL
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost|bash|sh|zsh)\.exe/i
| CommandLine=/(^|\s)claude(\s|$)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, FilePath, @timestamp], limit=200)
```

**Variant: WSL used to curl/wget Anthropic API (manual API calls)**

```logscale
// curl or wget invoking Anthropic API endpoints from WSL
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost|bash|sh|zsh)\.exe/i
| in(FileName, values=["curl", "wget", "python", "python3", "node"])
| CommandLine=/(api\.anthropic\.com|claude\.ai)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: WSL activity with Anthropic API key in args**

```logscale
// Anthropic API key exposed in WSL process command line
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost|bash|sh|zsh)\.exe/i
| CommandLine=/sk-ant-[a-zA-Z0-9\-_]{20,}/
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: All WSL process execution (baselining)**

```logscale
// Baseline all WSL usage — understand who uses WSL and what they run
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/(wsl|wslhost)\.exe/i
| groupBy([ComputerName, UserName, FileName], function=count(as=exec_count))
| sort(exec_count, order=desc)
| table([ComputerName, UserName, FileName, exec_count])
```

**Variant: WSL network connections to external services (data egress)**

```logscale
// Network connections from WSL host process to non-RFC1918 addresses
#event_simpleName=NetworkConnectIP4
| FileName=/(wsl|wslhost|vmmemwsl)/i
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| RemotePort=443
| groupBy([ComputerName, UserName, RemoteAddressIP4, FileName], function=count(as=conn_count))
| sort(conn_count, order=desc)
```

## Response Notes

**Triage steps:**
1. Baseline first — identify which users legitimately use WSL in your environment (developers, security teams, researchers)
2. For Claude/AI tool access: assess whether the use is authorized and whether sensitive data could be submitted (files piped to the command, clipboard content)
3. Check the parent process chain: WSL invoked by a user interactively (expected) vs. WSL spawned by an Office document or unusual binary (suspicious)
4. Review WSL network connections: `NetworkConnectIP4` from `wslhost.exe` or `vmmemWSL` shows Linux-side traffic at the Windows level
5. Look for file staging near WSL Claude usage — large `FileWritten` or `FileOpenInfo` events before the AI tool session may indicate data preparation for submission

**Coverage notes:**
- CrowdStrike's sensor runs in the Windows host, so Linux binaries within WSL are captured via the WSL interop process (`wsl.exe`, `wslhost.exe`) and the VM memory process (`vmmemWSL`)
- Deep Linux-level process visibility inside WSL requires the Falcon sensor for Linux installed within the WSL distribution
- Network activity from WSL appears attributed to `wslhost.exe` or `vmmemWSL` in Windows network events

**False positives:**
- Developer workflows using Claude Code for coding assistance (legitimate)
- Security researchers using Claude for analysis (legitimate)
- This is primarily a monitoring/baselining hunt — combine with data access and policy context before escalating

## References

- https://attack.mitre.org/techniques/T1202/
- https://learn.microsoft.com/en-us/windows/wsl/about
- https://www.crowdstrike.com/blog/windows-subsystem-for-linux-threat-detection/
- https://docs.anthropic.com/en/docs/claude-code
