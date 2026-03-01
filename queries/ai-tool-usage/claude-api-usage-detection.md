# Claude AI / Anthropic API Usage Detection (Insider Threat)

## Description

Detects endpoints or users accessing Anthropic's Claude API or Claude.ai web service — relevant in insider threat scenarios, DLP programs, or environments where AI tool usage is regulated or restricted. Hunting targets include direct API calls to `api.anthropic.com`, browser-based access to `claude.ai`, local Claude clients (Claude Desktop, Claude Code CLI), and processes making HTTP requests to Anthropic's infrastructure. This is an informational/monitoring hunt — activity is suspicious only in context of policy violations or data handling concerns.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration / Collection |
| **Technique** | T1567 — Exfiltration Over Web Service |
| **Sub-technique** | T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `DnsRequest`, `NetworkConnectIP4`, `ProcessRollup2` |

## Severity

**Low (Monitoring)** — Usage of Claude is not inherently malicious; severity depends on data classification policies, what data is being submitted, and whether usage is authorized.

## Query

```logscale
// DNS queries to Anthropic / Claude domains
#event_simpleName=DnsRequest
| DomainName=/(
    claude\.ai|
    anthropic\.com|
    api\.anthropic\.com|
    console\.anthropic\.com|
    usepromptly\.com
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=500)
```

**Variant: Network connections to Anthropic API infrastructure**

```logscale
// Outbound HTTPS connections to Anthropic domains — API calls or browser sessions
#event_simpleName=NetworkConnectIP4
| RemotePort=443
// Anthropic primarily uses AWS infrastructure; DNS-based detection above is more reliable
// This variant uses a join with DNS events for IP-to-domain correlation
| join({
    #event_simpleName=DnsRequest
    | DomainName=/anthropic\.com|claude\.ai/i
  }, field=[aid, ComputerName], include=[DomainName])
| table([ComputerName, UserName, RemoteAddressIP4, DomainName, FileName, @timestamp], limit=200)
```

**Variant: Claude Code CLI or Claude Desktop process execution**

```logscale
// Claude CLI tool, Claude Desktop, or Anthropic SDK usage via process name
#event_simpleName=ProcessRollup2
| in(FileName, values=["claude", "claude.exe", "Claude.exe", "Claude Desktop.exe"])
| table([ComputerName, UserName, FileName, CommandLine, FilePath, @timestamp], limit=200)
```

**Variant: Anthropic SDK / Python API client execution**

```logscale
// Python or Node.js processes invoking the Anthropic SDK
#event_simpleName=ProcessRollup2
| in(FileName, values=["python.exe", "python3", "python3.exe", "node.exe", "node"])
| CommandLine=/(anthropic|claude|api\.anthropic)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Claude API key in environment or command line (credential hygiene)**

```logscale
// API key pattern in command line arguments — accidental key exposure
#event_simpleName=ProcessRollup2
| CommandLine=/sk-ant-[a-zA-Z0-9\-_]{20,}/
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: Bulk usage by user across endpoints (insider threat aggregation)**

```logscale
// Users accessing Claude AI across multiple machines or high frequency — potential data exfil pattern
#event_simpleName=DnsRequest
| DomainName=/anthropic\.com|claude\.ai/i
| groupBy([UserName, ComputerName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([UserName, ComputerName, query_count])
```

## Response Notes

**Triage steps:**
1. Determine if AI tool usage is permitted in your organization's policy — many organizations have approved AI tools; unauthorized use may only be a policy violation
2. Correlate Claude access timing with bulk file access, data staging, or large upload events — if sensitive data was accessed before Claude queries, investigate data submission risk
3. Check which specific Claude features are being used: API (programmatic — higher risk for automated data submission), web (browser — standard chat usage)
4. Review `CommandLine` for Anthropic API key patterns that may indicate an unauthorized developer integration pulling data
5. For Claude Code CLI users: check `CommandLine` for flags like `--print` or piped input that may suggest sensitive content is being submitted

**Contextual questions for triage:**
- Is the user in a role where AI tool usage would be expected (developer, analyst)?
- Is the access from a corporate device or a personal device?
- Was there large file/clipboard activity in the same session window?
- Does the organization's DLP policy apply to AI tool submissions?

**False positives:**
- Security teams using Claude for threat intel, analysis, or hunting assistance (like this library!)
- Developers building applications with the Anthropic SDK
- Authorized AI pilot program participants
- This query should be treated as **informational enrichment** rather than a standalone alert

## References

- https://attack.mitre.org/techniques/T1567/
- https://docs.anthropic.com/en/api/getting-started
- https://www.cisa.gov/sites/default/files/2023-11/Cybersecurity-Best-Practices-for-AI.pdf
