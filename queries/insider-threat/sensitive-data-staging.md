# Sensitive Data Staging Before AI Tool Access

## Description

Detects potential insider threat behavior where a user accesses or copies a large number of files shortly before using an AI tool (Claude, ChatGPT, Copilot, etc.) or uploading to a cloud service. The pattern of bulk file access followed by AI API or upload activity suggests deliberate data collection for AI-assisted exfiltration or policy-violating data submission. This is a correlation hunt combining file access events with AI tool network activity.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection / Exfiltration |
| **Technique** | T1005 — Data from Local System |
| **Sub-technique** | T1567.002 — Exfiltration to Cloud Storage |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `FileWritten`, `DnsRequest`, `ProcessRollup2` |

## Severity

**Medium** — Requires policy context; elevated to High if classified or sensitive file paths are involved.

## Query

```logscale
// Users with both high file access activity AND AI tool DNS queries in the same session window
// Step 1: Find users with high file open activity
#event_simpleName=FileWritten
| groupBy([ComputerName, UserName], function=count(as=file_writes))
| file_writes > 50

// Step 2 (run separately and correlate): AI tool access by same users
// #event_simpleName=DnsRequest
// | DomainName=/(anthropic\.com|claude\.ai|chat\.openai\.com|openai\.com|copilot\.microsoft\.com)/i
// | groupBy([ComputerName, UserName], function=count())
```

**Variant: Mass file copy to staging directory then AI access**

```logscale
// Files copied to common staging paths (Desktop, Downloads, Temp) followed by external access
#event_simpleName=FileWritten
| FilePath=/(\\Desktop\\|\\Downloads\\|\\Temp\\|\\Public\\)/i
| groupBy([ComputerName, UserName, FilePath], function=count(as=files_staged))
| files_staged > 20
| sort(files_staged, order=desc)
| table([ComputerName, UserName, FilePath, files_staged])
```

**Variant: Large file access before AI tool session (by same aid)**

```logscale
// Single host: large number of distinct file paths opened in 30 minutes before AI DNS queries
#event_simpleName=FileWritten
| groupBy([aid, ComputerName, UserName, bin(@timestamp, span=30min)], function=count(as=file_count))
| file_count > 30
| sort(file_count, order=desc)
| table([ComputerName, UserName, file_count, _bucket])
```

**Variant: Sensitive file types staged (code, configs, documents)**

```logscale
// Sensitive file extensions accessed in bulk — source code, credentials, configs, documents
#event_simpleName=FileWritten
| FilePath=/(
    \.py$|\.js$|\.ts$|\.go$|\.java$|\.c$|\.cpp$|\.cs$|
    \.env$|\.config$|\.cfg$|\.ini$|\.pem$|\.key$|\.pfx$|\.p12$|
    \.sql$|\.db$|\.mdb$|
    \.docx?$|\.xlsx?$|\.pptx?$|\.pdf$|
    \.json$|\.yaml$|\.yml$|\.xml$|
    \.kdbx$|\.rdp$|\.ssh$|id_rsa|\.ppk$
  )/i
| groupBy([ComputerName, UserName], function=count(as=sensitive_files))
| sensitive_files > 15
| sort(sensitive_files, order=desc)
| table([ComputerName, UserName, sensitive_files])
```

## Response Notes

**Triage steps:**
1. Identify the specific files accessed — review file paths for classification indicators (data labels, sensitive project directories)
2. Correlate the file access window with AI tool DNS/network activity — same `UserName` and `ComputerName` within 30-60 minutes is the key signal
3. Interview the user if access is suspicious — many cases are benign (user compiling a report, legitimate AI-assisted work)
4. Check if files were moved/deleted after the AI tool session — covering tracks is an escalation indicator
5. Review clipboard manager activity or screenshot tools active during the AI session if available

**False positives:**
- Developers and analysts commonly use AI tools to assist with work on legitimate files — this is normal in many organizations
- This query requires policy context — if AI tools are approved and usage is within scope, this is informational only
- Adjust file count thresholds based on your environment baseline

## References

- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/techniques/T1567/
- https://www.cisa.gov/sites/default/files/2023-11/Cybersecurity-Best-Practices-for-AI.pdf
