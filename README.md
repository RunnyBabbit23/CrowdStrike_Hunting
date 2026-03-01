# CrowdStrike Hunting Library

A curated collection of threat hunting queries written in LogScale Query Language (LQL) for use in **CrowdStrike Falcon Next-Gen SIEM** Advanced Event Search.

---

## Structure

```
queries/
├── execution/          # Code execution techniques (T1059, T1204, etc.)
├── persistence/        # Persistence mechanisms (T1053, T1547, T1543, etc.)
├── credential-access/  # Credential theft (T1003, T1558, T1110, etc.)
├── lateral-movement/   # Lateral movement (T1021, T1570, etc.)
├── defense-evasion/    # Evasion techniques (T1055, T1562, T1070, etc.)
├── command-and-control/ # C2 patterns (T1071, T1095, T1132, etc.)
├── ransomware/         # Ransomware behaviors (encryption, wipers, backups)
├── identity/           # Identity-based threats (Kerberos, LDAP, AD abuse)
├── cloud/              # Cloud threats (IAM, S3, API abuse via Falcon CSPM)
├── ai-tool-usage/      # AI tool usage detection (Claude, WSL+AI, API keys)
└── insider-threat/     # Insider threat patterns (data staging, bulk access)

templates/
└── query-template.md   # Standard template for new queries

docs/
├── logscale-cheatsheet.md   # LogScale syntax reference
└── data-sources.md          # CrowdStrike event types and key fields
```

---

## Data Sources

| Source | Platform | Event Examples |
|---|---|---|
| **Endpoint (EDR)** | Falcon Sensor | `ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `FileWritten`, `RegGenericValueUpdate` |
| **Identity Protection** | Falcon ITP | `AuthActivityAuditEvent`, `DirectoryServiceEventV2`, `SuspiciousKerberosRequest` |
| **Cloud (CSPM/Horizon)** | Falcon Cloud Security | `CloudAuditEvent`, `PolicyDetectionSummary` |

---

## Query Format

Each query file follows this structure:

- **Title** — descriptive name
- **Description** — what the query detects and why it matters
- **MITRE ATT&CK** — tactic, technique ID and name
- **Data Source** — sensor/log type and specific event names used
- **Severity** — High / Medium / Low
- **Query** — raw LogScale code block, paste-ready for NG-SIEM Advanced Search
- **Response Notes** — triage guidance and false positive considerations
- **References** — relevant links, CVEs, or blog posts

---

## Usage

1. Open **Falcon Next-Gen SIEM** → **Advanced Event Search**
2. Select the appropriate **repository** (e.g., `base_sensor_activity`, `base_identity_activity`)
3. Set your time range (start with **Last 7 Days** for hunting)
4. Paste the LogScale query from any `.md` file's code block
5. Review results and pivot on `aid`, `UserName`, or `ComputerName`

---

## Severity Ratings

| Level | Meaning |
|---|---|
| **High** | Strong indicator of malicious activity — investigate immediately |
| **Medium** | Suspicious activity that requires context — triage and pivot |
| **Low** | Informational / baselining — use for anomaly detection |

---

## Contributing

Use [templates/query-template.md](templates/query-template.md) when adding new queries. Tag each query with the appropriate MITRE technique ID and data source.
