# CrowdStrike Hunting Library

A curated collection of threat hunting queries written in LogScale Query Language (LQL) for use in **CrowdStrike Falcon Next-Gen SIEM** Advanced Event Search.

---

## Structure

```
queries/
├── execution/           # Code execution techniques (T1059, T1204, etc.)
├── persistence/         # Persistence mechanisms (T1053, T1547, T1543, etc.)
├── credential-access/   # Credential theft (T1003, T1558, T1110, etc.)
├── lateral-movement/    # Lateral movement (T1021, T1570, etc.)
├── defense-evasion/     # Evasion techniques (T1055, T1562, T1070, etc.)
├── command-and-control/ # C2 patterns (T1071, T1095, T1132, etc.)
├── ransomware/          # Ransomware behaviors (encryption, wipers, backups)
├── identity/            # Identity-based threats (Kerberos, LDAP, AD abuse)
├── cloud/               # Cloud threats — AWS + Azure (IAM, S3, Key Vault, etc.)
├── ai-tool-usage/       # AI tool usage detection (Claude, WSL+AI, API keys)
└── insider-threat/      # 16 insider threat patterns (exfil, evasion, access anomalies)

templates/
└── query-template.md    # Standard template for new queries

docs/
├── logscale-cheatsheet.md   # LogScale syntax reference
└── data-sources.md          # CrowdStrike event types and key fields
```

---

## Query Index

### Insider Threat (16 queries)

| File | Technique | Severity |
|---|---|---|
| [sensitive-data-staging.md](queries/insider-threat/sensitive-data-staging.md) | Data staging before AI tool use | Medium |
| [bulk-archive-compression.md](queries/insider-threat/bulk-archive-compression.md) | T1560.001 — Archive via utility | Medium |
| [bulk-file-enumeration.md](queries/insider-threat/bulk-file-enumeration.md) | T1083 — File and directory discovery | Medium |
| [database-tool-access.md](queries/insider-threat/database-tool-access.md) | T1005 / T1213 — Data from local/repo | Medium |
| [screen-capture-recording.md](queries/insider-threat/screen-capture-recording.md) | T1113 — Screen capture | Low |
| [removable-media-usb-exfil.md](queries/insider-threat/removable-media-usb-exfil.md) | T1052.001 — Exfiltration over USB | High |
| [personal-cloud-storage-upload.md](queries/insider-threat/personal-cloud-storage-upload.md) | T1567.002 — Exfiltration to cloud storage | Medium |
| [personal-webmail-access.md](queries/insider-threat/personal-webmail-access.md) | T1048.003 — Exfiltration over alternative protocol | Low |
| [git-exfiltration.md](queries/insider-threat/git-exfiltration.md) | T1567.001 — Exfiltration to code repository | Medium |
| [secure-delete-tools.md](queries/insider-threat/secure-delete-tools.md) | T1070.004 — Indicator removal: file deletion | High |
| [event-log-clearing.md](queries/insider-threat/event-log-clearing.md) | T1070.001 — Clear Windows event logs | High |
| [browser-history-deletion.md](queries/insider-threat/browser-history-deletion.md) | T1070.004 — Browser artifact cleanup | Low |
| [off-hours-access.md](queries/insider-threat/off-hours-access.md) | T1078 — Valid accounts (behavioral) | Low |
| [departing-employee-indicators.md](queries/insider-threat/departing-employee-indicators.md) | T1005 / T1078 — Data collection before departure | Low |
| [tor-anonymous-browser.md](queries/insider-threat/tor-anonymous-browser.md) | T1090.003 — Multi-hop proxy (Tor) | High |
| [personal-vpn-clients.md](queries/insider-threat/personal-vpn-clients.md) | T1090.002 — External proxy (personal VPN) | Medium |

### Cloud — AWS (7 queries)

| File | Technique | Severity |
|---|---|---|
| [iam-privilege-escalation.md](queries/cloud/iam-privilege-escalation.md) | T1078.004 / T1098 — IAM escalation | High |
| [s3-data-exfiltration.md](queries/cloud/s3-data-exfiltration.md) | T1530 — Data from cloud storage | High |
| [aws-cloudtrail-tampering.md](queries/cloud/aws-cloudtrail-tampering.md) | T1562.008 — Disable cloud logs | High |
| [aws-imds-and-credential-theft.md](queries/cloud/aws-imds-and-credential-theft.md) | T1552.005 — Cloud instance metadata API | High |
| [aws-secrets-and-parameter-access.md](queries/cloud/aws-secrets-and-parameter-access.md) | T1555 — Credentials from password stores | High |
| [aws-security-group-changes.md](queries/cloud/aws-security-group-changes.md) | T1562.007 — Disable cloud firewall | High |
| [aws-lambda-abuse.md](queries/cloud/aws-lambda-abuse.md) | T1648 — Serverless execution | High |

### Cloud — Azure (5 queries)

| File | Technique | Severity |
|---|---|---|
| [azure-impossible-travel.md](queries/cloud/azure-impossible-travel.md) | T1078.004 — Cloud account compromise | High |
| [azure-service-principal-abuse.md](queries/cloud/azure-service-principal-abuse.md) | T1098.001 — Additional cloud credentials | High |
| [azure-key-vault-access.md](queries/cloud/azure-key-vault-access.md) | T1555 — Credentials from password stores | High |
| [azure-conditional-access-tampering.md](queries/cloud/azure-conditional-access-tampering.md) | T1562.001 / T1556.006 — Impair defenses / Modify MFA | High |
| [azure-automation-runbook-abuse.md](queries/cloud/azure-automation-runbook-abuse.md) | T1648 — Serverless execution | High |

### Lateral Movement (3 queries)

| File | Technique | Severity |
|---|---|---|
| [psexec-remote-execution.md](queries/lateral-movement/psexec-remote-execution.md) | T1021.002 — SMB/Windows Admin Shares | High |
| [wmi-lateral-movement.md](queries/lateral-movement/wmi-lateral-movement.md) | T1021.006 / T1047 — WMI | High |
| [network-neighbor-spread.md](queries/lateral-movement/network-neighbor-spread.md) | T1210 — Exploitation of remote services / spread detection | High |

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

## Response Scripts

### RTR Forensic Collection

| File | Purpose |
|---|---|
| [scripts/Invoke-ForensicCollection.ps1](scripts/Invoke-ForensicCollection.ps1) | PowerShell script — collects all forensic artifacts and packages them into a ZIP |
| [scripts/README-rtr-collection.md](scripts/README-rtr-collection.md) | Full usage guide — upload, execute, download, verify, and analyze |

**Quick start:**
```
# In RTR session:
runscript -CloudFile="Invoke-ForensicCollection"
get "C:\Windows\Temp\CS_Forensics_<hostname>_<timestamp>.zip"
```

**Artifacts collected:** system info, network state, running processes/services, user accounts/sessions, persistence (run keys, scheduled tasks, WMI subs, IFEO, COM hijack), event logs (EVTX + CSV), prefetch, LNK/recent files, registry exports (ShimCache, AmCache, BAM/DAM, USB history), browser databases (Chrome/Edge/Firefox).

### RTR Neighbor Triage

| File | Purpose |
|---|---|
| [scripts/Invoke-NeighborTriage.ps1](scripts/Invoke-NeighborTriage.ps1) | Lightweight IoC-parameterized triage script — checks a host for known-bad artifacts from a specific incident |

**Quick start:**
```
# In RTR session on a neighbor host:
runscript -CloudFile="Invoke-NeighborTriage" -CommandLine="-CompromisedHost VICTIM01 -MalwareHashes @('aabbcc...') -C2IPs @('1.2.3.4') -C2Domains @('evil.com')"
get "C:\Windows\Temp\NeighborTriage_<hostname>_<timestamp>.txt"
```

**Key parameters:** `-CompromisedHost`, `-CompromisedUsers`, `-MalwareHashes`, `-MalwareFileNames`, `-C2IPs`, `-C2Domains`, `-C2Ports`, `-MalwareServiceNames`, `-MalwareTaskNames`, `-MalwareRegistryValues`, `-MalwareMutexes`, `-HoursBack`

**Output:** Risk-scored text report with verdict — `HIGH RISK` / `MEDIUM RISK` / `LOW RISK` / `CLEAN`

### General-Purpose IoC Check

| File | Purpose |
|---|---|
| [scripts/Invoke-IoCCheck.ps1](scripts/Invoke-IoCCheck.ps1) | Checks a host against any IoC list — reads from an uploaded CSV file |
| [scripts/ioc-template.csv](scripts/ioc-template.csv) | CSV template with all supported IoC types and field documentation |

**Quick start:**
```
# Step 1 — upload your IoC list via RTR:
put "C:\local\path\to\iocs.csv"

# Step 2 — run the checker:
runscript -CloudFile="Invoke-IoCCheck" -CommandLine="-IoCFile C:\Windows\Temp\iocs.csv"

# Step 3 — download both reports:
get "C:\Windows\Temp\IoCCheck_<hostname>_<timestamp>.txt"
get "C:\Windows\Temp\IoCCheck_<hostname>_<timestamp>.csv"
```

**IoC types supported:** `hash-sha256`, `hash-md5`, `hash-sha1`, `ip`, `ip-cidr`, `domain`, `url`, `filepath`, `filename`, `registry-key`, `registry-value`, `service-name`, `task-name`, `mutex`, `process-name`, `pipe-name`, `user-agent`, `yara`

**CSV format:** `Type,Value,Description,Severity,ThreatName,Source` — export directly from CrowdStrike Falcon Intelligence, MISP, AlienVault OTX, or build manually from threat reports.

**Output:** Text report + SIEM-ready CSV with verdict — `COMPROMISED` / `SUSPICIOUS` / `POSSIBLE INDICATOR` / `CLEAN`

---

## Contributing

Use [templates/query-template.md](templates/query-template.md) when adding new queries. Tag each query with the appropriate MITRE technique ID and data source.
