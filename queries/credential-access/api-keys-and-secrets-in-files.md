# API Keys and Secrets in Files / Command Lines

## Description

Detects API keys, tokens, and other credentials exposed on endpoints — either written to disk in plaintext files or passed as arguments in process command lines. Insider threats, developers with poor secret hygiene, and post-compromise credential staging all generate this pattern.

CrowdStrike cannot read file contents by default, so this query set covers:
- **Command lines** containing credential-shaped strings (most reliable)
- **File writes** of known credential file names to suspicious paths
- **Private key and certificate file writes**
- **Cloud CLI secret operations** with plaintext inline credentials
- **Scripted credential harvesting** — scripts writing env vars or config to disk

## MITRE ATT&CK

| Field | Value |
|---|---|
| Tactic | Credential Access / Collection |
| Technique | T1552 — Unsecured Credentials |
| Sub-techniques | T1552.001 Credentials in Files, T1552.004 Private Keys |
| Related | T1213 — Data from Information Repositories |

## Data Source

| Source | Repository | Event Types |
|---|---|---|
| Endpoint EDR | `base_sensor_activity` | `ProcessRollup2`, `FileWritten`, `PeFileWritten` |

## Severity: High

---

## Queries

### Query 1 — API Key Patterns in Process Command Lines

Catches credentials passed as CLI arguments or embedded in scripts that were executed. Covers the most common SaaS/cloud API key formats.

```logscale
#repo="base_sensor_activity"
#event_simpleName="ProcessRollup2"
| regex(field=CommandLine, regex="""(?i)(AKIA[0-9A-Z]{16}|sk-ant-[a-zA-Z0-9\-_]{20,}|sk-proj-[a-zA-Z0-9\-_]{30,}|sk-[a-zA-Z0-9]{48}|ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{59}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-[0-9a-zA-Z\-]{10,48}|sq0atp-[0-9A-Za-z\-_]{22}|EAACEdEose0cBA[0-9A-Za-z]+|[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy][\s:=\"']+[a-zA-Z0-9\-_]{20,}|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\s:=\"']+\S{8,}|[Ss][Ee][Cc][Rr][Ee][Tt][\s:=\"']+[a-zA-Z0-9\-_]{16,}|[Tt][Oo][Kk][Ee][Nn][\s:=\"']+[a-zA-Z0-9\-_.]{20,})""", flags=i)
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

**Key patterns covered:**
| Pattern | Service |
|---|---|
| `AKIA[0-9A-Z]{16}` | AWS Access Key ID |
| `sk-ant-...` | Anthropic / Claude API |
| `sk-proj-...` / `sk-[48 chars]` | OpenAI API |
| `ghp_...` / `github_pat_...` | GitHub Personal Access Token |
| `AIza[35 chars]` | Google Cloud / Maps API |
| `xox[b/a/p/r/s]-...` | Slack Bot/App token |
| `sq0atp-...` | Square API |
| `EAACEdEose0cBA...` | Facebook Graph API |
| Generic `api_key=`, `password=`, `secret=`, `token=` | Broad credential catch |

---

### Query 2 — Credential File Names Written to Suspicious Paths

Detects writes of known credential file names (`.env`, `credentials.json`, `secrets.yaml`, etc.) to locations that suggest staging, exfiltration, or accidental exposure. File *content* is not inspected — this fires on the file name and path alone.

```logscale
#repo="base_sensor_activity"
#event_simpleName in ("FileWritten", "PeFileWritten")
| regex(field=TargetFileName, regex="""(?i)(\.env$|\.env\.(local|prod|production|staging|dev|development|test)|credentials(\.json|\.yaml|\.yml|\.txt|\.cfg|\.ini|\.xml)?$|secrets?(\.json|\.yaml|\.yml|\.txt)?$|api[_-]?keys?(\.json|\.yaml|\.txt)?$|auth[_-]?token(s)?(\.json|\.txt)?$|\.npmrc$|\.pypirc$|\.netrc$|\.pgpass$|kubeconfig|config(\.json|\.yaml)?$)""")
| regex(field=TargetFileName, regex="""(?i)(\\temp\\|\\tmp\\|\\downloads?\\|\\desktop\\|\\appdata\\local\\temp\\|\\users\\public\\|[D-Z]:\\|\\onedrive\\|\\dropbox\\|\\google drive\\|\\box\\|\\documents\\|\\pictures\\)""")
| table([ComputerName, UserName, TargetFileName, FileName, ParentBaseFileName], limit=200)
```

---

### Query 3 — Private Key and Certificate File Writes

Private keys written outside of expected certificate store paths indicate harvesting or mishandling. PEM files, PKCS#12 bundles, and SSH private keys in user-writable locations are high-signal.

```logscale
#repo="base_sensor_activity"
#event_simpleName in ("FileWritten", "PeFileWritten")
| regex(field=TargetFileName, regex="""(?i)\.(pem|key|pfx|p12|p8|pkcs12|asc|ppk|ovpn|jks|keystore)$""")
| regex(field=TargetFileName, regex="""(?i)(\\temp\\|\\tmp\\|\\downloads?\\|\\desktop\\|\\appdata\\|\\users\\public\\|[D-Z]:\\|\\onedrive\\|\\dropbox\\|\\documents\\|id_rsa|id_ed25519|id_ecdsa|id_dsa)""")
| table([ComputerName, UserName, TargetFileName, FileName, ParentBaseFileName], limit=200)
```

---

### Query 4 — Cloud CLI Inline Secret Operations

Catches AWS, Azure, and GCP CLI commands that pass secrets or credentials as inline plaintext arguments — a common developer mistake that exposes secrets in process command line logging.

```logscale
#repo="base_sensor_activity"
#event_simpleName="ProcessRollup2"
| regex(field=FileName, regex="""(?i)(aws\.exe|az\.exe|gcloud\.cmd|kubectl\.exe|vault\.exe|op\.exe|chamber\.exe)$""")
| regex(field=CommandLine, regex="""(?i)(--secret-string\s+["']?[^-\s]{8,}|--value\s+["']?[^-\s]{8,}|--password\s+["']?[^-\s]{8,}|--credentials-file|configure\s+set\s+(aws_access_key|aws_secret)|login\s+--password-stdin|secrets\s+create|kv\s+secret\s+set)""")
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

---

### Query 5 — PowerShell / Scripts Writing Credential Content to Disk

PowerShell that uses `Set-Content`, `Out-File`, `Add-Content`, or `[IO.File]::WriteAllText` with credential-related variable names is a strong indicator of credential harvesting or staging.

```logscale
#repo="base_sensor_activity"
#event_simpleName="ProcessRollup2"
| in(FileName, values=["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"])
| regex(field=CommandLine, regex="""(?i)(Set-Content|Out-File|Add-Content|WriteAllText|WriteAllLines|Export-Csv|ConvertTo-Json)\s.{0,100}(password|secret|token|api.?key|credential|access.?key|private.?key)""")
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

---

### Query 6 — .git Repository Credential Leaks

Git operations that may bake credentials into repository history — committing `.env` files, using credential-embedded remote URLs (`https://user:pass@host`), or storing AWS credentials in source trees.

```logscale
#repo="base_sensor_activity"
#event_simpleName="ProcessRollup2"
| in(FileName, values=["git.exe", "git"])
| regex(field=CommandLine, regex="""(?i)(https?://[^@\s]+:[^@\s]+@|commit\s.{0,80}(env|secret|key|credential|password|token)|remote\s+add\s+\S+\s+https?://[^@]+:[^@]+@|add\s+.*\.(env|pem|key|pfx|p12|credentials))""")
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

---

### Query 7 — Anomalous Volume of Credential-Named File Writes Per User

Baselining approach — flags users who write an unusual number of credential-named files in a session. Single writes may be legitimate; 5+ in a short window is suspicious.

```logscale
#repo="base_sensor_activity"
#event_simpleName in ("FileWritten", "PeFileWritten")
| regex(field=TargetFileName, regex="""(?i)(password|secret|credential|api.?key|token|\.env|private.?key|access.?key)""")
| groupBy([ComputerName, UserName], function=[count(as=CredFileWrites), collect(TargetFileName, limit=20, as=FilesSeen)])
| CredFileWrites >= 5
| sort(CredFileWrites, order=desc)
| table([ComputerName, UserName, CredFileWrites, FilesSeen], limit=100)
```

---

## Response Notes

### Triage Steps

1. **Pivot on `UserName` + `ComputerName`** — look for surrounding `ProcessRollup2` events to understand what the user was doing before and after the hit.
2. **Check parent process** — `ParentBaseFileName` tells you whether this was invoked interactively (explorer.exe, cmd.exe) or programmatically (a build system, CI runner, automation).
3. **Correlate with network activity** — if a key was exposed in a command line, check for `NetworkConnectIP4` from the same process around the same time; the key may have been used immediately.
4. **Check git history** — if Query 6 fires, review what was committed and whether the repository is internal or external-facing.
5. **Determine if the credential is live** — work with the owning team to rotate any exposed credential immediately, regardless of intent.

### False Positives

| Source | Explanation |
|---|---|
| CI/CD build agents | Legitimate pipelines often pass secrets via environment variables that appear in command lines |
| Developer workstations | Developers testing scripts locally may legitimately pass test API keys |
| Vault/secrets management agents | Tools like HashiCorp Vault agent, AWS Secrets Manager CLI will generate these patterns during normal operation |
| Password manager CLIs | `op`, `1password-cli`, `bwarden` will show in Query 4 hits |
| Certificate management | Legitimate PKI operations generate `.pem`/`.pfx` writes in expected paths |

### Tuning Tips

- Add an `allowlist` for known CI/CD agent machine names: `| ComputerName != /build-agent-\d+/i`
- Exclude known vault/secrets-manager processes: `| ParentBaseFileName != /vault|conjur|aws-vault/i`
- For Query 1, scope to non-developer machines first by filtering on `UserName` groups
- For Query 2/3, exclude known certificate paths: `| TargetFileName != /\\ProgramData\\ssl|\\cert\\|\\pki\\/i`

## References

- [MITRE T1552.001 — Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE T1552.004 — Private Keys](https://attack.mitre.org/techniques/T1552/004/)
- [truffleHog — secret scanning patterns](https://github.com/trufflesecurity/trufflehog)
- [CrowdStrike — Protecting secrets in modern environments](https://www.crowdstrike.com/blog/)
