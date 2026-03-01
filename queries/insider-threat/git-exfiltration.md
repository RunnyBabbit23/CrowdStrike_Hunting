# Git / Source Code Repository Exfiltration

## Description

Detects source code exfiltration via Git — a primary insider threat vector for software companies. Patterns include `git clone` of internal repositories to local disk at scale, `git push` to external or personal remote repositories (GitHub personal accounts, GitLab, Bitbucket personal), and mass repository cloning via scripts. Developers with legitimate internal repo access can exfiltrate entire codebases, IP, and embedded secrets in a single command that appears as routine developer activity.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration / Collection |
| **Technique** | T1213 — Data from Information Repositories |
| **Sub-technique** | T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `DnsRequest`, `NetworkConnectIP4` |

## Severity

**Medium** — Git activity is routine for developers; severity is High when pushing to external/personal remotes, cloning at scale, or activity occurs from non-developer endpoints.

## Query

```logscale
// git push to external remote — source code leaving to outside repository
#event_simpleName=ProcessRollup2
| FileName=/(git|git\.exe)/i
| CommandLine=/push/i
| CommandLine=/(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sourceforge\.net)/i
| CommandLine!=/yourcompany\.github\.com|yourorg/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: git clone of multiple internal repositories (mass cloning)**

```logscale
// High-volume git clone activity from a single user — bulk repo exfiltration
#event_simpleName=ProcessRollup2
| FileName=/(git|git\.exe)/i
| CommandLine=/clone/i
| groupBy([ComputerName, UserName], function=count(as=clone_count))
| clone_count > 10
| sort(clone_count, order=desc)
| table([ComputerName, UserName, clone_count])
```

**Variant: git remote add pointing to external service**

```logscale
// Adding external remote to existing repo — staging for push to personal account
#event_simpleName=ProcessRollup2
| FileName=/(git|git\.exe)/i
| CommandLine=/remote\s+add/i
| CommandLine=/(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: DNS queries to code hosting platforms**

```logscale
// DNS to external code repositories — may indicate push/clone to personal accounts
#event_simpleName=DnsRequest
| DomainName=/(
    github\.com|raw\.githubusercontent\.com|
    gitlab\.com|
    bitbucket\.org|
    codeberg\.org|
    sourceforge\.net|
    gitea\.io|
    sr\.ht|
    pastebin\.com|paste\.ee|hastebin\.com|
    gist\.github\.com
  )/i
| groupBy([ComputerName, UserName, DomainName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([ComputerName, UserName, DomainName, query_count])
```

**Variant: Scripted mass clone (batch file or PowerShell looping git clone)**

```logscale
// PowerShell or cmd driving multiple git clone operations — scripted bulk exfiltration
#event_simpleName=ProcessRollup2
| in(FileName, values=["powershell.exe", "cmd.exe", "bash.exe", "sh"])
| CommandLine=/(for.*git clone|foreach.*git clone|git clone.*\n.*git clone)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: git archive — creating exportable archive of repo**

```logscale
// git archive used to create a tarball of repo contents without full clone history
#event_simpleName=ProcessRollup2
| FileName=/(git|git\.exe)/i
| CommandLine=/archive/i
| table([ComputerName, UserName, CommandLine, FilePath, @timestamp], limit=200)
```

**Variant: Unauthorized git credential configuration (external account setup)**

```logscale
// git config setting user.email to non-corporate domain — personal account setup
#event_simpleName=ProcessRollup32
| FileName=/(git|git\.exe)/i
| CommandLine=/config.*(user\.email|user\.name)/i
| CommandLine!=/yourcompany\.com|yourdomain\.com/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the remote URL in the `CommandLine` for `push` and `remote add` — personal accounts on shared platforms (github.com/personaluser) vs. corporate org accounts
2. For mass clone: check the source repositories — internal IP-range git servers, private GitHub org repos, or public repos? Cloning internal repos in bulk is high priority
3. Review `UserName` employment status — developers who have given notice are elevated priority
4. Check if `git push` was successful by looking for follow-on network connections to the remote host
5. Correlate with `DnsRequest` events to external code platforms — combination of DNS + push is near-certain exfiltration

**False positives:**
- Developers regularly push to their own forks on GitHub as part of standard open source contribution workflows
- CI/CD pipelines push to external repos for deployment — filter by service account names and known pipeline processes
- Onboarding developers may clone large numbers of repos on day one — correlate with account age
- Tune the push detection by adding your company's GitHub organization to the exclusion list

## References

- https://attack.mitre.org/techniques/T1567/001/
- https://www.crowdstrike.com/blog/source-code-theft-insider-threat/
- https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/
