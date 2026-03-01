# Bulk File Enumeration / Directory Traversal

## Description

Detects systematic enumeration of file system directories — a reconnaissance step where an insider or attacker maps out available data before staging and exfiltrating it. Common indicators include `dir /s`, `tree`, `Get-ChildItem -Recurse`, `find`, and `robocopy /l` targeting sensitive directories (source code, finance, HR, contracts, customer data). The volume and breadth of directories traversed distinguishes reconnaissance from normal file browsing.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Discovery / Collection |
| **Technique** | T1083 — File and Directory Discovery |
| **Sub-technique** | Recursive directory listing, file system mapping |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**Medium** — Directory enumeration is common in IT workflows; severity increases when targeting sensitive paths, run by non-admin users, or combined with staging/compression activity.

## Query

```logscale
// cmd.exe recursive directory listing — classic insider recon technique
#event_simpleName=ProcessRollup2
| FileName=cmd.exe
| CommandLine=/(dir\s+.*\/s|dir\s+\/s|tree\s+\/[af])/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: PowerShell recursive file listing**

```logscale
// PowerShell Get-ChildItem recurse — often used to enumerate and export file lists
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(Get-ChildItem|gci|dir|ls).*(-Recurse|-r\b)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Robocopy in list-only mode (non-destructive bulk enumeration)**

```logscale
// Robocopy /l (list-only) used to enumerate files without copying — recon before actual copy
#event_simpleName=ProcessRollup2
| FileName=robocopy.exe
| CommandLine=/\s\/l(\s|$)/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Enumeration targeting sensitive directories**

```logscale
// Directory traversal targeting high-value data paths
#event_simpleName=ProcessRollup2
| in(FileName, values=["cmd.exe", "powershell.exe", "find.exe", "where.exe", "forfiles.exe"])
| CommandLine=/(
    \\finance\\|\\payroll\\|\\hr\\|\\legal\\|\\contracts\\|
    \\source\\|\\src\\|\\repos\\|\\git\\|\\svn\\|
    \\confidential\\|\\sensitive\\|\\restricted\\|\\classified\\|
    \\customer\\|\\clients\\|\\pii\\|\\personal\\|
    \\backup\\|\\archive\\|\\shared\\
  )/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: forfiles — enumerate files matching extension criteria**

```logscale
// forfiles used to find files by type — targeting specific data classes
#event_simpleName=ProcessRollup2
| FileName=forfiles.exe
| CommandLine=/\.(docx?|xlsx?|pdf|csv|sql|pst|msg|kdbx|pfx|pem|key|env)/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Users enumerating file shares (network path traversal)**

```logscale
// Directory listing against UNC paths — enumerating network shares
#event_simpleName=ProcessRollup2
| in(FileName, values=["cmd.exe", "powershell.exe"])
| CommandLine=/(dir|tree|ls|gci).{0,30}(\\\\[a-zA-Z0-9\-]+\\)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the specific paths being enumerated — high-value directories (source code, HR, finance) are the primary concern
2. Check `UserName` role — is this access within their normal job function?
3. Look for what happens next: `FileWritten` events for output files, or archive tool execution in the same time window
4. Pivot on `aid` to see if enumeration was followed by bulk file opens or compression
5. Review if the same user enumerated multiple systems (lateral enumeration via UNC paths)

**False positives:**
- IT administrators regularly enumerate file systems for audit, capacity planning, and troubleshooting
- Backup agents perform recursive directory scans — filter by service accounts
- Security scanners (DLP, CASB) enumerate file systems for classification
- Developers use recursive listings during build processes — filter known CI/CD service accounts

## References

- https://attack.mitre.org/techniques/T1083/
- https://www.dhs.gov/sites/default/files/publications/Combating%20the%20Insider%20Threat_0.pdf
