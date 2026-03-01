# Personal Cloud Storage Upload Detection

## Description

Detects use of personal cloud storage services — Dropbox, Google Drive, Box personal, Mega, WeTransfer, and similar — from corporate endpoints. Insiders commonly use personal cloud storage to exfiltrate data because it appears as normal HTTPS traffic, bypasses many DLP solutions that don't inspect encrypted web traffic, and provides plausible deniability. Detection focuses on DNS queries to personal storage domains, sync client process execution, and browser-based uploads following bulk file access.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration |
| **Technique** | T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| **Sub-technique** | Personal cloud storage, file sharing services |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `DnsRequest`, `ProcessRollup2`, `NetworkConnectIP4` |

## Severity

**Medium** — Personal cloud storage access is policy-dependent; elevated to High when preceded by bulk file access or access to sensitive data paths.

## Query

```logscale
// DNS queries to personal cloud storage and file sharing services
#event_simpleName=DnsRequest
| DomainName=/(
    dropbox\.com|dropboxusercontent\.com|dropboxapi\.com|
    drive\.google\.com|docs\.google\.com|myaccount\.google\.com|
    box\.com|app\.box\.com|
    mega\.nz|mega\.co\.nz|megaupload\.com|
    wetransfer\.com|fromsmash\.com|
    mediafire\.com|
    sendspace\.com|
    pcloud\.com|
    sync\.com|
    spideroak\.com|
    tresorit\.com|
    icloud\.com|icloud-content\.com|
    onedrive\.live\.com|1drv\.ms|
    sharepoint\.live\.com
  )/i
| DomainName!=/\.microsoft\.com|\.office\.com|\.sharepoint\.com/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=500)
```

**Variant: Personal cloud sync client process execution**

```logscale
// Sync client binaries — personal cloud storage installed on corporate endpoint
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "Dropbox.exe", "DropboxUpdate.exe",
    "googledrivesync.exe", "GoogleDriveFS.exe", "DriveFS.exe",
    "Box.exe", "BoxSync.exe", "BoxUpdate.exe",
    "MEGAsync.exe", "MEGAupdater.exe",
    "pCloud.exe", "pCloudDrive.exe",
    "SyncApp.exe",
    "Tresorit.exe"
  ])
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: Browser uploading to personal storage (DNS + file access correlation)**

```logscale
// DNS to personal cloud services correlated with prior bulk file activity
// Step 1: Find hosts with personal cloud DNS queries
#event_simpleName=DnsRequest
| DomainName=/(dropbox|drive\.google|mega\.nz|wetransfer|mediafire|box\.com)/i
| groupBy([ComputerName, UserName, DomainName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([ComputerName, UserName, DomainName, query_count])
```

**Variant: File sync client writing corporate files to sync folder**

```logscale
// Files written to known sync folder paths — corporate data entering personal cloud sync
#event_simpleName=FileWritten
| FilePath=/(
    \\Dropbox\\|
    \\Google Drive\\|\\GoogleDrive\\|\\Google\\Drive\\|
    \\Box Sync\\|\\Box\\|
    \\MEGA\\|
    \\pCloud Drive\\|
    \\OneDrive - Personal\\
  )/i
| FileName=/\.(docx?|xlsx?|pdf|csv|pptx?|py|js|ts|go|sql|zip|rar|7z|json|key|pem|env|cfg)$/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: WeTransfer and one-time upload services (browser-based)**

```logscale
// One-time file sharing services — commonly used to avoid leaving persistent cloud storage trace
#event_simpleName=DnsRequest
| DomainName=/(
    wetransfer\.com|
    fromsmash\.com|
    transfer\.sh|
    file\.io|
    gofile\.io|
    pixeldrain\.com|
    anonfiles\.com|
    0x0\.st|
    filedropper\.com|
    uploadfiles\.io
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Check whether the user has authorized use of the specific service — many organizations allow corporate OneDrive but not personal Dropbox
2. Correlate the cloud storage access time with `FileWritten` events to the sync folder or preceding bulk file access
3. For browser-based uploads, check what DNS queries preceded the upload — did the user access sensitive internal resources just before?
4. Identify the volume of data transferred if proxy/CASB logs are available — DNS alone doesn't show volume
5. Review `UserName` context — departing employees, disgruntled users, or users with access to sensitive data are higher priority

**False positives:**
- Some organizations permit Dropbox or Box for business use — validate against approved tool list
- Personal OneDrive is often confused with corporate OneDrive — the domain `onedrive.live.com` is personal; `*.sharepoint.com` is corporate
- Developers may use GitHub/GitLab (not in this query) — covered in the git-exfiltration query

## References

- https://attack.mitre.org/techniques/T1567/002/
- https://www.crowdstrike.com/blog/data-exfiltration-detection-with-crowdstrike/
- https://www.proofpoint.com/us/blog/cloud-security/cloud-account-takeover-insider-threats
