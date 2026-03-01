# Browser History and Artifact Deletion

## Description

Detects deliberate clearing of browser history, cache, cookies, and download records — an anti-forensics technique used by insiders to conceal which websites they visited (personal cloud storage, webmail, competitor sites, job boards) or which files they downloaded and uploaded. Detection focuses on browser command-line flags that trigger private/incognito mode, `RunDll32.exe` invocations of the browser cleanup function, and CCleaner/BleachBit runs targeting browser artifacts.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion |
| **Technique** | T1070.004 — Indicator Removal: File Deletion |
| **Sub-technique** | Browser artifact cleanup, private mode evasion |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**Low (Monitoring)** — Browser cleanup is routine; elevated to Medium when correlated with prior webmail, cloud storage, or file staging activity.

## Query

```logscale
// Internet Explorer / Legacy Edge history clearing via RunDll32
#event_simpleName=ProcessRollup2
| FileName=RunDll32.exe
| CommandLine=/(InetCpl\.cpl,ClearMyTracksByProcess|inetcpl\.cpl.*clear|ClearMyTracks)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Browser launched in private/incognito mode**

```logscale
// Browsers started in private/incognito mode — no history recorded for this session
#event_simpleName=ProcessRollup2
| in(FileName, values=["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe", "opera.exe"])
| CommandLine=/(--incognito|--private|InPrivate|-private|-inprivate)/i
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: Chrome / Edge command-line history clear**

```logscale
// Browser launched with clear-data or profile-reset flags
#event_simpleName=ProcessRollup2
| in(FileName, values=["chrome.exe", "msedge.exe"])
| CommandLine=/(--clear-token-service|--clear-main-frame-cache|profile.*reset|--disable-extensions)/i
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: CCleaner / BleachBit targeting browser history**

```logscale
// Automated cleanup tools — often used to wipe browser history specifically
#event_simpleName=ProcessRollup2
| in(FileName, values=["CCleaner.exe", "CCleaner64.exe", "BleachBit.exe", "PrivaZer.exe", "Wise Disk Cleaner.exe"])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: PowerShell deleting browser history files directly**

```logscale
// PowerShell or cmd directly deleting browser profile data directories
#event_simpleName=ProcessRollup2
| in(FileName, values=["powershell.exe", "cmd.exe"])
| CommandLine=/(
    \\AppData\\Local\\Google\\Chrome\\User Data|
    \\AppData\\Local\\Microsoft\\Edge\\User Data|
    \\AppData\\Roaming\\Mozilla\\Firefox\\Profiles|
    \\AppData\\Local\\BraveSoftware|
    History|Cookies|Cache|Login Data|Visited Links
  )/i
| CommandLine=/(Remove-Item|rd\/s|rmdir|del\/[sq]|rm\s+-rf)/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Batch browser artifact deletion (high-volume file deletes in browser profile)**

```logscale
// High-volume file deletion in browser profile directories — aggressive history wipe
#event_simpleName=FileDeleted
| FilePath=/(
    \\AppData\\Local\\Google\\Chrome\\User Data\\|
    \\AppData\\Local\\Microsoft\\Edge\\User Data\\|
    \\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\|
    \\AppData\\Local\\BraveSoftware\\Brave-Browser\\
  )/i
| groupBy([ComputerName, UserName, FilePath], function=count(as=delete_count))
| delete_count > 20
| sort(delete_count, order=desc)
| table([ComputerName, UserName, FilePath, delete_count])
```

## Response Notes

**Triage steps:**
1. Check what activity preceded the history deletion — webmail DNS queries, personal cloud storage access, or file staging in the prior session window are the key correlations
2. Incognito mode alone is weak signal; incognito mode launch after file staging or before webmail access is much stronger
3. For RunDll32 IE cleanup, check the numeric flag in `ClearMyTracksByProcess` — the bitmask value indicates what was cleared (history, cookies, temp files, passwords)
4. Browser artifacts (SQLite databases, LNK files, Prefetch, Shellbag entries) may survive even after history clearing — forensic acquisition can recover them
5. Correlate with `DnsRequest` events — DNS is logged separately from browser history and is harder to clear

**False positives:**
- Privacy-conscious users routinely use incognito mode for legitimate reasons
- IT departments run CCleaner on endpoints for routine maintenance
- Automated endpoint health scripts may clear browser caches
- This is most valuable as a **correlation signal** rather than a standalone alert

## References

- https://attack.mitre.org/techniques/T1070/004/
- https://support.microsoft.com/en-us/topic/delete-your-browsing-history-in-internet-explorer
