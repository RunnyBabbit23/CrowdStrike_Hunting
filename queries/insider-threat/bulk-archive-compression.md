# Bulk Archive / Compression Before Exfiltration

## Description

Detects use of archiving and compression tools to package large volumes of files — a common pre-exfiltration step in insider threat scenarios. Attackers and malicious insiders use tools like 7-Zip, WinRAR, WinZip, and PowerShell's `Compress-Archive` to bundle files into a single transferable container before moving data via USB, email, or cloud upload. The combination of a compression tool being used with a large number of source files or sensitive paths is the key signal.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Technique** | T1560 — Archive Collected Data |
| **Sub-technique** | T1560.001 — Archive via Utility |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `FileWritten` |

## Severity

**Medium** — Compression tool use alone is common; elevated to High when combined with sensitive source paths, large output archive sizes, or followed by USB/cloud activity.

## Query

```logscale
// Compression tools run with arguments pointing to sensitive paths or producing large archives
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "7z.exe", "7za.exe", "7zr.exe",
    "WinRAR.exe", "Rar.exe", "UnRAR.exe",
    "WinZip32.exe", "WinZip64.exe",
    "zip.exe", "tar.exe",
    "makecab.exe", "expand.exe"
  ])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: PowerShell Compress-Archive (script-based packaging)**

```logscale
// PowerShell used to create archives — often used to avoid triggering on known archive tools
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(Compress-Archive|ZipFile|System\.IO\.Compression|io\.compression)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Archive written to removable or network path**

```logscale
// Archive files written to removable media, network share, or user profile staging area
#event_simpleName=FileWritten
| FileName=/\.(zip|rar|7z|tar|gz|bz2|cab|iso|tgz|tar\.gz)$/i
| FilePath=/(
    [D-Z]:\\|
    \\\\|
    \\Desktop\\|
    \\Downloads\\|
    \\Temp\\|
    \\Public\\|
    \\OneDrive\\|
    \\Dropbox\\|
    \\Google Drive\\|
    \\Box\\
  )/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: High-volume compression activity from a single user (aggregation)**

```logscale
// Users running archive tools frequently — identify heavy archiving sessions
#event_simpleName=ProcessRollup2
| in(FileName, values=["7z.exe","7za.exe","WinRAR.exe","Rar.exe","zip.exe","tar.exe"])
| groupBy([ComputerName, UserName, FileName], function=count(as=archive_count))
| archive_count > 10
| sort(archive_count, order=desc)
| table([ComputerName, UserName, FileName, archive_count])
```

**Variant: Archive tool targeting source code or sensitive paths**

```logscale
// Compression targeting directories that commonly hold sensitive data
#event_simpleName=ProcessRollup2
| in(FileName, values=["7z.exe","7za.exe","WinRAR.exe","Rar.exe","zip.exe"])
| CommandLine=/(
    \\src\\|\\source\\|\\code\\|\\repo\\|\\git\\|
    \\hr\\|\\finance\\|\\payroll\\|\\legal\\|\\contracts\\|
    \\confidential\\|\\secret\\|\\sensitive\\|\\restricted\\|
    \\backup\\|\\database\\|\\db\\
  )/i
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the archive output path from `CommandLine` — destination matters most (USB, cloud sync folder, network share)
2. Review the source path in the command line — what data was packaged?
3. Check `FileWritten` events for the resulting archive file path and size
4. Look at what happened to the archive: was it subsequently uploaded, emailed, or moved to a USB device?
5. Pivot on `UserName` across the session window — did bulk file access (opens/reads) precede the compression?

**False positives:**
- Software developers regularly archive project directories for release or backup
- IT teams use compression for log archiving and software deployment
- Legitimate backup jobs may use compression tools — filter by known backup service accounts
- Tune by excluding known backup tool parent processes: `| ParentBaseFileName!=/backup|veeam|acronis/i`

## References

- https://attack.mitre.org/techniques/T1560/001/
- https://www.cisa.gov/sites/default/files/publications/CISA_Insider_Threat_Mitigation_Guide.pdf
