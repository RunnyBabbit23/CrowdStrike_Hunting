# Mass File Encryption / Ransomware Behavior

## Description

Detects mass file write/rename activity consistent with ransomware encryption — characterized by a single process writing or renaming a large number of files in rapid succession, often appending a ransomware-specific extension. CrowdStrike's sensor captures file system operations, enabling detection of encryption activity both from known ransomware families and novel variants. This query is most effective when combined with shadow copy deletion detection.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Impact |
| **Technique** | T1486 — Data Encrypted for Impact |
| **Sub-technique** | File encryption, extension appending |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `FileWritten`, `PeFileWritten` |

## Severity

**High** — Mass file modification activity is a near-certain ransomware indicator requiring immediate response.

## Query

```logscale
// Mass file writes from a single process — potential encryption activity
#event_simpleName=FileWritten
| groupBy([aid, ComputerName, FileName], function=count(as=file_write_count))
| file_write_count > 100
| FileName!=/\b(MsMpEng|svchost|SearchIndexer|TiWorker|wuauclt|TrustedInstaller|msiexec|explorer|OneDrive|Dropbox|GoogleDrive)\b/i
| sort(file_write_count, order=desc)
| table([ComputerName, FileName, file_write_count])
```

**Variant: Known ransomware extension appending**

```logscale
// File writes with common ransomware extensions appended
#event_simpleName=FileWritten
| FileName=/\.(
    locked|encrypted|enc|crypt|cry|lck|
    lockbit|blackcat|alphv|cl0p|clop|
    ryuk|revil|sodinokibi|darkside|
    wasted|babuk|hive|avos|conti|
    egregor|maze|netwalker|phobos|
    dharma|stop|djvu|rdp|zzzzz|
    zepto|locky|cerber|petya|notpetya
  )$/i
| table([ComputerName, UserName, FileName, FilePath], limit=200)
```

**Variant: Ransom note file creation**

```logscale
// Ransom note files dropped — confirms active ransomware deployment
#event_simpleName=FileWritten
| FileName=/(
    HOW_TO_DECRYPT|DECRYPT_INSTRUCTIONS|READ_ME|RESTORE_FILES|
    YOUR_FILES_ARE_ENCRYPTED|RECOVERY_FILES|!!!READ_THIS!!!|
    HOW_TO_RESTORE|_readme\.txt|ransom_note|@Restore-My-Files
  )/i
| table([ComputerName, UserName, FileName, FilePath], limit=200)
```

## Response Notes

**Triage steps:**
1. **Immediately isolate affected hosts** at the network level — ransomware may be spreading via SMB
2. Identify the encrypting process from `FileName` — check its full path (`FilePath`) and hash
3. Determine patient zero: which host started encryption first, and what preceded it (lateral movement, initial access)
4. Check if the ransomware binary was staged to other hosts before encryption began
5. Coordinate with backup/storage teams to identify last known-good snapshot

**False positives:**
- Backup agents perform mass reads/writes during backup operations — they should not append new extensions
- File sync tools (OneDrive, Dropbox) perform mass writes during initial sync — filter by known sync processes
- Antivirus quarantine operations may rename files — but not in large volumes with unknown extensions

## References

- https://attack.mitre.org/techniques/T1486/
- https://www.crowdstrike.com/blog/ransomware-hunting-with-crowdstrike-falcon/
- https://thedfirreport.com/
