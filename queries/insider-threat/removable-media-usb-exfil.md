# Removable Media / USB Data Exfiltration

## Description

Detects bulk data transfer to removable storage devices — one of the most direct insider threat exfiltration vectors. CrowdStrike's sensor captures file write events with drive letter context, enabling detection of large volumes of files written to non-system drives (typically `D:\` through `Z:\` for removable media). Key signals include high file write counts to removable paths, sensitive file types being copied, and archive files staged to USB drives.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration |
| **Technique** | T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB |
| **Sub-technique** | Bulk file copy, archive copy to removable media |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `FileWritten`, `ProcessRollup2` |

## Severity

**High** — Bulk file copies to removable media are a primary insider exfiltration vector; treat as high priority especially outside business hours or from sensitive systems.

## Query

```logscale
// High-volume file writes to non-system drive letters (removable media indicators)
#event_simpleName=FileWritten
| FilePath=/^[D-Z]:\\/i
| FilePath!=/^(D|E):\\(Program Files|Windows|ProgramData|Recovery|System Volume Information)/i
| groupBy([ComputerName, UserName, FilePath], function=count(as=file_count))
| file_count > 50
| sort(file_count, order=desc)
| table([ComputerName, UserName, FilePath, file_count])
```

**Variant: Sensitive file types copied to removable drive**

```logscale
// Specific high-value file types written to removable media
#event_simpleName=FileWritten
| FilePath=/^[D-Z]:\\/i
| FileName=/\.(
    docx?|xlsx?|pptx?|pdf|csv|txt|msg|eml|pst|ost|
    sql|db|sqlite|mdb|accdb|
    py|js|ts|go|java|c|cpp|cs|h|
    json|yaml|yml|xml|config|cfg|ini|env|
    pem|key|pfx|p12|ppk|kdbx|rdp|
    zip|rar|7z|tar|gz
  )$/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=500)
```

**Variant: xcopy / robocopy to removable drive (bulk copy command)**

```logscale
// Bulk copy tools targeting removable media paths
#event_simpleName=ProcessRollup2
| in(FileName, values=["xcopy.exe", "robocopy.exe", "copy.exe"])
| CommandLine=/\s[D-Z]:\\/i
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: Explorer-based copy to removable media (shell operation)**

```logscale
// File explorer shell operations writing to removable drives
// Detected via file writes attributed to explorer.exe
#event_simpleName=FileWritten
| FilePath=/^[D-Z]:\\/i
| FileName=explorer.exe
| groupBy([ComputerName, UserName, FilePath], function=count(as=file_count))
| file_count > 20
| sort(file_count, order=desc)
```

**Variant: Archive or encrypted container written to USB**

```logscale
// Single large archive or encrypted container written to removable drive — pre-packaged exfil
#event_simpleName=FileWritten
| FilePath=/^[D-Z]:\\/i
| FileName=/\.(zip|rar|7z|tar|gz|cab|iso|tc|vc|veracrypt|kdbx)$/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: USB activity outside business hours**

```logscale
// File writes to removable media during off-hours (before 7am or after 7pm)
#event_simpleName=FileWritten
| FilePath=/^[D-Z]:\\/i
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| hour < "07" OR hour > "19"
| groupBy([ComputerName, UserName, FilePath, hour], function=count(as=file_count))
| file_count > 10
| sort(file_count, order=desc)
| table([ComputerName, UserName, FilePath, hour, file_count])
```

## Response Notes

**Triage steps:**
1. Identify the drive letter — CrowdStrike does not natively resolve drive type, so correlate with asset management or MDM data to confirm USB vs. secondary fixed disk
2. Review `UserName` and the system — elevated concern for privileged users, departing employees, or systems with sensitive data access
3. Check file types copied — source code, financial data, credentials, and customer PII are highest priority
4. Look at the time window — off-hours USB activity is significantly more suspicious
5. Review whether the user copied then deleted files from the USB (`FileDeleted` on removable path) — covering tracks indicator

**Coverage note:**
- CrowdStrike captures file writes to drive letters; distinguishing USB from secondary fixed disks requires asset context
- Consider enabling `RemovableMediaConnected` event type if available in your Falcon configuration
- Pair with Falcon's USB Device Control policy for preventive enforcement

**False positives:**
- IT administrators use USB drives for OS deployment, firmware updates, and diagnostic tools
- Users may have secondary fixed drives (D:\ for data partition) — exclude known fixed drive paths
- Portable application installations to USB drives — filter by installer parent processes

## References

- https://attack.mitre.org/techniques/T1052/001/
- https://www.crowdstrike.com/blog/usb-device-control-with-crowdstrike-falcon/
- https://www.cisa.gov/sites/default/files/publications/CISA_Insider_Threat_Mitigation_Guide.pdf
