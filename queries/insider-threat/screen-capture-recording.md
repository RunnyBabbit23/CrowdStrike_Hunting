# Screen Capture and Recording Tools

## Description

Detects use of screen capture and recording software in potentially sensitive contexts — including third-party screenshot tools (Greenshot, Snagit, ShareX), screen recording (OBS, Camtasia), and Windows built-in capture utilities. While legitimate in many workflows, repeated or bulk screenshot activity on endpoints with access to sensitive data (financial systems, source code, customer records) can indicate data harvesting by an insider who lacks file-level access but can view data on screen.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection |
| **Technique** | T1113 — Screen Capture |
| **Sub-technique** | Automated/bulk screenshot, screen recording |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `FileWritten` |

## Severity

**Low (Monitoring)** — Screen capture tools are widespread; elevated to Medium/High when used on sensitive systems, at high frequency, or combined with bulk file staging.

## Query

```logscale
// Third-party screen capture and recording tool execution
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "Greenshot.exe",
    "Snagit32.exe", "Snagit64.exe", "SnagitEditor.exe",
    "ShareX.exe",
    "Lightshot.exe",
    "PicPick.exe",
    "obs64.exe", "obs32.exe", "obs.exe",
    "Camtasia.exe", "CamtasiaStudio.exe",
    "Bandicam.exe",
    "Fraps.exe",
    "FlashBack.exe",
    "Debut.exe",
    "RecordMyDesktop.exe"
  ])
| table([ComputerName, UserName, FileName, FilePath, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Built-in Windows capture tools (SnippingTool, PSR, Xbox Game Bar)**

```logscale
// Built-in Windows screenshot and recording utilities
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "SnippingTool.exe",
    "ScreenSketch.exe",
    "psr.exe",
    "GameBar.exe",
    "GameBarPresenceWriter.exe"
  ])
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Problem Steps Recorder (PSR) — automated screenshot logging**

```logscale
// psr.exe with /start flag — automated screenshot capture of all user actions
#event_simpleName=ProcessRollup2
| FileName=psr.exe
| CommandLine=/\/start/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: High-frequency screenshot file creation**

```logscale
// Large number of image files written in short period — bulk screenshot harvesting
#event_simpleName=FileWritten
| FileName=/\.(png|jpg|jpeg|bmp|gif|tiff|tif)$/i
| FilePath=/(\\Screenshots\\|\\Captures\\|\\Pictures\\|\\Desktop\\|\\Temp\\)/i
| groupBy([ComputerName, UserName, FilePath, bin(@timestamp, span=30min)], function=count(as=screenshot_count))
| screenshot_count > 20
| sort(screenshot_count, order=desc)
| table([ComputerName, UserName, FilePath, screenshot_count, _bucket])
```

**Variant: Screen capture output in staging directories**

```logscale
// Screenshot or recording files written to exfil-ready locations
#event_simpleName=FileWritten
| FileName=/\.(png|jpg|mp4|avi|mkv|mov|wmv|gif)$/i
| FilePath=/(\\Desktop\\|\\Downloads\\|\\Temp\\|\\Public\\|\\OneDrive\\|\\Dropbox\\)/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Determine if the user has a legitimate need for screen capture — marketing, training, and support teams commonly use these tools
2. Check the frequency and timing — bulk captures in a short window during off-hours are higher risk
3. Review what application had focus during the capture session (if determinable from other events)
4. Look for the captured images being compressed, emailed, or uploaded in the same session window
5. For `psr.exe /start` — this is rarely used legitimately and logs every mouse click and screen state

**False positives:**
- IT support teams use screen recording to document issues and create tutorials
- Developers use screenshot tools for documentation and bug reporting
- Training and L&D teams routinely record screens for course content
- Baseline `FileName` frequency per user over 30 days to identify anomalous spikes

## References

- https://attack.mitre.org/techniques/T1113/
- https://www.proofpoint.com/us/blog/insider-threat-management/common-insider-threat-indicators
