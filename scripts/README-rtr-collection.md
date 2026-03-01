# RTR Forensic Collection — Usage Guide

Script: [Invoke-ForensicCollection.ps1](Invoke-ForensicCollection.ps1)

Collects forensic artifacts from a suspected Windows endpoint via CrowdStrike Real-Time Response and packages them into a single ZIP file for download. Designed to run as SYSTEM through RTR without requiring any pre-installed tools.

---

## Quick Reference

```
Step 1 — Upload script to Falcon cloud scripts (one-time)
Step 2 — Open RTR session to the target host
Step 3 — runscript -CloudFile="Invoke-ForensicCollection"
Step 4 — get "C:\Windows\Temp\CS_Forensics_<hostname>_<timestamp>.zip"
```

---

## Step 1 — Upload the Script (One-Time Setup)

1. In the Falcon console navigate to **Response → Scripts**
2. Click **Add Script**
3. Set:
   - **Name:** `Invoke-ForensicCollection`
   - **Platform:** Windows
   - **Permission:** Admin
4. Paste the contents of `Invoke-ForensicCollection.ps1` or upload the file
5. Save

---

## Step 2 — Start an RTR Session

1. Navigate to **Investigate → Hosts** and find the suspected host
2. Click **Contain** → **Real-Time Response** (or use the RTR from a Detection)
3. Wait for the session to connect — you will see a command prompt

---

## Step 3 — Run the Collection Script

**Basic run (all artifacts, default settings):**
```
runscript -CloudFile="Invoke-ForensicCollection"
```

**Without full EVTX file copies (faster, smaller output):**
```
runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-IncludeEventLogs:`$false"
```

**Without browser artifact copies:**
```
runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-IncludeBrowserArtifacts:`$false"
```

**Custom output path:**
```
runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-OutputPath C:\Temp"
```

**Limit event log CSV entries (reduce size):**
```
runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-MaxEventLogEntries 1000"
```

**Combined options:**
```
runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-IncludeEventLogs:`$false -MaxEventLogEntries 2000"
```

The script prints progress to the RTR console as it runs. Watch for the final output line:

```
[HH:MM:SS][INFO] Download with RTR command:
[HH:MM:SS][INFO]   get "C:\Windows\Temp\CS_Forensics_HOSTNAME_20241201_143022.zip"
```

---

## Step 4 — Download the ZIP

Copy the exact path from the script's final output and run:

```
get "C:\Windows\Temp\CS_Forensics_HOSTNAME_20241201_143022.zip"
```

The file will download to your local machine via the Falcon console. Depending on the size, this may take a few minutes.

**Typical ZIP sizes:**
| Configuration | Approximate Size |
|---|---|
| Full collection (EVTX + browsers) | 150–500 MB |
| No EVTX, no browsers | 5–25 MB |
| No EVTX, with browsers | 20–80 MB |

---

## Step 5 — Verify Integrity

The ZIP contains `00_collection_manifest.txt` with SHA256 hashes of every collected file. Verify on receipt:

**PowerShell:**
```powershell
# Verify the ZIP itself
Get-FileHash .\CS_Forensics_HOSTNAME_timestamp.zip -Algorithm SHA256

# After extraction, compare individual files against the manifest
$manifest = Import-Csv .\CS_Forensics_HOSTNAME_timestamp\00_manifest.csv
foreach ($item in $manifest | Where-Object { $_.Collected -eq 'True' }) {
    $file = ".\CS_Forensics_HOSTNAME_timestamp\$($item.File)"
    $actual = (Get-FileHash $file -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if ($actual -ne $item.SHA256) {
        Write-Warning "HASH MISMATCH: $($item.File)"
    }
}
```

---

## What Is Collected

### `system/`
| File | Contents |
|---|---|
| `systeminfo.txt` | Full systeminfo output — OS, hardware, patches, network config |
| `hostname_ip.txt` | Hostname, domain, full ipconfig /all |
| `installed_software.csv` | All installed programs from 32-bit and 64-bit registry hives |
| `hotfixes.csv` | Installed Windows patches sorted by date |
| `environment_vars.txt` | All environment variables |
| `disk_info.txt` | Volumes, partitions, free space |
| `loaded_drivers.csv` | Kernel drivers (name, state, binary path) |

### `network/`
| File | Contents |
|---|---|
| `netstat.txt` | `netstat -ano` output |
| `netstat_with_process.txt` | Connections with process names resolved |
| `arp_cache.txt` | ARP table |
| `dns_cache.txt` | DNS client resolver cache |
| `route_table.txt` | IP routing table |
| `firewall_rules.csv` | Enabled Windows Firewall rules |
| `network_shares.txt` | Active SMB shares |
| `smb_sessions.txt` | Active inbound SMB sessions |
| `hosts_file.txt` | Windows hosts file (check for redirect/poisoning) |

### `processes/`
| File | Contents |
|---|---|
| `running_processes.csv` | All processes: PID, PPID, path, command line, SHA256 |
| `process_tree.txt` | Parent-child process hierarchy |
| `services.csv` | All services: state, start mode, binary path, account |
| `dll_list.txt` | All loaded modules per process |

### `users/`
| File | Contents |
|---|---|
| `local_users.txt` | Local user accounts and properties |
| `local_groups.txt` | Local groups and members |
| `logged_on_users.txt` | Currently active sessions (quser + WMI) |
| `user_profiles.txt` | All user profiles with last use times |
| `recent_logon_events.csv` | Security events: 4624, 4625, 4634, 4648, 4672, 4776 |

### `persistence/`
| File | Contents |
|---|---|
| `run_keys.txt` | HKLM/HKCU run key values |
| `scheduled_tasks.csv` | All tasks: name, state, actions, triggers, last run |
| `startup_folders.txt` | Contents of all-users and per-user startup folders |
| `image_file_execution_options.txt` | IFEO debugger entries (accessibility backdoors) |
| `wmi_subscriptions.txt` | WMI event filters, consumers, and bindings |
| `com_hijack_check.txt` | HKCU CLSID overrides (COM hijacking) |

### `logs/`
| File | Contents |
|---|---|
| `security_events.csv` | Security channel: key event IDs in CSV |
| `system_events.csv` | System channel: service install/crash events |
| `application_events.csv` | Application channel: last N events |
| `powershell_events.csv` | PowerShell operational: 4103, 4104 (script block logging) |
| `sysmon_events.csv` | Sysmon events if installed |
| `taskscheduler_events.csv` | Task scheduler: task created, modified, executed |
| `*.evtx` | Raw EVTX files for Security, System, Application, PowerShell, Sysmon, RDP |

### `files/`
| File | Contents |
|---|---|
| `prefetch_list.txt` | Listing of all prefetch files |
| `prefetch\*.pf` | Last 128 prefetch files (binary, parse with PECmd) |
| `temp_recent_files.txt` | Recently modified files in all TEMP directories |
| `recently_modified_executables.txt` | PE/script files modified in last 30 days in user-writable paths |
| `lnk_recent_files.txt` | LNK files from Recent folders for all users |
| `downloads_folders.txt` | Downloads folder contents for all users (last 60 days) |

### `registry/`
| File | Contents |
|---|---|
| `run_hklm.reg`, `run_hkcu.reg` | Autorun keys |
| `services.reg` | Services hive |
| `usb_history.reg`, `usb_devices.reg` | USB device history |
| `typed_paths.reg` | Explorer address bar typed paths |
| `recent_docs.reg` | RecentDocs registry (recently opened files by type) |
| `run_mru.reg` | Run dialog history |
| `ifeo.reg` | Image File Execution Options |
| `shimcache.reg` | AppCompatCache / ShimCache (application execution evidence) |
| `bam_dam.reg` | Background Activity Monitor (execution timestamps) |
| `rdp_mru.reg` | RDP client recently connected servers |
| `lsa_settings.reg` | LSA configuration (WDigest, Credential Guard) |
| `Amcache.hve` | AmCache hive binary (parse with AmcacheParser) |

### `browser/`
Copies of SQLite database files for Chrome, Edge, and Firefox for each user profile:
- `History` — URLs visited with timestamps
- `Cookies` — Session cookies
- `Places.sqlite` (Firefox) — History + bookmarks

Parse with [DB Browser for SQLite](https://sqlitebrowser.org/) or tools like [hindsight](https://github.com/obsidianforensics/hindsight).

---

## Analyzing the Output

### Recommended tools
| Tool | Use | Source |
|---|---|---|
| **Timeline Explorer** | Parse all CSVs into unified timeline | Eric Zimmerman Tools |
| **PECmd** | Parse prefetch files | Eric Zimmerman Tools |
| **AmcacheParser** | Parse Amcache.hve | Eric Zimmerman Tools |
| **AppCompatCacheParser** | Parse ShimCache from registry export | Eric Zimmerman Tools |
| **RegRipper** | Deep registry hive analysis | GitHub: keydet89/RegRipper3.0 |
| **DB Browser for SQLite** | Browse browser history databases | sqlitebrowser.org |
| **Hindsight** | Chrome/Edge browser forensics | GitHub: obsidianforensics/hindsight |
| **Chainsaw** | Fast sigma-rule based EVTX hunting | GitHub: WithSecureLabs/chainsaw |
| **Hayabusa** | EVTX timeline generation | GitHub: Yamato-Security/hayabusa |

### Quick triage with PowerShell (on your analyst workstation)

```powershell
# See recently modified executables in writable paths
Import-Csv .\CS_Forensics_HOST_ts\files\recently_modified_executables.txt  # (review manually)

# Find processes with no path (hollow/injected)
Import-Csv .\CS_Forensics_HOST_ts\processes\running_processes.csv |
    Where-Object { -not $_.ExecutablePath } |
    Select-Object PID, ParentPID, Name, CommandLine

# Look for non-standard services
Import-Csv .\CS_Forensics_HOST_ts\processes\services.csv |
    Where-Object { $_.PathName -notmatch 'System32|SysWOW64|Program Files' -and $_.State -eq 'Running' } |
    Select-Object Name, PathName, StartName

# Review external connections from netstat
Get-Content .\CS_Forensics_HOST_ts\network\netstat_with_process.txt |
    Where-Object { $_ -match 'ESTABLISHED' }

# Check for IFEO debugger backdoors
Get-Content .\CS_Forensics_HOST_ts\persistence\image_file_execution_options.txt |
    Where-Object { $_ -match '-->' }

# Recent logon failures then successes
Import-Csv .\CS_Forensics_HOST_ts\users\recent_logon_events.csv |
    Where-Object { $_.EventId -in @('4625','4648') } |
    Select-Object TimeCreated, EventId, Message |
    Sort-Object TimeCreated
```

---

## Chain of Custody Notes

- Record the RTR session ID from the Falcon audit log
- Note the collection timestamp from the ZIP filename
- The `00_collection_manifest.txt` inside the ZIP contains:
  - Collecting user identity (SYSTEM)
  - Start/end timestamps
  - SHA256 hash of every collected file
  - Any collection errors
- Store the original ZIP with write-protection and document your hash before analysis

---

## Troubleshooting

| Issue | Solution |
|---|---|
| `runscript` times out | The default RTR script timeout is 55 seconds. For large environments run without EVTX: `-IncludeEventLogs:$false` |
| `get` fails or is slow | Large ZIPs can take time; confirm the file exists first with `ls C:\Windows\Temp\CS_*` |
| Script runs but output is empty | Confirm the script is saved correctly in cloud scripts — check for encoding issues |
| Access denied on some artifacts | Normal — SYSTEM does not have access to some per-user locked files; check `00_collection_manifest.txt` for failures |
| ZIP not created | Check for free disk space on C: drive; collection staging requires ~2x the artifact size |
