# Network Neighbor Spread Detection — Pivot from Known Compromise

## Description

A structured pivot methodology for identifying lateral spread from a known compromised host. Starting from a single confirmed compromise (hostname, IP, user account, or malware hash), these queries systematically answer: *What other hosts did the attacker reach? What did they do there? Is the malware spreading?*

Run these queries in order — each successive query narrows the scope from "who talked to this host" down to "what hosts have confirmed compromise indicators."

**Replace the placeholder values before running:**
- `COMPROMISED_HOSTNAME` → the confirmed compromised host's name
- `COMPROMISED_IP` → its internal IP address
- `COMPROMISED_USER` → the account used during the compromise
- `MALWARE_HASH` → SHA256 of identified malware (from process list or `00_manifest.csv`)
- `MALWARE_FILENAME` → the malware executable name (e.g., `beacon.exe`)
- `C2_IP` → identified C2 server IP
- `C2_DOMAIN` → identified C2 domain

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement / Discovery |
| **Technique** | T1021 — Remote Services, T1078 — Valid Accounts |
| **Sub-technique** | T1570 — Lateral Tool Transfer, T1018 — Remote System Discovery |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR / Identity Protection |
| **Repository** | `base_sensor_activity`, `base_identity_activity` |
| **Event Types** | `NetworkConnectIP4`, `ProcessRollup2`, `UserLogon`, `AuthActivityAuditEvent`, `DnsRequest` |

## Severity

**High** — Any confirmed spread indicator on a neighbor host requires immediate containment and collection.

---

## Query 1 — Identify All Hosts That Communicated With the Compromised Host

*Who did the compromised host talk to? These are your candidate neighbor hosts.*

```logscale
// Outbound connections FROM the compromised host to internal peers
// Replace COMPROMISED_HOSTNAME with the actual hostname
#event_simpleName=NetworkConnectIP4
| ComputerName=COMPROMISED_HOSTNAME
| RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| groupBy([RemoteAddressIP4, RemotePort], function=count(as=conn_count))
| sort(conn_count, order=desc)
| table([RemoteAddressIP4, RemotePort, conn_count])
```

**Variant: Inbound connections TO the compromised host (who initiated contact?)**

```logscale
// Hosts that connected TO the compromised host — potential attacker source or already-infected peers
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=COMPROMISED_IP
| ComputerName!=COMPROMISED_HOSTNAME
| groupBy([ComputerName, aid, RemotePort], function=count(as=conn_count))
| sort(conn_count, order=desc)
| table([ComputerName, RemoteAddressIP4, RemotePort, conn_count])
```

**Variant: Identify unique internal hosts the compromised machine reached**

```logscale
// Deduplicated list of internal hosts that had sessions with compromised host
#event_simpleName=NetworkConnectIP4
| ComputerName=COMPROMISED_HOSTNAME
| RemoteAddressIP4=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| groupBy([RemoteAddressIP4], function=count())
| table([RemoteAddressIP4, count_])
```

---

## Query 2 — Check for Lateral Movement Artifacts on Neighbor Hosts

*Did the attacker actually execute anything on those neighbors?*

```logscale
// PSEXESVC on neighbor hosts — they were lateral movement targets
#event_simpleName=ProcessRollup2
| FileName=PSEXESVC.exe
| ComputerName!=COMPROMISED_HOSTNAME
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: WMI Provider Host spawning shells on neighbors**

```logscale
// WmiPrvSE spawning cmd/powershell on hosts other than the known compromised one
#event_simpleName=ProcessRollup2
| ParentBaseFileName=WmiPrvSE.exe
| in(FileName, values=["cmd.exe","powershell.exe","wscript.exe","cscript.exe"])
| ComputerName!=COMPROMISED_HOSTNAME
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: Remote scheduled task creation on neighbors (from compromised host)**

```logscale
// schtasks /create run with a remote target (/s flag) originating from any host
#event_simpleName=ProcessRollup2
| FileName=schtasks.exe
| CommandLine=/\/create.*\/s\s/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: New service installed on neighbor hosts (T1543.003 lateral spread)**

```logscale
// Service created on hosts other than the compromised one — common ransomware/C2 spread pattern
#event_simpleName=ProcessRollup2
| FileName=sc.exe
| CommandLine=/create/i
| ComputerName!=COMPROMISED_HOSTNAME
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

---

## Query 3 — Hunt for Malware Hash on All Hosts

*Is the same malware binary present elsewhere in the environment?*

```logscale
// Search for the exact malware SHA256 across all endpoints
// Replace MALWARE_HASH with the actual hash from your forensic collection
#event_simpleName=ProcessRollup2
| SHA256HashData=MALWARE_HASH
| table([ComputerName, UserName, FileName, FilePath, CommandLine, @timestamp], limit=500)
```

**Variant: Search by malware filename (lower confidence, catches renamed copies)**

```logscale
// Search by filename — catches if the malware was copied and executed under same name
#event_simpleName=ProcessRollup2
| FileName=MALWARE_FILENAME
| table([ComputerName, UserName, FilePath, CommandLine, SHA256HashData, @timestamp], limit=500)
```

**Variant: Hunt for the malware file being written to disk on any host**

```logscale
// The malware binary being staged/written to disk
#event_simpleName=PeFileWritten
| SHA256HashData=MALWARE_HASH
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

**Variant: Multiple malware hashes (if you have a list)**

```logscale
// Check all known-bad hashes from this incident across all endpoints
#event_simpleName=ProcessRollup2
| in(SHA256HashData, values=[
    "HASH1_HERE",
    "HASH2_HERE",
    "HASH3_HERE"
  ])
| table([ComputerName, UserName, FileName, SHA256HashData, @timestamp], limit=500)
```

---

## Query 4 — Track Compromised User Account Across the Environment

*Did the attacker use the compromised credentials to authenticate to other systems?*

```logscale
// All logon events from the compromised account on hosts other than the known source
#event_simpleName=UserLogon
| UserName=COMPROMISED_USER
| ComputerName!=COMPROMISED_HOSTNAME
| LogonType!=3
| table([ComputerName, UserName, LogonType, @timestamp], limit=500)
```

**Variant: Network logons (type 3) — pass-the-hash / lateral movement**

```logscale
// Network logons from compromised account — indicates credential reuse across hosts
#event_simpleName=UserLogon
| UserName=COMPROMISED_USER
| LogonType=3
| ComputerName!=COMPROMISED_HOSTNAME
| table([ComputerName, UserName, LogonType, @timestamp], limit=500)
```

**Variant: ITP — Kerberos/NTLM auth from compromised account (domain-wide)**

```logscale
// Domain authentication events for the compromised account (Identity Protection)
#event_simpleName=AuthActivityAuditEvent
| SourceUserName=COMPROMISED_USER
| DestinationComputerName!=COMPROMISED_HOSTNAME
| groupBy([SourceComputerName, DestinationComputerName, EventType], function=count(as=auth_count))
| sort(auth_count, order=desc)
| table([SourceComputerName, DestinationComputerName, EventType, auth_count])
```

**Variant: Privilege use on neighbor hosts with compromised account**

```logscale
// Compromised account using elevated privileges on any host
#event_simpleName=UserLogon
| UserName=COMPROMISED_USER
| LogonType=10
| table([ComputerName, UserName, LogonType, @timestamp], limit=200)
```

---

## Query 5 — Check for C2 Communication on Neighbor Hosts

*Are other hosts already calling home to the same C2 infrastructure?*

```logscale
// Any host connecting to the identified C2 IP (not just the known compromised host)
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=C2_IP
| table([ComputerName, UserName, FileName, RemotePort, @timestamp], limit=500)
```

**Variant: C2 domain in DNS requests across all hosts**

```logscale
// DNS queries for the identified C2 domain from all endpoints
#event_simpleName=DnsRequest
| DomainName=C2_DOMAIN
| table([ComputerName, UserName, DomainName, @timestamp], limit=500)
```

**Variant: Hosts connecting to same ASN/IP range as known C2**

```logscale
// Connections to the same /24 subnet as the known C2 IP (catches C2 infrastructure rotation)
// Replace first three octets of C2 IP below
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=/^C2_IP_FIRST_THREE_OCTETS\./
| RemotePort=443
| ComputerName!=COMPROMISED_HOSTNAME
| table([ComputerName, FileName, RemoteAddressIP4, @timestamp], limit=200)
```

---

## Query 6 — Hunt for Identical Persistence Artifacts on Neighbors

*Did the attacker install the same backdoor persistence on multiple hosts?*

```logscale
// Same registry run key value on any host — persistence copied across environment
#event_simpleName=RegGenericValueUpdate
| RegObjectName=/Software\\Microsoft\\Windows\\CurrentVersion\\Run/i
| RegStringValue=/MALWARE_FILENAME/i
| table([ComputerName, UserName, RegObjectName, RegValueName, RegStringValue, @timestamp], limit=200)
```

**Variant: Same scheduled task name across hosts**

```logscale
// Identical scheduled task created on multiple hosts — automated deployment indicator
#event_simpleName=ProcessRollup2
| FileName=schtasks.exe
| CommandLine=/\/tn\s+"TASK_NAME_HERE"/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

**Variant: Same malware service name across hosts**

```logscale
// Identical service name created across hosts — worm/ransomware deployment pattern
#event_simpleName=ProcessRollup2
| FileName=sc.exe
| CommandLine=/create.*SERVICE_NAME_HERE/i
| table([ComputerName, UserName, CommandLine, @timestamp], limit=200)
```

---

## Query 7 — Timeline of Spread (Chronological View)

*When did the attacker move from host to host? Build the attack timeline.*

```logscale
// All suspicious activity across identified neighbor hosts in a time window
// Replace HOST_LIST with comma-separated hostnames from Query 1 results
#event_simpleName=/(ProcessRollup2|NetworkConnectIP4|UserLogon|RegGenericValueUpdate|PeFileWritten)/
| in(ComputerName, values=[
    "COMPROMISED_HOSTNAME",
    "NEIGHBOR_HOST_1",
    "NEIGHBOR_HOST_2",
    "NEIGHBOR_HOST_3"
  ])
| FileName!=/svchost|MsMpEng|SearchIndexer|WmiPrvSE|TrustedInstaller|wuauclt|spoolsv|lsass|csrss/i
| groupBy([ComputerName, #event_simpleName, FileName], function=count(as=event_count))
| sort(event_count, order=desc)
| table([ComputerName, #event_simpleName, FileName, event_count])
```

**Variant: Per-host first-seen time of malware hash (spread timeline)**

```logscale
// When was the malware first seen on each host? Reveals propagation order and speed
#event_simpleName=ProcessRollup2
| SHA256HashData=MALWARE_HASH
| groupBy([ComputerName], function=[
    min(@timestamp, as=first_seen),
    max(@timestamp, as=last_seen),
    count(as=execution_count)
  ])
| sort(first_seen)
| table([ComputerName, first_seen, last_seen, execution_count])
```

---

## Query 8 — Identify Uncontained Hosts Still Beaconing

*Are there hosts you haven't found yet that are still calling home?*

```logscale
// All internal hosts currently reaching known C2 IP — identifies scope of active compromise
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=C2_IP
| groupBy([ComputerName, aid], function=[
    count(as=beacon_count),
    min(@timestamp, as=first_beacon),
    max(@timestamp, as=last_beacon)
  ])
| sort(last_beacon, order=desc)
| table([ComputerName, beacon_count, first_beacon, last_beacon])
```

**Variant: Active beaconing right now (last 1 hour)**

```logscale
// Hosts still actively communicating with C2 in the last hour — prioritize for containment
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=C2_IP
| @timestamp > now() - 1h
| groupBy([ComputerName, aid], function=count(as=recent_beacons))
| sort(recent_beacons, order=desc)
| table([ComputerName, recent_beacons])
```

---

## Recommended Pivot Workflow

```
1. Run Query 1  →  Get list of internal IPs the compromised host talked to
2. Resolve IPs to hostnames (asset inventory / ipconfig on each)
3. Run Query 2  →  Confirm which neighbors have lateral movement artifacts
4. Run Query 3  →  Check ALL endpoints for the malware hash (not just known neighbors)
5. Run Query 4  →  Track compromised credentials across the domain
6. Run Query 5  →  Check ALL endpoints for C2 communication
7. Run Query 7  →  Build chronological spread timeline
8. Run Query 8  →  Identify any hosts still actively beaconing
9. Contain any newly identified hosts via Falcon network containment
10. Run Invoke-NeighborTriage.ps1 on high-priority neighbors for quick IoC check
11. Run Invoke-ForensicCollection.ps1 on confirmed compromised neighbors
```

## Response Notes

**Triage steps:**
1. Start with Query 1 to establish the blast radius — the list of neighbors is your initial scope
2. Query 3 (hash hunt) is the highest fidelity — confirmed hash match = confirmed compromise
3. Query 4 (user tracking) reveals credential-based spread even if the malware binary changed
4. Query 8 identifies hosts you may have missed — active C2 beaconing is a gift for scoping
5. Contain hosts in Falcon Network Containment as you confirm them — do not wait to finish all queries

**False positives:**
- Internal network scans and monitoring tools will appear in Query 1 — correlate with known scanner IPs
- Service account logons (Query 4) may appear on many hosts legitimately — focus on interactive logon types
- Domain controllers and management servers communicate with all hosts — filter by hostname pattern if needed

## References

- https://attack.mitre.org/techniques/T1021/
- https://www.crowdstrike.com/blog/lateral-movement-detection-with-crowdstrike/
- https://www.sans.org/reading-room/whitepapers/incident/incident-response-pivot-points-39285
