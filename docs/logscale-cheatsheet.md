# LogScale Query Language Cheatsheet

Reference for writing CrowdStrike Falcon Next-Gen SIEM queries.

---

## Basic Syntax

```logscale
// Filter by event type (tag field — most efficient, evaluated first)
#event_simpleName=ProcessRollup2

// Pipe-chain additional filters
| FileName=/powershell\.exe/i
| CommandLine=/-enc/i

// Output
| table([ComputerName, UserName, CommandLine], limit=500)
```

---

## Filtering

```logscale
// Exact match
FileName=powershell.exe

// Case-insensitive regex
FileName=/powershell\.exe/i

// Negation
FileName!=/powershell\.exe/i

// OR logic (field)
FileName=/(powershell|cmd|wscript)\.exe/i

// Set membership
| in(FileName, values=["powershell.exe", "cmd.exe", "wscript.exe"])

// NOT in set
| !in(FileName, values=["svchost.exe", "explorer.exe"])

// Wildcard (use sparingly — regex is preferred)
FileName=*powershell*

// Numeric comparison
RemotePort > 1024
RemotePort <= 443

// Field existence
FileName=*      // field exists and is non-empty
```

---

## String Operations

```logscale
// Contains (case-sensitive)
CommandLine=*-encoded*

// Lowercase for normalization
| eval(cmdLower=lower(CommandLine))
| cmdLower=*-enc*

// String length
| eval(cmdLen=length(CommandLine))
| cmdLen > 500

// Substring extraction
| eval(ext=substr(FileName, -4, 4))
```

---

## Aggregation

```logscale
// Count events by field
| groupBy([ComputerName], function=count())

// Count with multiple group-by fields
| groupBy([ComputerName, UserName], function=count(as=event_count))

// Sort descending
| sort(event_count, order=desc)

// Top N
| head(20)

// Unique values
| groupBy([CommandLine], function=count())
| sort(count_, order=desc)

// Rare values (anomaly hunting)
| groupBy([FileName], function=count())
| count_ < 5
| sort(count_)
```

---

## Time Operations

```logscale
// Format timestamp
| eval(eventTime=formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp))

// Time-based bucketing (for frequency analysis)
| bucket(span=1h, function=count())

// Relative time filter (in query bar, use the time picker)
// For inline: @timestamp > now()-7d
```

---

## Joins

```logscale
// Self-join to correlate two event types
#event_simpleName=ProcessRollup2
| FileName=/lsass\.exe/i
| join({
    #event_simpleName=NetworkConnectIP4
    | RemotePort=443
  }, field=aid, include=[RemoteAddressIP4, RemotePort])
```

---

## Eval / Computed Fields

```logscale
// Create new field
| eval(suspiciousScore=if(CommandLine=*-enc*, 10, 0))

// Conditional
| eval(risk=case(
    CommandLine=*-enc* AND CommandLine=*bypass*, "high",
    CommandLine=*-enc*, "medium",
    default="low"
  ))
```

---

## Common CrowdStrike Event Types

### Endpoint EDR (`base_sensor_activity`)

| Event | Description |
|---|---|
| `ProcessRollup2` | Process creation with full command line |
| `SyntheticProcessRollup2` | Synthetic process events |
| `NetworkConnectIP4` | IPv4 outbound connection |
| `NetworkConnectIP6` | IPv6 outbound connection |
| `NetworkListenIP4` | Listening socket |
| `DnsRequest` | DNS query |
| `FileWritten` | File write |
| `FileDeleted` | File deletion |
| `PeFileWritten` | PE/executable written to disk |
| `RegGenericValueUpdate` | Registry value set |
| `RegKeyCreated` | Registry key created |
| `UserLogon` | Local/domain logon |
| `UserLogoff` | Logoff event |
| `DriverLoad` | Kernel driver loaded |
| `ImageLoad` | DLL/module loaded |
| `SuspiciousPageAllocated` | Suspicious memory allocation (injection) |
| `InjectedThread` | Remote thread injection |
| `EngineLoadEvent` | Script engine loaded |
| `CommandHistory` | Shell command history |

### Identity Protection (`base_identity_activity`)

| Event | Description |
|---|---|
| `AuthActivityAuditEvent` | Authentication activity |
| `DirectoryServiceEventV2` | LDAP/AD operations |
| `SuspiciousKerberosRequest` | Anomalous Kerberos ticket request |
| `IdentityConceptEvent` | ITP-generated behavioral concept |

### Cloud CSPM (`falcon_audit`, `cloudtrail`)

| Event | Description |
|---|---|
| `CloudAuditEvent` | Unified cloud API audit event |
| `PolicyDetectionSummary` | CSPM policy violation |

---

## Key CrowdStrike Fields

### Process Events
| Field | Description |
|---|---|
| `aid` | Agent ID (unique per sensor install) |
| `cid` | Customer ID |
| `ComputerName` | Hostname |
| `UserName` | Executing user |
| `FileName` | Executable name only |
| `FilePath` | Full path (may need `ImageFileName`) |
| `CommandLine` | Full command line |
| `ParentBaseFileName` | Parent process name |
| `ParentCommandLine` | Parent command line |
| `MD5HashData` | MD5 hash |
| `SHA256HashData` | SHA256 hash |
| `ProcessId` (or `TargetProcessId`) | PID |

### Network Events
| Field | Description |
|---|---|
| `RemoteAddressIP4` | Destination IP |
| `RemotePort` | Destination port |
| `LocalAddressIP4` | Source IP |
| `LocalPort` | Source port |
| `Protocol` | TCP/UDP |

### DNS Events
| Field | Description |
|---|---|
| `DomainName` | Queried domain |
| `RequestType` | DNS record type |

### Registry Events
| Field | Description |
|---|---|
| `RegObjectName` | Registry key path |
| `RegValueName` | Value name |
| `RegStringValue` | String value data |
| `RegNumericValue` | Numeric value data |

---

## Tips for NG-SIEM Advanced Search

1. **Always filter on `#event_simpleName` first** — it's a tag and avoids full-text scan
2. **Use `limit=` on `table()`** — default can be slow on large result sets
3. **Pivot on `aid`** — correlate all activity from the same sensor in one query
4. **Regex over wildcards** — `/pattern/i` is faster and more precise than `*pattern*`
5. **Time range matters** — start with 24h, expand to 7d if needed
6. **Use `groupBy` before `table`** for aggregation-based anomaly hunting
