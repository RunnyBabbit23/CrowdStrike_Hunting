# C2 Beaconing — Periodic Outbound Connections

## Description

Detects command and control beaconing — periodic outbound network connections from an implant to a C2 server at regular intervals. Beacons are a hallmark of post-exploitation frameworks such as Cobalt Strike, Metasploit Meterpreter, Sliver, Brute Ratel, and custom malware. Detection focuses on high connection frequency to a single destination from a single process, unexpected processes making outbound connections, and connections on non-standard ports.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Command and Control |
| **Technique** | T1071.001 — Application Layer Protocol: Web Protocols |
| **Sub-technique** | T1095 (non-application layer), T1571 (non-standard port) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `NetworkConnectIP4`, `NetworkConnectIP6` |

## Severity

**Medium** — Requires correlation with process context and destination reputation; high frequency + uncommon process = High.

## Query

```logscale
// Processes with high outbound connection frequency to a single IP (beaconing pattern)
#event_simpleName=NetworkConnectIP4
| groupBy([aid, ComputerName, FileName, RemoteAddressIP4, RemotePort], function=count(as=conn_count))
| conn_count > 50
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| sort(conn_count, order=desc)
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, conn_count])
```

**Variant: Uncommon processes making outbound connections**

```logscale
// Non-browser, non-system processes making outbound connections on standard web ports
#event_simpleName=NetworkConnectIP4
| in(RemotePort, values=[80, 443, 8080, 8443])
| FileName!=/\b(chrome|firefox|msedge|iexplore|svchost|lsass|services|spoolsv|wuauclt|msiexec|backgroundtaskhost|searchindexer|searchprotocolhost|onedrive|teams|zoom|outlook|slack)\b/i
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort], function=count(as=conn_count))
| sort(conn_count, order=desc)
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, conn_count])
```

**Variant: Non-standard port C2 connections**

```logscale
// Outbound connections to uncommon ports (not 80, 443, 53, 25, 587, 993)
#event_simpleName=NetworkConnectIP4
| RemotePort not in [80, 443, 53, 25, 110, 587, 993, 995, 22, 3389, 445, 135, 139]
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| FileName!=/\b(svchost|lsass|services|wuauclt|msiexec|vmware|virtualbox|teams|zoom)\b/i
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort], function=count(as=conn_count))
| conn_count > 5
| sort(conn_count, order=desc)
```

## Response Notes

**Triage steps:**
1. Check `RemoteAddressIP4` against threat intel feeds and passive DNS
2. Identify the `FileName` making connections — system processes (svchost) making connections on unusual ports are concerning; unknown binaries are critical
3. Pivot on `aid` to correlate the network activity with process creation and file write events
4. Look for jitter patterns — true beaconing has regular timing; use time-bucketed `groupBy` to visualize intervals
5. Capture or proxy the connection if possible to inspect C2 protocol (HTTP/S beacon headers, custom protocol)

**False positives:**
- Endpoint agents (EDR, AV, DLP, patch management) make frequent outbound connections
- Video conferencing and chat apps (Teams, Zoom, Slack) connect frequently to cloud endpoints
- The process exclusion list should be tuned for your environment — start broad, then narrow

## References

- https://attack.mitre.org/techniques/T1071/001/
- https://www.crowdstrike.com/blog/detecting-cobalt-strike-command-and-control/
- https://unit42.paloaltonetworks.com/cobalt-strike-threat-hunting/
