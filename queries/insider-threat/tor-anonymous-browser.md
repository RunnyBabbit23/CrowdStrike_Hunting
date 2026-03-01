# Tor Browser and Anonymous Browsing Detection

## Description

Detects use of Tor Browser and other anonymization tools on corporate endpoints — a strong evasion indicator used by insiders who are aware they are being monitored, or by attackers using a compromised endpoint while avoiding attribution. Tor Browser bundles Firefox with the Tor network client; detection focuses on the process name, the bundled Firefox profile path, network connections to Tor guard nodes, and DNS queries bypassing the corporate resolver. Tor usage on corporate endpoints is rarely legitimate.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Exfiltration |
| **Technique** | T1090.003 — Proxy: Multi-hop Proxy |
| **Sub-technique** | Tor anonymization network, onion routing |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest` |

## Severity

**High** — Tor usage on a corporate endpoint is a strong indicator of intentional monitoring evasion; combine with file staging or data access for near-certain insider threat confirmation.

## Query

```logscale
// Tor Browser process execution (Firefox bundled with Tor)
#event_simpleName=ProcessRollup2
| in(FileName, values=["tor.exe", "tor", "firefox.exe"])
| FilePath=/(
    \\Tor Browser\\|
    \\tor\\|
    \\torbrowser\\|
    \\Desktop\\Tor|
    \\Downloads\\Tor|
    \\AppData.*Tor Browser
  )/i
| table([ComputerName, UserName, FileName, FilePath, CommandLine, @timestamp], limit=200)
```

**Variant: Tor process by name (any install location)**

```logscale
// Tor relay/client process execution regardless of install path
#event_simpleName=ProcessRollup2
| FileName=/(^tor\.exe$|^tor$)/i
| table([ComputerName, UserName, FileName, FilePath, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Network connection to Tor guard node port ranges**

```logscale
// Outbound connections to Tor's common ORPort (9001, 9030) and DirPort
// Tor guard nodes also use 443 and 80 — this catches the dedicated ports
#event_simpleName=NetworkConnectIP4
| in(RemotePort, values=[9001, 9030, 9050, 9051, 9150, 9151])
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| table([ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: SOCKS proxy usage (Tor proxying other apps)**

```logscale
// Applications connecting to localhost SOCKS proxy (Tor default: 127.0.0.1:9050 or 9150)
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4=/^127\.0\.0\.1$/
| in(RemotePort, values=[9050, 9150, 1080, 1081])
| FileName!=/tor\.exe/i
| table([ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: Onion domain DNS queries (Tor DNS leaks)**

```logscale
// .onion TLD queries — indicates Tor usage attempting to reach dark web sites
// Note: proper Tor setups resolve .onion internally; DNS leaks may indicate misconfigured Tor
#event_simpleName=DnsRequest
| DomainName=/\.onion$/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=200)
```

**Variant: Tor directory authority / bootstrap DNS queries**

```logscale
// DNS to Tor Project infrastructure — Tor client bootstrapping
#event_simpleName=DnsRequest
| DomainName=/(
    torproject\.org|
    bridges\.torproject\.org|
    check\.torproject\.org|
    metrics\.torproject\.org|
    dist\.torproject\.org
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=200)
```

**Variant: Other anonymization tools**

```logscale
// I2P, Freenet, and other anonymization network clients
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "i2p.exe", "i2prouter.exe", "i2prouter",
    "freenet.exe",
    "retroshare.exe",
    "tails.exe",
    "whonix.exe"
  ])
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify how Tor was installed — user's `%APPDATA%` or `%Downloads%` path indicates intentional personal installation; `%Temp%` may indicate attacker-deployed tool
2. Check what activity preceded Tor usage — file staging, bulk access, or USB activity in the prior hours
3. Review the duration of Tor sessions via process runtime (first/last event for the process PID)
4. Determine if other high-value data access occurred from the same `UserName` in the same session
5. Preserve forensic artifacts — Tor Browser leaves limited history but process memory may contain URLs visited

**False positives:**
- Security researchers and penetration testers may use Tor — correlate with authorized activity
- Some privacy-focused employees may use Tor for legitimate personal privacy on corporate devices (policy violation but not necessarily malicious)
- Tor is occasionally used for threat intel research — validate with the security team

## References

- https://attack.mitre.org/techniques/T1090/003/
- https://www.torproject.org/
- https://www.crowdstrike.com/blog/how-crowdstrike-detects-tor-usage/
