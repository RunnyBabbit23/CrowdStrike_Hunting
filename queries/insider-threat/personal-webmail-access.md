# Personal Webmail Access from Corporate Endpoints

## Description

Detects access to personal webmail services — Gmail, Yahoo Mail, Outlook.com, ProtonMail, Tutanota — from corporate devices. Insiders use webmail as an exfiltration channel because it uses standard HTTPS (port 443), blends into normal browser traffic, and creates an out-of-band communication path that bypasses corporate email DLP. The combination of webmail DNS queries following bulk file access or sensitive data interaction is the key signal chain.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration |
| **Technique** | T1048.003 — Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol |
| **Sub-technique** | T1567 — Exfiltration Over Web Service (webmail) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `DnsRequest`, `NetworkConnectIP4` |

## Severity

**Low (Monitoring)** — Personal webmail access is common on corporate devices; severity increases when preceded by bulk data access or combined with file staging activity.

## Query

```logscale
// DNS queries to personal webmail services from corporate endpoints
#event_simpleName=DnsRequest
| DomainName=/(
    mail\.google\.com|gmail\.com|googlemail\.com|
    mail\.yahoo\.com|ymail\.com|yahoomail\.com|
    outlook\.live\.com|hotmail\.com|live\.com|msn\.com|
    protonmail\.com|proton\.me|pm\.me|
    tutanota\.com|tutamail\.com|tuta\.io|
    fastmail\.com|fastmail\.fm|
    zoho\.com|mail\.zoho\.com|
    icloud\.com|me\.com|mac\.com|
    gmx\.com|gmx\.net|
    mail\.com|
    aol\.com|aim\.com|
    yandex\.com|yandex\.ru|mail\.yandex\.com|
    cock\.li|disroot\.org|
    guerrillamail\.com|10minutemail\.com
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=500)
```

**Variant: Encrypted/anonymous email services (higher risk)**

```logscale
// Privacy-focused or anonymous email — higher risk for deliberate evasion
#event_simpleName=DnsRequest
| DomainName=/(
    protonmail\.com|proton\.me|pm\.me|
    tutanota\.com|tutamail\.com|tuta\.io|
    guerrillamail\.com|
    10minutemail\.com|
    mailnesia\.com|
    maildrop\.cc|
    cock\.li|
    disroot\.org|
    riseup\.net|
    ctemplar\.com
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=200)
```

**Variant: SMTP/IMAP clients connecting to personal mail servers**

```logscale
// Email clients connecting to personal mail infrastructure via standard mail ports
#event_simpleName=NetworkConnectIP4
| in(RemotePort, values=[25, 465, 587, 993, 995, 143, 110])
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| in(FileName, values=["outlook.exe", "thunderbird.exe", "mailbird.exe", "eM Client.exe", "the bat.exe", "postfix"])
| table([ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: Webmail access frequency aggregation (identify heavy users)**

```logscale
// Users with frequent personal webmail DNS queries — identify patterns over time
#event_simpleName=DnsRequest
| DomainName=/(gmail\.com|mail\.google\.com|protonmail\.com|tutanota\.com|yahoo\.com|hotmail\.com|outlook\.live)/i
| groupBy([ComputerName, UserName, DomainName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([ComputerName, UserName, DomainName, query_count])
```

## Response Notes

**Triage steps:**
1. This query is most valuable as a **correlation signal** — combine with file staging, bulk enumeration, or USB activity from the same user in the same time window
2. Standalone webmail access is likely benign; trigger investigation when preceded by sensitive data access within the same session
3. ProtonMail, Tutanota, and similar privacy-focused services are higher risk because emails are end-to-end encrypted, eliminating any DLP visibility
4. Check the timing — webmail access immediately after accessing sensitive directories is the key correlation
5. Review any SMTP/IMAP connections (non-browser) — configuring Thunderbird to pull corporate email via personal mail forwarding is an evasion technique

**False positives:**
- Personal webmail access for non-work purposes is extremely common on corporate devices — this is informational unless correlated with other signals
- Remote workers often access personal email on corporate devices during work hours
- Some organizations explicitly permit personal webmail — validate against policy before acting

## References

- https://attack.mitre.org/techniques/T1048/003/
- https://www.crowdstrike.com/blog/insider-threat-detection/
