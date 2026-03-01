# Kerberoasting — Service Ticket Enumeration

## Description

Detects Kerberoasting — a technique where an attacker requests Kerberos service tickets (TGS) for service accounts with SPNs registered in Active Directory, then cracks the tickets offline to recover plaintext passwords. The attack is performed entirely with valid domain credentials and leaves only Kerberos audit logs. CrowdStrike Identity Threat Protection detects anomalous TGS request patterns that deviate from the host's baseline.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting |
| **Sub-technique** | TGS-REQ for RC4-encrypted tickets |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Identity Protection (Falcon ITP) |
| **Repository** | `base_identity_activity` |
| **Event Types** | `SuspiciousKerberosRequest`, `AuthActivityAuditEvent` |

## Severity

**High** — Bulk TGS requests in a short window with RC4 encryption type are a near-certain indicator of Kerberoasting.

## Query

```logscale
// CrowdStrike ITP Kerberoasting detection events
#event_simpleName=SuspiciousKerberosRequest
| ConceptName=/kerberoast/i
| table([ComputerName, UserName, ServiceName, EncryptionType, ConceptName, DetectDescription], limit=200)
```

**Variant: Bulk TGS requests via AuthActivityAuditEvent**

```logscale
// High-volume TGS requests from a single source in 5-minute windows
#event_simpleName=AuthActivityAuditEvent
| EventType=TGS_REQUEST
| EncryptionType=/(RC4|ARCFOUR|0x17|0x18)/i
| groupBy([SourceUserName, SourceComputerName, ServiceName], function=count(as=ticket_count))
| ticket_count > 10
| sort(ticket_count, order=desc)
| table([SourceUserName, SourceComputerName, ServiceName, ticket_count])
```

**Variant: RC4 ticket requests (encryption downgrade indicator)**

```logscale
// TGS requests with RC4 encryption where AES is available — indicates downgrade for crackability
#event_simpleName=AuthActivityAuditEvent
| EventType=TGS_REQUEST
| EncryptionType=/(0x17|0x18)/
| ServiceName!=/krbtgt|kadmin/
| table([SourceUserName, SourceComputerName, ServiceName, EncryptionType, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the source user (`SourceUserName`) and workstation — was this activity expected for that user?
2. Review the list of requested service names — a diverse set of SPNs in a short time is highly suspicious
3. Check if the source IP is a known admin workstation or an unusual endpoint
4. Reset passwords for all targeted service accounts immediately if attack is confirmed
5. Prioritize service accounts with high privileges (Domain Admins, Exchange, SQL) in the ticket list

**False positives:**
- Vulnerability scanners may request service tickets as part of Kerberos enumeration checks
- Legitimate admin tools may request multiple tickets — baseline by user/host before alerting
- Pentest activity — correlate with authorized engagement windows

## References

- https://attack.mitre.org/techniques/T1558/003/
- https://www.crowdstrike.com/blog/kerberoasting-attacks-deep-dive/
- https://adsecurity.org/?p=2011
