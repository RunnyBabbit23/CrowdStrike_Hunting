# Pass-the-Hash / Pass-the-Ticket Detection

## Description

Detects pass-the-hash (PtH) and pass-the-ticket (PtT) attacks — techniques where an attacker uses captured NTLM hashes or Kerberos tickets to authenticate as a user without knowing their plaintext password. PtH is characterized by NTLM logons from unexpected source hosts, logon type 3 (network) from workstation-to-workstation, and `sekurlsa::pth` patterns. CrowdStrike Identity Threat Protection detects these through behavioral analysis of authentication patterns.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Lateral Movement / Credential Access |
| **Technique** | T1550.002 — Use Alternate Authentication Material: Pass the Hash |
| **Sub-technique** | T1550.003 — Pass the Ticket |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Identity Protection (Falcon ITP) |
| **Repository** | `base_identity_activity` |
| **Event Types** | `AuthActivityAuditEvent`, `IdentityConceptEvent` |

## Severity

**High** — Confirmed PtH/PtT behavioral detections from ITP are high-fidelity; NTLM anomalies require additional context.

## Query

```logscale
// CrowdStrike ITP Pass-the-Hash concept events
#event_simpleName=IdentityConceptEvent
| ConceptName=/(PassTheHash|PassTheTicket|OverpassTheHash|Kerberos.*Delegation.*Abuse)/i
| table([ComputerName, UserName, ConceptName, DetectDescription, Severity, @timestamp], limit=200)
```

**Variant: Workstation-to-workstation NTLM authentication (lateral movement indicator)**

```logscale
// NTLM logons between workstations — atypical in standard environments
#event_simpleName=AuthActivityAuditEvent
| EventType=NTLM_AUTHENTICATE
| AuthenticationPackage=NTLM
| SourceComputerName!=/dc|domaincontroller|ad\d|srv|server/i
| DestinationComputerName!=/dc|domaincontroller|ad\d|srv|server/i
| SourceComputerName!=DestinationComputerName
| groupBy([SourceComputerName, DestinationComputerName, SourceUserName], function=count(as=ntlm_count))
| ntlm_count > 5
| sort(ntlm_count, order=desc)
```

**Variant: Anomalous Kerberos ticket usage (PtT indicator)**

```logscale
// Kerberos ticket used from different IP than where it was requested
#event_simpleName=AuthActivityAuditEvent
| EventType=TGS_REQUEST
| SourceIPAddress!=ClientIPAddress
| table([SourceUserName, SourceIPAddress, ClientIPAddress, ServiceName, @timestamp], limit=200)
```

**Variant: mimikatz sekurlsa::pth command (source-side)**

```logscale
// Mimikatz pass-the-hash command execution
#event_simpleName=ProcessRollup2
| CommandLine=/(sekurlsa::pth|pth.*\/user|pth.*\/ntlm|mimikatz.*lsadump|mimikatz.*sekurlsa)/i
| table([ComputerName, UserName, CommandLine, FileName, SHA256HashData], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the destination host targeted in the PtH/PtT — assess what resources are accessible there
2. Determine which hash/ticket was used — pivot to credential dumping events (LSASS access) that may have preceded this
3. Check the source host for signs of compromise — look for unusual process execution prior to the lateral movement
4. Reset credentials for all potentially compromised accounts
5. Review the full logon history of the targeted account in the 24h following the event for follow-on lateral movement

**False positives:**
- NTLM is legitimately used in many environments; PtH detection requires behavioral context from ITP, not just NTLM usage
- The ITP `IdentityConceptEvent` detections are high-fidelity and tuned to reduce false positives
- Authorized red team activity may generate these events — correlate with engagement windows

## References

- https://attack.mitre.org/techniques/T1550/002/
- https://www.crowdstrike.com/blog/pass-the-hash-detection/
- https://www.sans.org/reading-room/whitepapers/testing/pass-the-hash-attacks-tools-mitigation-33283
