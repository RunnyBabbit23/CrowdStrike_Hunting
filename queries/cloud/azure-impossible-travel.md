# Azure AD Impossible Travel and Anomalous Sign-In Detection

## Description

Detects impossible travel scenarios in Azure AD authentication — where the same user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible, indicating credential compromise or token theft. Also covers anomalous sign-in patterns including legacy protocol use (which bypasses MFA), sign-ins from anonymous proxy IPs, and first-time country logins. These patterns are surfaced via Falcon Identity Protection's Azure AD integration.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Initial Access / Credential Access |
| **Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Sub-technique** | T1110 — Brute Force (credential stuffing leading to valid sign-in) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Identity Protection (Falcon ITP) / Cloud CSPM |
| **Repository** | `base_identity_activity` or Azure-specific repository |
| **Event Types** | `AuthActivityAuditEvent`, `IdentityConceptEvent`, `CloudAuditEvent` |

## Severity

**High** — Confirmed impossible travel is a near-certain credential compromise indicator; treat as active account takeover.

## Query

```logscale
// CrowdStrike ITP impossible travel concept events
#event_simpleName=IdentityConceptEvent
| ConceptName=/(ImpossibleTravel|AnomalousSignIn|UnfamiliarLocation|AtypicalTravel)/i
| table([UserName, ComputerName, ConceptName, DetectDescription, SourceIPAddress, Severity, @timestamp], limit=200)
```

**Variant: Azure AD sign-in from known anonymous proxy or VPN exit nodes**

```logscale
// Sign-ins flagged as anonymous proxy or Tor network by Azure AD
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Sign-in|UserLoggedIn)/i
| RiskDetail=/(anonymizedIPAddress|unfamiliarFeatures|maliciousIPAddress|impossibleTravel)/i
| table([UserPrincipalName, OperationName, RiskDetail, CallerIPAddress, LocationCity, LocationCountry, @timestamp], limit=200)
```

**Variant: Legacy authentication protocol usage (bypasses MFA)**

```logscale
// Sign-ins via legacy protocols — SMTP AUTH, POP3, IMAP, legacy Exchange — MFA bypass
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Sign-in|UserLoggedIn)/i
| ClientAppUsed=/(
    Exchange ActiveSync|
    SMTP|
    POP3|
    IMAP4|
    Authenticated SMTP|
    Other clients|
    AutoDiscover|
    Exchange Online PowerShell|
    Exchange Web Services|
    MAPI Over HTTP|
    Offline Address Book
  )/i
| table([UserPrincipalName, ClientAppUsed, CallerIPAddress, LocationCountry, @timestamp], limit=200)
```

**Variant: First sign-in from a new country**

```logscale
// Users authenticating from a country they've never used before
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Sign-in|UserLoggedIn)/i
| RiskEventTypes=/unfamiliarFeatures|newCountry/i
| table([UserPrincipalName, CallerIPAddress, LocationCountry, LocationCity, RiskEventTypes, @timestamp], limit=200)
```

**Variant: Multiple failed logins followed by success (credential stuffing success)**

```logscale
// Account with recent failed authentications that then succeeds — stuffing or brute force win
#event_simpleName=AuthActivityAuditEvent
| CloudProvider=Azure
| EventType=/(FAILED_LOGIN|INVALID_CREDENTIAL)/i
| groupBy([SourceUserName], function=count(as=fail_count))
| fail_count > 5
| sort(fail_count, order=desc)
| table([SourceUserName, fail_count])
// Then separately run: find successful logins from the same usernames
```

**Variant: MFA fatigue / MFA push flood**

```logscale
// High volume of MFA authentication requests to a single user — MFA fatigue attack
#event_simpleName=AuthActivityAuditEvent
| EventType=/(MFA_REQUEST|PUSH_NOTIFICATION)/i
| groupBy([SourceUserName, bin(@timestamp, span=1h)], function=count(as=mfa_count))
| mfa_count > 10
| sort(mfa_count, order=desc)
| table([SourceUserName, mfa_count, _bucket])
```

## Response Notes

**Triage steps:**
1. For impossible travel: calculate the physical distance between the two authentication locations and compare to time elapsed — any velocity exceeding ~900 km/h is impossible
2. Contact the user through an out-of-band channel (phone, not email — email may be compromised) to confirm whether they recognize the activity
3. Immediately revoke all active sessions: Azure Portal → User → Authentication → Revoke Sessions
4. Reset the user's password and require MFA re-registration if compromise is confirmed
5. Review all actions taken in Azure, M365, and connected applications in the compromise window

**For legacy protocol detections:**
- Legacy protocols that bypass MFA are a significant risk even without impossible travel
- Block legacy authentication at the Conditional Access policy level: require Modern Authentication
- Common attack: attacker uses harvested credentials against OWA with basic auth

**False positives:**
- VPN usage can create apparent impossible travel when the VPN exit node is in a distant country — correlate with VPN login context
- Dual-SIM or roaming phones may authenticate from unexpected countries
- Split-tunneling VPN configurations may cause geographic inconsistency

## References

- https://attack.mitre.org/techniques/T1078/004/
- https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/concept-identity-protection-risks
- https://www.crowdstrike.com/blog/falcon-identity-threat-protection-azure-ad/
