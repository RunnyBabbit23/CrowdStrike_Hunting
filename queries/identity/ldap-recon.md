# LDAP Reconnaissance and AD Enumeration

## Description

Detects LDAP-based Active Directory enumeration — a standard attacker technique used to map domain users, groups, computers, GPOs, ACLs, and trust relationships after gaining initial access. Tools like BloodHound/SharpHound, PowerView, ADRecon, and Impacket's `GetADUsers.py` generate distinctive LDAP query patterns that differ from normal user and workstation behavior. CrowdStrike Identity Threat Protection monitors LDAP traffic at the domain controller level.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Discovery |
| **Technique** | T1087.002 — Account Discovery: Domain Account |
| **Sub-technique** | T1482 — Domain Trust Discovery, T1069.002 — Domain Groups |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Identity Protection (Falcon ITP) |
| **Repository** | `base_identity_activity` |
| **Event Types** | `DirectoryServiceEventV2`, `AuthActivityAuditEvent` |

## Severity

**Medium** — LDAP enumeration alone is suspicious; combine with lateral movement or Kerberoasting for High severity.

## Query

```logscale
// BloodHound/SharpHound LDAP enumeration patterns — distinctive query filters
#event_simpleName=DirectoryServiceEventV2
| LDAPFilter=/(
    \(objectClass=trustedDomain\)|
    \(objectCategory=groupPolicyContainer\)|
    \(objectClass=computer\)|
    \(samAccountType=805306368\)|
    \(objectCategory=person\)\(objectClass=user\)|
    msds-allowedtodelegateto|
    \(objectClass=organizationalUnit\)|
    adminCount=1|
    memberOf=.*CN=Domain Admins
  )/i
| table([ComputerName, UserName, LDAPFilter, TargetDomainName, @timestamp], limit=200)
```

**Variant: High-volume LDAP queries from a non-DC workstation**

```logscale
// Bulk LDAP enumeration from workstations (not domain controllers or management servers)
#event_simpleName=DirectoryServiceEventV2
| ComputerName!=/dc|domaincontroller|ad\d|pdc/i
| groupBy([ComputerName, UserName], function=count(as=ldap_count))
| ldap_count > 200
| sort(ldap_count, order=desc)
| table([ComputerName, UserName, ldap_count])
```

**Variant: PowerView-style cmdlets in PowerShell (source-side detection)**

```logscale
// PowerView or similar AD enumeration via PowerShell on endpoint
#event_simpleName=ProcessRollup2
| FileName=/powershell(\.exe)?/i
| CommandLine=/(
    Get-DomainUser|Get-DomainGroup|Get-DomainComputer|Get-DomainController|
    Get-DomainTrust|Get-DomainGPO|Get-DomainOU|Get-DomainACL|
    Find-DomainUserLocation|Find-LocalAdminAccess|
    Invoke-ACLScanner|Get-ObjectAcl|
    Get-NetUser|Get-NetGroup|Get-NetComputer|Get-NetDomain|
    Invoke-BloodHound|SharpHound
  )/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the source workstation and user — is this from an authorized admin, security team, or an unexpected endpoint?
2. Correlate LDAP enumeration timing with other suspicious events (Kerberoasting, lateral movement, new logons)
3. Look for BloodHound output files (`BloodHound.zip`, `*.json` collections) written to disk via `FileWritten` events
4. Alert: if LDAP enumeration is followed by targeted movement to Domain Admin accounts or privileged resources
5. Review whether this correlates with an authorized red team engagement

**False positives:**
- IAM/AD management tools (Azure AD Connect, Quest, SolarWinds SAM) perform frequent LDAP queries
- Vulnerability scanners may enumerate AD as part of their scan
- Authorized security assessments — correlate with change management windows
- Baseline your environment's normal LDAP query volume before setting thresholds

## References

- https://attack.mitre.org/techniques/T1087/002/
- https://www.crowdstrike.com/blog/protecting-active-directory-from-bloodhound-attacks/
- https://github.com/BloodHoundAD/BloodHound
