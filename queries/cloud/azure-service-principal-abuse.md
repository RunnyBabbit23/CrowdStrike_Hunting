# Azure Service Principal and App Registration Abuse

## Description

Detects abuse of Azure service principals and app registrations — a key persistence and privilege escalation technique in Azure environments. Attackers add credentials (certificates, secrets) to existing service principals to maintain persistent access, create new high-privilege app registrations, and grant themselves OAuth consent to applications with broad permissions. These techniques are favored because service principal credentials are long-lived, don't require MFA, and often have elevated permissions.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence / Privilege Escalation |
| **Technique** | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| **Sub-technique** | T1550.001 — Use Alternate Authentication Material: Application Access Token |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or Azure-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Adding credentials to service principals or creating high-privilege app registrations by non-standard identities is a critical persistence indicator.

## Query

```logscale
// New credential (secret or certificate) added to existing service principal
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add service principal credentials|Update application|Add application|AddKey|UpdateKey)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: New app registration created with high-privilege API permissions**

```logscale
// New Azure AD application with broad Microsoft Graph or other high-privilege permissions
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add application|Consent to application|Update application - Certificates and secrets)/i
| TargetResources=/(
    Directory\.ReadWrite\.All|
    Mail\.ReadWrite\.All|
    Mail\.Send|
    User\.ReadWrite\.All|
    Group\.ReadWrite\.All|
    RoleManagement\.ReadWrite\.Directory|
    Application\.ReadWrite\.All|
    Files\.ReadWrite\.All|
    full_access_as_app
  )/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Admin consent granted to application (OAuth abuse)**

```logscale
// Admin consent to OAuth application — grants broad permissions to service principal
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Consent to application|Add OAuth2PermissionGrant|Update OAuth2PermissionGrant)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Service principal added to privileged role**

```logscale
// Service principal added to Global Admin, Privileged Role Admin, or Owner
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add member to role|Add eligible member to role)/i
| TargetResources=/(Global Administrator|Privileged Role Administrator|Security Administrator|Application Administrator)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Service principal credential expiry extended (persistence maintenance)**

```logscale
// Long-lived or expiry-extended credentials added to service principals
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add service principal credentials|Update application - Certificates and secrets)/i
// Long expiry credentials often have no EndDate or very far future date
| TargetResources=/(endDate.*2030|endDate.*2035|endDate.*2040|noExpiry)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Federated identity credential added (token impersonation)**

```logscale
// Federated identity credentials added — allows external identity provider tokens to impersonate SP
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add federated identity credential|Update federated identity credential)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the application or service principal that received new credentials — is it a known production application or an unknown/unfamiliar app?
2. Check the identity that made the change (`InitiatedByUserPrincipalName`) — is this a known Azure admin? Run impossible travel detection on the same identity
3. Review the permissions granted — `Directory.ReadWrite.All` and `Mail.ReadWrite.All` are particularly dangerous
4. Revoke the credential immediately if unauthorized: Azure Portal → App registrations → [App] → Certificates & secrets → delete
5. Audit all actions taken using the service principal credentials in the compromise window via Azure AD sign-in logs filtered to the application ID

**False positives:**
- DevOps pipelines routinely create and rotate service principal credentials for deployment automation
- Application teams create app registrations for new service integrations — validate with application owners
- Certificate rotation scripts may trigger `UpdateKey` events — filter by known automation service accounts

## References

- https://attack.mitre.org/techniques/T1098/001/
- https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
- https://www.crowdstrike.com/blog/azure-active-directory-hunting/
