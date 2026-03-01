# Azure Conditional Access Policy Modification

## Description

Detects modifications to Azure Conditional Access (CA) policies — security controls that enforce MFA, device compliance, approved app requirements, and location-based access restrictions. Attackers who gain Global Administrator or Security Administrator access may modify or disable Conditional Access policies to remove MFA requirements, create exclusions for their compromised accounts, or add trusted locations that allow access from attacker-controlled IPs. CA policy tampering is a high-value target because it enables persistent authentication without MFA.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Persistence |
| **Technique** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Sub-technique** | T1556.006 — Modify Authentication Process: Multi-Factor Authentication |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or Azure-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Disabling MFA enforcement or adding attacker-controlled IPs to trusted locations enables persistent authentication bypass; treat as critical.

## Query

```logscale
// Conditional Access policy created, modified, or deleted
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(
    Add conditional access policy|
    Update conditional access policy|
    Delete conditional access policy|
    microsoft\.aad\.b2c\/policies|
    ConditionalAccess\/policies
  )/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: CA policy disabled**

```logscale
// Conditional Access policy set to disabled state — MFA requirement removed
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Update conditional access policy)/i
| TargetResources=/(state.*disabled|disabled.*state)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Named location added (attacker IP added to trusted list)**

```logscale
// New named location created — could be used to whitelist attacker-controlled IP ranges
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add named location|Update named location)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: MFA registration policy modified**

```logscale
// Azure AD MFA registration policy disabled or relaxed
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Update MFA|Update authentication method|Update per-user MFA)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Security defaults disabled**

```logscale
// Azure AD security defaults turned off — disables baseline MFA enforcement
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Update company settings|Update onPremisesPublishingProfiles)/i
| TargetResources=/(securityDefaults.*false|isEnabled.*false)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Break-glass/exclusion account added to CA policy exclusions**

```logscale
// Users added to CA policy exclusion lists — bypassing policy for specific accounts
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Update conditional access policy)/i
| TargetResources=/(excludeUsers|excludeGroups)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Review the specific policy modified — was it the primary MFA enforcement policy, a location-based policy, or a device compliance policy?
2. Compare the before/after state from the `TargetResources` field — what specifically changed (disabled, exclusions added, trusted location added)?
3. Verify the identity that made the change — known security admin vs. unexpected account
4. Check for concurrent sign-in activity from the same account using CA policy exclusions or new trusted locations
5. Revert the policy change immediately if unauthorized and review whether any authentication bypass occurred during the window the policy was modified

**False positives:**
- Security and IT teams regularly modify CA policies for legitimate operational reasons — validate against change management
- Emergency access (break-glass) accounts may be added to policy exclusions intentionally
- Policy testing and piloting may involve temporarily relaxing policies — tag testing changes in your change management system

## References

- https://attack.mitre.org/techniques/T1562/001/
- https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview
- https://www.crowdstrike.com/blog/azure-conditional-access-hunting/
- https://posts.specterops.io/hiding-in-plain-sight-using-azure-conditional-access-policies-for-evasion-9c1b55a59b7e
