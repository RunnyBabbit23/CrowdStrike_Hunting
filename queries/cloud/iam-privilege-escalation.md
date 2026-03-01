# Cloud IAM Privilege Escalation

## Description

Detects suspicious IAM modifications in cloud environments (AWS, Azure, GCP) ingested via Falcon Cloud Security / CSPM — including adding users to privileged groups, creating new admin accounts, attaching high-privilege policies directly to users, and modifying role trust relationships. IAM privilege escalation is a critical step in cloud-focused intrusions, enabling long-term persistence and data access.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Privilege Escalation / Persistence |
| **Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Sub-technique** | T1098 — Account Manipulation |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — IAM changes by non-standard users or service accounts outside change windows are a critical escalation indicator.

## Query

```logscale
// AWS: High-privilege IAM actions (policy attach, admin group membership, root usage)
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(
    AttachUserPolicy|
    AttachRolePolicy|
    AttachGroupPolicy|
    AddUserToGroup|
    CreateAccessKey|
    CreateLoginProfile|
    UpdateAssumeRolePolicy|
    PutUserPolicy|
    PutRolePolicy|
    CreatePolicyVersion|
    SetDefaultPolicyVersion
  )/i
| RequestParameters=/(AdministratorAccess|PowerUserAccess|arn:aws:iam::aws:policy\/Administrator)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: AWS root account usage**

```logscale
// Root account activity — should never be used in production
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| UserIdentityType=Root
| table([UserIdentityArn, EventName, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Azure: Add member to privileged role**

```logscale
// Azure: Adding users to Global Admin, Privileged Role Admin, or Owner
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Add member to role|Add eligible member to role)/i
| TargetResources=/(Global Administrator|Privileged Role Administrator|Owner|Contributor)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: New cloud access key creation (persistence)**

```logscale
// New IAM access key created — persistence or credential theft indicator
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=CreateAccessKey
| table([UserIdentityArn, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the calling identity (`UserIdentityArn`, `InitiatedByUserPrincipalName`) — is this an authorized admin?
2. Check `SourceIPAddress` — unexpected geographic location or IP reputation flags are high priority
3. Verify if the change was authorized through your change management process
4. For new access keys: immediately rotate or deactivate the key if not recognized, then investigate the calling identity
5. Review CloudTrail / Azure AD audit logs for additional activity from the same identity in the preceding 24h

**False positives:**
- Infrastructure-as-code tools (Terraform, CloudFormation, Pulumi) make IAM changes during deployments
- Onboarding automation scripts may attach policies to new accounts
- Filter known CI/CD service account ARNs/SPNs after baselining your environment

## References

- https://attack.mitre.org/techniques/T1078/004/
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://www.crowdstrike.com/blog/cloud-security-posture-management/
