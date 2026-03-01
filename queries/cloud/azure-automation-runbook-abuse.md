# Azure Automation Account and Runbook Abuse

## Description

Detects abuse of Azure Automation Accounts and Runbooks for persistent code execution and privilege escalation. Azure Automation provides a managed environment for running PowerShell and Python scripts with an attached managed identity, often with Contributor or Owner permissions on subscriptions. Attackers who can create or modify runbooks can execute arbitrary code in Azure's infrastructure with the automation account's identity, access credentials stored as Automation variables/assets, and establish persistent scheduled execution via webhooks or scheduled jobs.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence / Privilege Escalation / Execution |
| **Technique** | T1648 — Serverless Execution |
| **Sub-technique** | T1053.007 — Scheduled Task/Job: Container Orchestration Job |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or Azure-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — New or modified runbooks attached to a managed identity with subscription-level permissions represent a critical persistent execution and privilege escalation risk.

## Query

```logscale
// Runbook created or modified — potential code execution persistence
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Create or update an Azure Automation runbook|microsoft\.automation\/automationAccounts\/runbooks\/write)/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Runbook job started manually (interactive execution)**

```logscale
// Runbook job started manually — not via schedule, possible interactive execution by attacker
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(Start an Azure Automation runbook job|microsoft\.automation\/automationAccounts\/jobs\/write)/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Automation variable or credential asset modified**

```logscale
// Automation account variables/credentials modified — may contain secrets accessible to runbooks
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(automation.*variable.*write|automation.*credential.*write|Create or update an Azure Automation variable)/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Webhook created for runbook (trigger-based persistence)**

```logscale
// Webhook created on automation runbook — enables external trigger for persistent execution
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(automation.*webhook.*write|Create or update an Azure Automation webhook)/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Managed identity assigned to automation account (high-privilege execution context)**

```logscale
// Managed identity assignment to automation account — defines execution privilege level
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(microsoft\.automation\/automationAccounts\/write|Update automation account)/i
| TargetResources=/(identity|managedIdentity|SystemAssigned|UserAssigned)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Schedule created for runbook (persistent recurring execution)**

```logscale
// Automation schedule created or linked to runbook — establishes recurring execution
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(automation.*schedule.*write|automation.*jobSchedule.*write)/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Review the runbook code: Azure Portal → Automation Accounts → [Account] → Runbooks → [Runbook] → View to inspect what the script does
2. Check the automation account's managed identity permissions — `az role assignment list --assignee [managed-identity-object-id]` to see what it can access
3. Look for automation variables containing credentials or connection strings — these are accessible to all runbooks in the account
4. Identify the schedule or trigger mechanism — webhooks create an unauthenticated HTTP endpoint for runbook invocation
5. Disable or quarantine the runbook immediately if unauthorized; revoke the managed identity's role assignments

**False positives:**
- DevOps teams routinely create and update runbooks for infrastructure automation — validate with the DevOps/platform team
- IT operations teams use automation accounts for scheduled maintenance tasks
- Infrastructure-as-code pipelines may create automation resources — filter by known deployment service principals

## References

- https://attack.mitre.org/techniques/T1648/
- https://www.netspi.com/blog/technical/cloud-penetration-testing/abusing-azure-automation-account-managed-identities/
- https://docs.microsoft.com/en-us/azure/automation/automation-security-overview
