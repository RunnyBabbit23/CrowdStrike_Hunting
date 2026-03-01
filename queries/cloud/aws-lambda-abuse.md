# AWS Lambda Abuse for Persistence and Execution

## Description

Detects abuse of AWS Lambda functions for attacker persistence, code execution, and data exfiltration. Attackers with appropriate IAM permissions can create new Lambda functions with malicious code, modify existing function code, attach higher-privilege execution roles, set up event triggers for automated execution, and use Lambda as a proxy for API calls that bypass IP-based controls. Lambda is particularly attractive because functions can run in any region, scale automatically, and blend in with legitimate serverless workloads.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Persistence / Execution |
| **Technique** | T1648 — Serverless Execution |
| **Sub-technique** | T1546 — Event Triggered Execution (Lambda triggers) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — New Lambda functions with elevated IAM roles, or modifications to existing functions by unexpected identities, indicate persistence or privilege escalation via serverless.

## Query

```logscale
// Lambda function created or code updated by non-standard identity
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(CreateFunction|UpdateFunctionCode|UpdateFunctionConfiguration)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Lambda function created with high-privilege execution role**

```logscale
// New Lambda with admin or high-privilege role — privilege escalation via serverless
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=CreateFunction
| RequestParameters=/(AdministratorAccess|PowerUserAccess|iam:.*\*|sts:AssumeRole)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Lambda triggers added (event-driven persistence)**

```logscale
// New event source mappings — attacker creating automated execution trigger
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(CreateEventSourceMapping|AddPermission|PutFunctionEventInvokeConfig)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Lambda function in unexpected region**

```logscale
// Lambda activity in regions not normally used by your organization
// Adjust exclusions to match your active Lambda regions
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(CreateFunction|UpdateFunctionCode|InvokeFunction)/i
| AWSRegion!=/us-east-1|us-east-2|us-west-2|eu-west-1/
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Lambda layer attach (code injection via shared layer)**

```logscale
// Lambda layer update — can be used to inject malicious code into multiple functions
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(PublishLayerVersion|UpdateFunctionConfiguration)/i
| RequestParameters=/layers/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Direct Lambda invocation from unexpected source**

```logscale
// Lambda invoked directly (not via trigger) from unexpected IP or identity
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=InvokeFunction
| UserIdentityType!=AWSService
| SourceIPAddress!=/\.amazonaws\.com|^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Review the function code: use `aws lambda get-function --function-name NAME` to retrieve the deployment package and inspect the code for malicious activity
2. Check the execution role ARN in `RequestParameters` — overly permissive roles attached to new functions are the primary risk
3. Look at the function's environment variables — these frequently contain hardcoded credentials or configuration secrets
4. Review the function's VPC configuration — Lambda in a VPC with access to private resources can pivot internally
5. Check for scheduled triggers (EventBridge rules) that would cause repeated execution

**False positives:**
- DevOps pipelines routinely create and update Lambda functions — filter by known CI/CD service account ARNs
- Infrastructure-as-code tools (SAM, CDK, Terraform) deploy Lambda functions during releases
- Tune by excluding known deployment role ARNs from your CI/CD system

## References

- https://attack.mitre.org/techniques/T1648/
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html
