# AWS Secrets Manager and SSM Parameter Store Credential Access

## Description

Detects bulk or unusual access to AWS Secrets Manager and SSM Parameter Store — the primary repositories for application secrets, database credentials, API keys, and encryption keys in AWS environments. Attackers with IAM permissions will enumerate and bulk-retrieve secrets to harvest credentials for lateral movement within the cloud environment and connected systems. Key patterns include bulk `GetSecretValue` calls, cross-account secret access, and secrets accessed by identities that don't normally access them.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1555 — Credentials from Password Stores |
| **Sub-technique** | T1552.004 — Unsecured Credentials: Private Keys |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Bulk secret retrieval by a single identity is a strong lateral movement and credential harvesting indicator; immediate response warranted.

## Query

```logscale
// Bulk GetSecretValue calls — mass credential harvesting from Secrets Manager
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=GetSecretValue
| groupBy([UserIdentityArn, SourceIPAddress], function=count(as=secret_reads))
| secret_reads > 5
| sort(secret_reads, order=desc)
| table([UserIdentityArn, SourceIPAddress, secret_reads])
```

**Variant: All Secrets Manager access for baselining and anomaly detection**

```logscale
// All Secrets Manager retrieval events — baseline and identify access patterns
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(GetSecretValue|DescribeSecret|ListSecrets|ListSecretVersionIds)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=500)
```

**Variant: SSM Parameter Store bulk retrieval**

```logscale
// Bulk SSM GetParameter/GetParameters calls — credential harvesting from Parameter Store
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(GetParameter|GetParameters|GetParametersByPath|DescribeParameters)/i
| groupBy([UserIdentityArn, SourceIPAddress], function=count(as=param_reads))
| param_reads > 20
| sort(param_reads, order=desc)
| table([UserIdentityArn, SourceIPAddress, param_reads])
```

**Variant: Secrets accessed from unusual identity (access outside normal service accounts)**

```logscale
// GetSecretValue called by identity that isn't the expected application service account
// Customize the exclusion list with your known application IAM roles
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=GetSecretValue
| UserIdentityArn!=/app-role|service-account|lambda-role|ecs-task-role/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, @timestamp], limit=200)
```

**Variant: Secret deletion or modification (destruction or replacement)**

```logscale
// Secrets deleted or modified — covering tracks or disrupting operations
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(DeleteSecret|PutSecretValue|UpdateSecret|RotateSecret|CancelRotateSecret|RestoreSecret)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: KMS key access for secret decryption (high-privilege)**

```logscale
// KMS Decrypt calls — may indicate decryption of encrypted secrets or data
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(Decrypt|GenerateDataKey|GenerateDataKeyWithoutPlaintext)/i
| groupBy([UserIdentityArn, SourceIPAddress], function=count(as=decrypt_count))
| decrypt_count > 10
| sort(decrypt_count, order=desc)
| table([UserIdentityArn, SourceIPAddress, decrypt_count])
```

## Response Notes

**Triage steps:**
1. Identify the exact secrets accessed from the `RequestParameters` field — database credentials, API keys, and TLS private keys are highest priority
2. Check the timeline — was access part of an application deployment (expected) or a manual interactive session (suspicious)?
3. For bulk access: determine whether the calling identity's normal usage pattern includes this many secret reads — baseline using the all-access variant
4. Rotate all accessed secrets immediately if unauthorized access is confirmed
5. Check downstream services using the compromised secrets — attackers may have already used harvested credentials to access databases or external APIs

**False positives:**
- Application startup sequences may retrieve multiple secrets at once — baseline per application role ARN
- Security tooling (Vault sync, secret rotation automation) performs bulk operations
- DevOps pipelines access secrets during deployment — filter by known CI/CD service account ARNs
- Tune `secret_reads > 5` threshold based on your environment's normal usage patterns

## References

- https://attack.mitre.org/techniques/T1555/
- https://rhinosecuritylabs.com/aws/attacking-aws-secrets-manager/
- https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring.html
