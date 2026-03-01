# AWS CloudTrail Tampering and Audit Log Manipulation

## Description

Detects attempts to disable, modify, or delete AWS CloudTrail logging — the primary audit mechanism for AWS API activity. Attackers who gain privileged AWS access frequently disable CloudTrail to operate without generating audit records. Techniques include stopping trails, deleting trails, disabling log file validation, and disabling S3 server access logging on the CloudTrail bucket. This is a critical signal indicating an attacker with IAM write permissions is attempting to operate blind.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion |
| **Technique** | T1562.008 — Impair Defenses: Disable or Modify Cloud Logs |
| **Sub-technique** | CloudTrail disable, S3 logging disable, GuardDuty disable |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — CloudTrail tampering is a near-certain indicator of a malicious actor with elevated AWS access attempting to evade detection.

## Query

```logscale
// CloudTrail stopped, deleted, or modified
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(
    StopLogging|
    DeleteTrail|
    UpdateTrail|
    PutEventSelectors|
    RemoveTags|
    DeleteEventDataStore
  )/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: GuardDuty disabled or findings suppressed**

```logscale
// GuardDuty detector disabled — removes threat detection capability
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(
    DeleteDetector|
    DisassociateMembers|
    StopMonitoringMembers|
    UpdateFilter|
    CreateFilter|
    ArchiveFindingsItem|
    DeleteMembers
  )/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: CloudWatch alarm and event rule deletion (detection suppression)**

```logscale
// CloudWatch rules and alarms deleted — removes monitoring and alerting
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(
    DeleteAlarms|
    DisableAlarmActions|
    DeleteRule|
    RemoveTargets|
    DeleteInsightRules|
    PutMetricAlarm.*Threshold.*0
  )/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: S3 bucket logging disabled on CloudTrail bucket**

```logscale
// S3 server access logging disabled — removes secondary audit trail
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(PutBucketLogging|DeleteBucketPolicy)/i
| RequestParameters=/cloudtrail|logs|audit/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, @timestamp], limit=200)
```

**Variant: Config recorder stopped (AWS Config)**

```logscale
// AWS Config recorder stopped — disables resource configuration tracking
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(StopConfigurationRecorder|DeleteConfigurationRecorder|DeleteDeliveryChannel)/i
| table([UserIdentityArn, EventName, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Multi-region CloudTrail tampering (coverage gap creation)**

```logscale
// Disabling multi-region trails — creating geographic coverage gaps
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=UpdateTrail
| RequestParameters=/IsMultiRegionTrail.*false|IncludeGlobalServiceEvents.*false/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the identity that stopped/deleted CloudTrail — check if this is a known admin IAM user, role, or a compromised service account
2. Check the source IP — unexpected geographic origin or anonymous hosting ranges (VPS, Tor) are high priority
3. Review all activity from the same identity in the 30 minutes before the CloudTrail tampering — what was the attacker doing before trying to disable logging?
4. Immediately re-enable CloudTrail and verify log file integrity using log file validation
5. Check if the CloudTrail S3 bucket contents were modified or deleted during the gap window

**Note on detection persistence:**
- CrowdStrike's cloud sensor does not rely on CloudTrail for detection — Falcon captures cloud API events via its own collection path, so this detection remains effective even after CloudTrail is disabled

**False positives:**
- Terraform/CloudFormation state changes may temporarily modify trail configurations during infrastructure updates
- Cloud security team audits may test trail modification detection — validate against change management
- Very low false positive rate for `StopLogging` and `DeleteTrail` in production environments

## References

- https://attack.mitre.org/techniques/T1562/008/
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- https://rhinosecuritylabs.com/aws/aws-cloudtrail-bypasses/
