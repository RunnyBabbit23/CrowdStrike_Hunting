# AWS Instance Metadata Service (IMDS) Abuse and Credential Theft

## Description

Detects abuse of the AWS Instance Metadata Service (IMDSv1) — a well-known attack vector where attackers exploit SSRF vulnerabilities or direct access to steal EC2 instance role credentials from `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. Stolen credentials are then used outside AWS to perform actions as the EC2 instance's IAM role. IMDSv1 is particularly dangerous because it requires no authentication; IMDSv2 mitigates this with session tokens but many organizations still run IMDSv1 instances.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Credential Access |
| **Technique** | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API |
| **Sub-technique** | SSRF to IMDS, direct IMDS access, credential theft from metadata |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — API calls from EC2 instance role credentials originating from outside AWS, or from unexpected IP ranges, indicate stolen IMDS credentials in use.

## Query

```logscale
// EC2 instance role credentials used from outside expected EC2 IP ranges
// Stolen IMDS credentials used externally — key indicator
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| UserIdentityType=AssumedRole
| UserIdentityArn=/i-[0-9a-f]{8,17}/i
// Instance credentials used from non-AWS IP space
| SourceIPAddress!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|\.amazonaws\.com)/
| table([UserIdentityArn, EventName, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: GetCallerIdentity from unusual source (reconnaissance after credential theft)**

```logscale
// sts:GetCallerIdentity called — attacker confirming stolen credentials work
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=GetCallerIdentity
| SourceIPAddress!=/\.amazonaws\.com|^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| table([UserIdentityArn, UserIdentityType, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Enumeration API calls suggesting credential testing**

```logscale
// Broad enumeration calls following credential acquisition — attacker mapping access
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(
    ListBuckets|
    ListRoles|
    ListUsers|
    ListPolicies|
    ListFunctions|
    DescribeInstances|
    DescribeSecurityGroups|
    GetAccountAuthorizationDetails|
    ListAttachedRolePolicies
  )/i
| groupBy([UserIdentityArn, SourceIPAddress], function=count(as=enum_count))
| enum_count > 5
| sort(enum_count, order=desc)
| table([UserIdentityArn, SourceIPAddress, enum_count])
```

**Variant: IMDSv1 token-less access detected via CSPM policy**

```logscale
// CSPM policy finding for IMDSv1 enabled instances
#event_simpleName=PolicyDetectionSummary
| PolicyName=/(imds|metadata.*v1|instance.*metadata.*hop)/i
| table([ResourceId, PolicyName, Severity, CloudProvider, AWSRegion, @timestamp], limit=200)
```

**Variant: Unusual AWS region usage (stolen creds used in unexpected region)**

```logscale
// Activity in regions not normally used by this organization
// Adjust the exclusion list to match your active AWS regions
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| AWSRegion!=/us-east-1|us-east-2|us-west-2|eu-west-1/
| EventName!=/DescribeRegions|ListRegions/i
| groupBy([UserIdentityArn, AWSRegion, EventName], function=count(as=action_count))
| sort(action_count, order=desc)
| table([UserIdentityArn, AWSRegion, EventName, action_count])
```

## Response Notes

**Triage steps:**
1. For stolen credential use: identify the source IP — check geolocation and ASN (cloud hosting ranges, residential ISPs, VPNs all have different implications)
2. Immediately revoke the instance profile or rotate credentials if external use is confirmed — update the IAM role's trust policy or detach it from the instance
3. Check which actions were taken with the stolen credentials — review the full activity timeline in the 24h after credential theft
4. Identify the SSRF vulnerability (if applicable) — review web application logs for requests to 169.254.169.254
5. Enforce IMDSv2 on all EC2 instances to prevent further credential theft via IMDS

**Remediation:**
- Enforce IMDSv2: `aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-endpoint enabled --http-token required`
- Apply IMDSv2 enforcement as default at the account level via Service Control Policy

**False positives:**
- Lambda functions using execution role credentials may appear as AssumedRole from AWS-owned IPs — these are expected
- Cross-region replication and DR processes may use instance roles in non-primary regions
- Verify the source IP carefully before acting — some legitimate AWS services use external IP ranges

## References

- https://attack.mitre.org/techniques/T1552/005/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed
