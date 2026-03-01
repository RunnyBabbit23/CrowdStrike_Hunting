# AWS Security Group and Network ACL Modifications

## Description

Detects modifications to AWS security groups and network ACLs that open access to sensitive resources — a technique used by attackers to create persistent backdoor network access, expose internal services to the internet, or enable exfiltration paths. Critical patterns include rules allowing ingress from `0.0.0.0/0` on administrative ports (22, 3389, 445, 1433, 3306), removal of egress restrictions, and modifications to security groups protecting sensitive infrastructure (databases, secrets, management planes).

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Persistence |
| **Technique** | T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall |
| **Sub-technique** | Security group rule modification, network ACL bypass |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Security group rules allowing 0.0.0.0/0 inbound on administrative or database ports expose resources to the entire internet and should be treated as critical.

## Query

```logscale
// Security group ingress rule allowing traffic from any IP (0.0.0.0/0 or ::/0)
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(AuthorizeSecurityGroupIngress|CreateSecurityGroup)/i
| RequestParameters=/(0\.0\.0\.0\/0|:\/0|cidrIp.*0\.0\.0\.0)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Open access on administrative or sensitive ports**

```logscale
// Ingress rules on high-risk ports opened to broad IP ranges
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=AuthorizeSecurityGroupIngress
| RequestParameters=/(
    :22\b|toPort.*22\b|fromPort.*22\b|
    :3389\b|toPort.*3389|fromPort.*3389|
    :445\b|toPort.*445|
    :1433\b|toPort.*1433|
    :3306\b|toPort.*3306|
    :5432\b|toPort.*5432|
    :6379\b|toPort.*6379|
    :27017\b|toPort.*27017|
    :9200\b|toPort.*9200|
    :8080\b|toPort.*8080
  )/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: All ports opened (allow all traffic)**

```logscale
// Security group rule allowing all ports (fromPort=0, toPort=65535 or protocol=-1)
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=AuthorizeSecurityGroupIngress
| RequestParameters=/(fromPort.*-1|toPort.*65535|ipProtocol.*-1)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Network ACL changes**

```logscale
// Network ACL modification — broader scope than security groups, affects entire subnet
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(CreateNetworkAclEntry|ReplaceNetworkAclEntry|DeleteNetworkAclEntry)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: VPC peering or endpoint creation (new network path)**

```logscale
// New VPC peering connections or PrivateLink endpoints — new network access paths
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(CreateVpcPeeringConnection|AcceptVpcPeeringConnection|CreateVpcEndpoint)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: Security group changes outside change window**

```logscale
// Security group modifications during off-hours — change management bypass indicator
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(AuthorizeSecurityGroupIngress|AuthorizeSecurityGroupEgress|CreateSecurityGroup)/i
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| (hour < "07" OR hour >= "19")
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, hour, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the security group modified and which resources are protected by it — database SGs, management plane SGs, and bastion host SGs are highest priority
2. Check the port and source CIDR — `0.0.0.0/0` on port 22 or 3389 is an immediate critical finding regardless of other context
3. Verify whether this was an authorized change through your change management system
4. Check the identity that made the change — human IAM user vs. service account vs. CI/CD role
5. If unauthorized: revoke the rule immediately with `aws ec2 revoke-security-group-ingress` and investigate how the identity obtained the permissions to make this change

**False positives:**
- Temporary access for debugging is common — developers open SG rules and forget to close them; use time-based detection to catch these
- Infrastructure-as-code deployments (Terraform, CDK) create security group rules — filter by known IaC service accounts
- Some CI/CD pipelines temporarily open rules for deployment testing

## References

- https://attack.mitre.org/techniques/T1562/007/
- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
- https://www.crowdstrike.com/blog/aws-security-misconfiguration-hunting/
