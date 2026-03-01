# S3 / Cloud Storage Data Exfiltration

## Description

Detects suspicious data access and exfiltration from cloud object storage — including AWS S3, Azure Blob, and GCP Cloud Storage. Patterns include bulk object downloads by a single identity in a short window, public bucket exposure changes, cross-account data copies, and unusual GetObject calls from unfamiliar IPs or service accounts. Cloud storage exfiltration is a primary data theft vector in ransomware double-extortion and cloud-focused APT campaigns.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Exfiltration |
| **Technique** | T1530 — Data from Cloud Storage |
| **Sub-technique** | Bulk download, bucket policy modification |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Cloud CSPM / Falcon Cloud Security |
| **Repository** | `falcon_audit` or cloud-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Bulk cloud storage access from unusual identities or IPs, especially combined with ACL changes, is a critical data theft indicator.

## Query

```logscale
// AWS S3: High-volume GetObject calls from a single identity (bulk download)
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=GetObject
| groupBy([UserIdentityArn, SourceIPAddress, RequestParameters_bucketName], function=count(as=object_count))
| object_count > 100
| sort(object_count, order=desc)
| table([UserIdentityArn, SourceIPAddress, RequestParameters_bucketName, object_count])
```

**Variant: S3 bucket made public**

```logscale
// S3 bucket ACL or policy changed to allow public access — data exposure
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=/(PutBucketAcl|PutBucketPolicy|DeleteBucketPolicy)/i
| RequestParameters=/(AllUsers|AuthenticatedUsers|public-read|public-read-write)/i
| table([UserIdentityArn, EventName, RequestParameters, SourceIPAddress, AWSRegion, @timestamp], limit=200)
```

**Variant: S3 data copied to external account**

```logscale
// S3 copy to a different AWS account — potential exfiltration
#event_simpleName=CloudAuditEvent
| CloudProvider=AWS
| EventName=CopyObject
| RequestParameters_destinationBucket=*
| table([UserIdentityArn, RequestParameters, SourceIPAddress, @timestamp], limit=200)
```

**Variant: Azure Blob bulk download**

```logscale
// Azure Blob Storage: high-volume reads from a single identity
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/GetBlob|Read Blob/i
| groupBy([CallerObjectId, CallerIPAddress, ResourceGroup], function=count(as=blob_reads))
| blob_reads > 50
| sort(blob_reads, order=desc)
```

**Variant: Cloud storage accessed from unusual geographic location**

```logscale
// Access from unexpected country — combine with IP geolocation enrichment
#event_simpleName=CloudAuditEvent
| EventName=/(GetObject|GetBlob|storage\.objects\.get)/i
| SourceCountry!=/United States|US/
| groupBy([UserIdentityArn, SourceIPAddress, SourceCountry], function=count(as=access_count))
| sort(access_count, order=desc)
```

## Response Notes

**Triage steps:**
1. Identify the accessing identity and confirm whether this access pattern is expected for their role
2. Check `SourceIPAddress` — access from Tor exit nodes, VPS ranges, or unexpected countries is high priority
3. For public ACL changes: immediately revert the policy and assess what data was exposed and for how long
4. Determine the volume of data accessed using CloudTrail S3 data event logs (requires enabling data events)
5. Check if the identity's credentials were recently created or if they differ from the user's usual access patterns

**False positives:**
- Analytics jobs and ETL pipelines perform bulk S3 reads — filter by known service account ARNs
- Backup processes regularly read large volumes of objects — baseline by service account and bucket
- Enable S3 server access logging for higher-fidelity detection

## References

- https://attack.mitre.org/techniques/T1530/
- https://www.crowdstrike.com/blog/cloud-data-exfiltration-detection/
- https://rhinosecuritylabs.com/aws/s3-bucket-misconfiguration-from-creation-to-iam/
