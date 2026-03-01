# Azure Key Vault Secret and Key Access Anomalies

## Description

Detects unusual access patterns to Azure Key Vault — the primary secrets, certificate, and cryptographic key store in Azure environments. Attackers with sufficient permissions enumerate Key Vault contents and bulk-retrieve secrets to harvest credentials for lateral movement. Key patterns include bulk secret retrieval by a single identity, access from unexpected IP addresses or service principals, key vault access policy modifications, and soft-delete purge operations (evidence destruction).

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
| **Repository** | `falcon_audit` or Azure-specific repository |
| **Event Types** | `CloudAuditEvent` |

## Severity

**High** — Bulk Key Vault secret retrieval outside normal application patterns is a critical credential harvesting indicator.

## Query

```logscale
// Bulk Key Vault secret retrieval — mass credential harvesting
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(SecretGet|KeyVaultSecretGet|GetSecret)/i
| groupBy([CallerObjectId, CallerIPAddress, ResourceGroup], function=count(as=secret_reads))
| secret_reads > 10
| sort(secret_reads, order=desc)
| table([CallerObjectId, CallerIPAddress, ResourceGroup, secret_reads])
```

**Variant: Key Vault access from unexpected identity or IP**

```logscale
// All Key Vault secret/key/certificate access — baseline and anomaly identification
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(SecretGet|KeyGet|CertificateGet|SecretList|KeyList|CertificateList)/i
| table([CallerObjectId, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=500)
```

**Variant: Key Vault access policy modified (permissions expansion)**

```logscale
// Access policy changes — granting new identities access to secrets, keys, or certificates
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(VaultPut|SetAccessPolicy|UpdateAccessPolicy|VaultAccessPolicyWrite)/i
| table([InitiatedByUserPrincipalName, OperationName, TargetResources, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Key Vault soft-delete purge (evidence/secrets destruction)**

```logscale
// Soft-deleted secret/key/certificate purged — permanent destruction, cannot be recovered
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(SecretPurge|KeyPurge|CertificatePurge|VaultPurge)/i
| table([CallerObjectId, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Certificate export (private key exfiltration)**

```logscale
// Certificate backup/export — private key material exfiltration
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(CertificateBackup|KeyBackup|SecretBackup)/i
| table([CallerObjectId, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

**Variant: Key Vault diagnostic logging disabled**

```logscale
// Diagnostic settings removed from Key Vault — disables audit logging for the vault
#event_simpleName=CloudAuditEvent
| CloudProvider=Azure
| OperationName=/(microsoft.insights\/diagnosticSettings\/delete|DiagnosticSettingsDelete)/i
| ResourceId=/vaults/i
| table([InitiatedByUserPrincipalName, OperationName, ResourceId, CallerIPAddress, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Identify the specific secrets/keys accessed by reviewing `ResourceId` — prioritize database connection strings, application secrets, and TLS private keys
2. Determine if the accessing identity (`CallerObjectId`) is the expected application service principal or an unexpected human identity
3. For bulk access: review the time window — application startup sequences access multiple secrets once; repeated bulk access throughout the day suggests manual harvesting
4. Rotate all accessed secrets and re-issue any certificates immediately if unauthorized access is confirmed
5. Check whether the Key Vault has soft-delete and purge protection enabled — if not, deleted secrets cannot be recovered

**False positives:**
- Applications access their own secrets at startup and may access multiple secrets — filter by known application service principal object IDs
- Deployment pipelines retrieve secrets during releases — filter by CI/CD service account
- Key rotation automation may appear as bulk access — validate against rotation schedule

## References

- https://attack.mitre.org/techniques/T1555/
- https://docs.microsoft.com/en-us/azure/key-vault/general/logging
- https://www.crowdstrike.com/blog/azure-key-vault-security/
