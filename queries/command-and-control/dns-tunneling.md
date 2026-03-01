# DNS Tunneling and C2 over DNS

## Description

Detects DNS-based command and control — a technique where attackers encode data in DNS queries and responses to exfiltrate data or receive commands while bypassing traditional network controls that allow DNS traffic. Indicators include high-frequency queries to a single domain, unusually long subdomain labels, queries for uncommon record types (TXT, NULL, MX used for data encoding), and newly registered or low-reputation domains. Tools like `iodine`, `dnscat2`, and custom C2 frameworks use this technique.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Command and Control / Exfiltration |
| **Technique** | T1071.004 — Application Layer Protocol: DNS |
| **Sub-technique** | DNS tunneling / DNS over HTTPS (DoH) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `DnsRequest` |

## Severity

**Medium** — High-volume DNS queries to a single domain require additional context (domain reputation, query length) before escalating, but repeated patterns are high confidence.

## Query

```logscale
// High-frequency DNS queries to the same domain from a single host (C2 beaconing pattern)
#event_simpleName=DnsRequest
| groupBy([aid, ComputerName, DomainName], function=count(as=query_count))
| query_count > 100
| sort(query_count, order=desc)
| table([ComputerName, DomainName, query_count])
```

**Variant: Long subdomain queries (data encoded in DNS labels)**

```logscale
// Queries with unusually long hostnames — data exfiltration via DNS encoding
#event_simpleName=DnsRequest
| eval(domainLen=length(DomainName))
| domainLen > 50
| DomainName!=/\.(microsoft|windows|office365|akamai|akamaitechnologies|amazonaws|azure|google|apple|cdn)\.com/i
| table([ComputerName, UserName, DomainName, domainLen], limit=200)
```

**Variant: High entropy domain names (DGA or tunneling)**

```logscale
// Many unique subdomains under the same apex domain — DGA or tunneling
#event_simpleName=DnsRequest
| eval(apexDomain=replace(DomainName, /^.*?([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$)/, "$1"))
| groupBy([ComputerName, apexDomain], function=count(as=unique_queries))
| unique_queries > 50
| sort(unique_queries, order=desc)
```

**Variant: Uncommon DNS record types used for tunneling**

```logscale
// TXT, NULL, MX requests — common encoding vectors for DNS tunneling
#event_simpleName=DnsRequest
| in(RequestType, values=["TXT", "NULL", "MX", "SRV", "CNAME"])
| DomainName!=/\.(microsoft|office365|google|amazon|apple|cloudflare)\.com/i
| groupBy([ComputerName, DomainName, RequestType], function=count())
| sort(count_, order=desc)
```

## Response Notes

**Triage steps:**
1. Check the apex domain reputation via threat intel — newly registered or low-reputation domains are high priority
2. Look for the process making DNS queries by pivoting from `aid` to `ProcessRollup2` and `DnsRequest` in the same timeframe
3. Review the encoded data in query labels if accessible — often reveals C2 protocol, commands, or exfiltrated data
4. Block the domain at DNS resolver level while investigating
5. Capture full network traffic for the host if possible — DNS packet inspection reveals the tunnel content

**False positives:**
- Legitimate CDN services and cloud providers use long subdomain names (tracking pixels, analytics)
- Software update mechanisms may generate high query volumes during updates
- Internal DNS split-horizon configurations may generate high counts for internal domains — exclude internal zones

## References

- https://attack.mitre.org/techniques/T1071/004/
- https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/
- https://github.com/iagox86/dnscat2
