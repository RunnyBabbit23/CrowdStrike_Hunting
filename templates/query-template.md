# [Query Title]

## Description

[What does this query detect? Explain the behavior, why it's suspicious/malicious, and what attacker goal it supports. 2-4 sentences.]

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | [e.g., Execution] |
| **Technique** | [e.g., T1059.001 — PowerShell] |
| **Sub-technique** | [if applicable] |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | [Endpoint EDR / Identity Protection / Cloud CSPM] |
| **Repository** | [e.g., `base_sensor_activity`] |
| **Event Types** | [e.g., `ProcessRollup2`] |

## Severity

**[High / Medium / Low]** — [One-line rationale]

## Query

```logscale
// [Brief comment explaining what this block does]
#event_simpleName=ProcessRollup2
| field1=value
| field2=/regex/i
| table([ComputerName, UserName, FileName, CommandLine], limit=200)
```

## Response Notes

**Triage steps:**
1. [First thing to check — pivot on `aid` or `ComputerName` for context]
2. [Second step — correlate with related events]
3. [Third step — escalation criteria]

**False positives:**
- [Known benign scenario that could trigger this query]
- [Exclusion suggestion if applicable]

## References

- [Link to MITRE page, vendor blog, CVE, etc.]
