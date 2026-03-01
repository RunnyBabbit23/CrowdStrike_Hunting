# Off-Hours System Access and Activity

## Description

Detects system logons, file access, and sensitive operations occurring outside normal business hours — a behavioral anomaly frequently associated with insider threat activity. Malicious insiders often conduct data collection and exfiltration during off-hours to avoid detection by colleagues and reduce the chance of security team intervention. This is a baselining and anomaly-detection hunt; results must be contextualized against each user's normal work schedule.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection / Exfiltration |
| **Technique** | T1078 — Valid Accounts |
| **Sub-technique** | Off-hours access as behavioral indicator |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR / Identity Protection |
| **Repository** | `base_sensor_activity`, `base_identity_activity` |
| **Event Types** | `UserLogon`, `ProcessRollup2`, `AuthActivityAuditEvent` |

## Severity

**Low (Monitoring)** — Off-hours access alone is weak signal; elevated to Medium/High when combined with bulk data access, USB activity, or cloud uploads during the same off-hours window.

## Query

```logscale
// Logon events outside business hours (before 7am or after 7pm, adjust to your timezone)
#event_simpleName=UserLogon
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| eval(dayOfWeek=formatTime("%u", field=@timestamp, timezone="America/Chicago"))
// %u: 1=Monday, 7=Sunday
| (hour < "07" OR hour >= "19") OR dayOfWeek >= "6"
| LogonType!=3
| table([ComputerName, UserName, LogonType, hour, dayOfWeek, @timestamp], limit=500)
```

**Variant: Off-hours process execution (active work, not just logon)**

```logscale
// Any process run outside business hours — active user activity
#event_simpleName=ProcessRollup2
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| eval(dayOfWeek=formatTime("%u", field=@timestamp, timezone="America/Chicago"))
| (hour < "07" OR hour >= "19") OR dayOfWeek >= "6"
| FileName!=/svchost|MsMpEng|SearchIndexer|WmiPrvSE|TrustedInstaller|wuauclt|spoolsv|lsass|csrss|winlogon|services|smss|fontdrvhost/i
| groupBy([ComputerName, UserName, FileName, hour], function=count(as=exec_count))
| exec_count > 10
| sort(exec_count, order=desc)
| table([ComputerName, UserName, FileName, hour, exec_count])
```

**Variant: Off-hours sensitive file access**

```logscale
// File writes during off-hours from interactive user sessions
#event_simpleName=FileWritten
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| eval(dayOfWeek=formatTime("%u", field=@timestamp, timezone="America/Chicago"))
| (hour < "07" OR hour >= "19") OR dayOfWeek >= "6"
| FilePath=/(\\finance\\|\\hr\\|\\legal\\|\\contracts\\|\\confidential\\|\\source\\|\\src\\|\\repos\\)/i
| table([ComputerName, UserName, FilePath, FileName, hour, @timestamp], limit=200)
```

**Variant: Weekend or holiday access pattern**

```logscale
// Weekend logons and active sessions — identify users working outside normal schedule
#event_simpleName=UserLogon
| eval(dayOfWeek=formatTime("%u", field=@timestamp, timezone="America/Chicago"))
| dayOfWeek >= "6"
| LogonType=2
| groupBy([ComputerName, UserName, dayOfWeek], function=count(as=logon_count))
| sort(logon_count, order=desc)
| table([ComputerName, UserName, dayOfWeek, logon_count])
```

**Variant: First-time off-hours logon (new behavior for existing user)**

```logscale
// Users logging in during hours they have never previously accessed the system
// Use over a 30-day window to establish baseline then review outliers
#event_simpleName=UserLogon
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| LogonType=2
| groupBy([UserName, hour], function=count(as=logon_count))
| logon_count == 1
// Users who have only ONE logon at this hour — potential first-time off-hours access
| sort(logon_count)
| table([UserName, hour, logon_count])
```

**Variant: ITP off-hours authentication (domain level)**

```logscale
// Domain-level authentication at unusual hours (Identity Protection)
#event_simpleName=AuthActivityAuditEvent
| eval(hour=formatTime("%H", field=@timestamp, timezone="America/Chicago"))
| hour < "07" OR hour >= "19"
| EventType=INTERACTIVE
| groupBy([SourceUserName, SourceComputerName, hour], function=count(as=auth_count))
| sort(auth_count, order=desc)
| table([SourceUserName, SourceComputerName, hour, auth_count])
```

## Response Notes

**Triage steps:**
1. Validate whether the user has a known reason for off-hours access (remote worker, on-call rotation, international team) before escalating
2. The strongest signal is: **off-hours logon + bulk file access/USB activity in the same session** — run the USB exfil and bulk enumeration queries filtered to the same `UserName` and time window
3. Compare the off-hours access frequency over 30 days — a one-time occurrence is weaker signal than recurring late-night sessions that started recently
4. Check for VPN or remote access context — a user logging in via VPN at 2am from a different country than their home base is high priority
5. Correlate with HR data where possible — users who have recently given notice, had performance reviews, or are known to be unhappy are elevated priority

**Timezone note:**
- Adjust `timezone="America/Chicago"` to match your primary business timezone
- For global organizations, consider per-user timezone assignment if available in your identity data

**False positives:**
- On-call engineers and global teams legitimately work outside standard hours
- Automated service accounts run scheduled tasks off-hours — filter by known service account names
- Remote workers in different time zones — this is the most common false positive source

## References

- https://attack.mitre.org/techniques/T1078/
- https://www.cisa.gov/sites/default/files/publications/CISA_Insider_Threat_Mitigation_Guide.pdf
- https://www.dhs.gov/sites/default/files/publications/Combating%20the%20Insider%20Threat_0.pdf
