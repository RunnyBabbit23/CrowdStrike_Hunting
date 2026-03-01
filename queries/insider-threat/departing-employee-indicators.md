# Departing Employee Behavioral Indicators

## Description

Detects behavioral patterns consistent with an employee preparing to leave an organization — characterized by unusual spikes in data access, file collection, LinkedIn/job board browsing, and external communication. Research shows insiders steal data most frequently in the 30-90 days before departure. This is a correlation hunt combining multiple weak signals into a risk profile: bulk file access + job site browsing + personal cloud/email access + USB activity.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Collection / Exfiltration |
| **Technique** | T1005 — Data from Local System |
| **Sub-technique** | T1078 — Valid Accounts (abuse before termination) |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `DnsRequest`, `ProcessRollup2`, `FileWritten` |

## Severity

**Low (Risk Indicator)** — No single signal here is malicious; the combination of several signals from the same user over a 7-30 day window elevates risk. Requires HR correlation for context.

## Query

```logscale
// Job board and professional network DNS queries — departure planning indicator
#event_simpleName=DnsRequest
| DomainName=/(
    linkedin\.com|
    indeed\.com|
    glassdoor\.com|
    monster\.com|
    ziprecruiter\.com|
    dice\.com|
    hired\.com|
    levels\.fyi|
    teamblind\.com|
    simplyhired\.com|
    careerbuilder\.com|
    jobs\.lever\.co|
    greenhouse\.io|
    workday\.com|
    icims\.com|
    smartrecruiters\.com
  )/i
| groupBy([ComputerName, UserName, DomainName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([ComputerName, UserName, DomainName, query_count])
```

**Variant: Competitor company website access**

```logscale
// Access to known competitor domains — potential job search at direct competitors
// Replace with your actual competitor domains
#event_simpleName=DnsRequest
| DomainName=/(
    competitor1\.com|
    competitor2\.com|
    competitor3\.com|
    competitor4\.io
  )/i
| groupBy([ComputerName, UserName, DomainName], function=count(as=query_count))
| sort(query_count, order=desc)
| table([ComputerName, UserName, DomainName, query_count])
```

**Variant: Spike in file access volume (collecting data before departure)**

```logscale
// Users with significantly elevated file write/copy activity in the current week vs. baseline
// Run over 30 days and look for users in the top percentile of recent activity
#event_simpleName=FileWritten
| eval(week=formatTime("%Y-W%V", field=@timestamp))
| groupBy([UserName, week], function=count(as=weekly_writes))
| sort(weekly_writes, order=desc)
| head(50)
| table([UserName, week, weekly_writes])
```

**Variant: Access to HR, finance, or executive directories (scope expansion)**

```logscale
// User accessing directories outside their normal job function — data collection beyond their role
#event_simpleName=ProcessRollup2
| FileName=/(explorer|cmd|powershell|robocopy|xcopy)\.exe/i
| CommandLine=/(
    \\hr\\|\\human.resources\\|\\payroll\\|\\compensation\\|
    \\finance\\|\\accounting\\|\\ap\\|\\ar\\|
    \\legal\\|\\contracts\\|\\litigation\\|
    \\executive\\|\\board\\|\\strategy\\|
    \\merger|\\acquisition|\\m&a\\
  )/i
| table([ComputerName, UserName, FileName, CommandLine, @timestamp], limit=200)
```

**Variant: Multiple risk indicators from the same user (risk aggregation)**

```logscale
// Aggregate multiple insider threat signals by user for risk scoring
// Combine job site access + personal cloud + webmail signals
#event_simpleName=DnsRequest
| DomainName=/(
    linkedin\.com|indeed\.com|glassdoor\.com|
    gmail\.com|protonmail\.com|
    dropbox\.com|drive\.google\.com|mega\.nz|
    wetransfer\.com
  )/i
| groupBy([UserName, DomainName], function=count(as=query_count))
| groupBy([UserName], function=[
    count(as=total_queries),
    collect(DomainName, limit=20, as=domains_accessed)
  ])
| sort(total_queries, order=desc)
| table([UserName, total_queries, domains_accessed])
```

**Variant: LinkedIn recruiter messages / InMail indicator (profile lookup pattern)**

```logscale
// High-frequency LinkedIn access — responding to recruiter outreach
#event_simpleName=DnsRequest
| DomainName=/linkedin\.com/i
| groupBy([ComputerName, UserName], function=count(as=linkedin_queries))
| linkedin_queries > 30
| sort(linkedin_queries, order=desc)
| table([ComputerName, UserName, linkedin_queries])
```

**Variant: Personal email + file staging + job site on same day**

```logscale
// Same user accessing job boards AND personal email on the same calendar day
// Run step 1 and step 2 separately, then correlate by UserName + date
// Step 1: Job board access dates
#event_simpleName=DnsRequest
| DomainName=/(linkedin|indeed|glassdoor|dice\.com)/i
| eval(date=formatTime("%Y-%m-%d", field=@timestamp))
| groupBy([UserName, date], function=count(as=job_queries))
// Step 2 (separate query): Personal email on same dates
// #event_simpleName=DnsRequest
// | DomainName=/(gmail|protonmail|yahoo.*mail|hotmail)/i
// | eval(date=formatTime("%Y-%m-%d", field=@timestamp))
// | groupBy([UserName, date], function=count(as=email_queries))
| table([UserName, date, job_queries])
```

## Response Notes

**Triage steps:**
1. This is a **risk profiling hunt** — results should be shared with HR and legal before any employee contact
2. Prioritize users with: (a) access to sensitive data + (b) job board activity + (c) any of the exfil indicators (USB, personal cloud, webmail) in the same window
3. Review `UserName` against HR data — is this user on a PIP, recently passed over for promotion, or in a restructuring-affected team?
4. Consider implementing a formal off-boarding data review process triggered when resignation is received
5. Do NOT contact the employee based on this data alone — work with HR/legal on appropriate response

**Privacy considerations:**
- Job searching is a legal activity and employees have some privacy expectations even on corporate devices
- These signals are risk indicators, not proof of wrongdoing
- Follow your organization's acceptable use policy, privacy policy, and local employment law before acting on this data
- Document the business justification for any monitoring or investigation

**False positives:**
- Routine LinkedIn use for professional networking is extremely common — frequency matters
- HR staff legitimately access HR systems and competitor sites for recruiting purposes
- Finance team members access financial directories as part of their normal job function

## References

- https://attack.mitre.org/techniques/T1005/
- https://www.crowdstrike.com/blog/insider-threat-detection/
- https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=484744
- https://www.dhs.gov/sites/default/files/publications/Combating%20the%20Insider%20Threat_0.pdf
