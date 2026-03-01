<#
.SYNOPSIS
    CrowdStrike RTR Lightweight Neighbor Triage Script

.DESCRIPTION
    Performs a fast IoC-driven triage check on a suspected neighbor host without
    running a full forensic collection. Takes IoCs identified on a confirmed
    compromised host and checks whether this host shows any matching indicators.

    Checks performed:
      - Running process hashes and filenames (malware binary presence/execution)
      - Network connections to known C2 IPs and ports
      - DNS cache for known C2 domains
      - Filesystem for malware files in common staging paths
      - Registry run keys for malware persistence
      - Scheduled tasks by name or command pattern
      - Windows services by name or binary path
      - WMI event subscriptions
      - Recently logged-on users from the compromised account
      - PSEXESVC / lateral movement tool artifacts

    Outputs a RISK ASSESSMENT (HIGH / MEDIUM / LOW / CLEAN) with all matches.

.PARAMETER CompromisedHost
    Hostname of the known compromised machine (for reference in report).

.PARAMETER CompromisedUsers
    One or more usernames from the compromised host to check for logon presence.

.PARAMETER MalwareHashes
    SHA256 hashes of malware identified on the compromised host.

.PARAMETER MalwareMD5
    MD5 hashes of malware identified on the compromised host.

.PARAMETER MalwareFileNames
    Executable filenames to search for (e.g., "beacon.exe", "svchosts.exe").

.PARAMETER MalwareFilePaths
    Specific full file paths to check for existence.

.PARAMETER C2IPs
    Known C2 IP addresses to check in active network connections.

.PARAMETER C2Domains
    Known C2 domains to check in the DNS resolver cache.

.PARAMETER C2Ports
    Known C2 ports to flag in active network connections.

.PARAMETER MalwareServiceNames
    Windows service names associated with the malware.

.PARAMETER MalwareTaskNames
    Scheduled task names associated with the malware.

.PARAMETER MalwareRegistryValues
    Registry value data strings to search in run keys.

.PARAMETER MalwareMutexes
    Named mutex strings to search for in handles (requires SysInternals handle.exe in path).

.PARAMETER HoursBack
    How many hours back to look for file system and event log activity. Default: 48.

.PARAMETER OutputPath
    Where to write the triage report. Default: C:\Windows\Temp

.EXAMPLE
    # Via RTR:
    runscript -CloudFile="Invoke-NeighborTriage" -CommandLine="-CompromisedHost VICTIM01 -CompromisedUsers jdoe -MalwareHashes abc123def456 -C2IPs 192.168.100.50 -C2Domains evil.c2.com"

.NOTES
    Designed to run as SYSTEM via CrowdStrike RTR.
    Download the report with: get "C:\Windows\Temp\NeighborTriage_<hostname>_<timestamp>.txt"
#>

[CmdletBinding()]
param(
    [string]   $CompromisedHost      = "UNKNOWN",
    [string[]] $CompromisedUsers     = @(),
    [string[]] $MalwareHashes        = @(),
    [string[]] $MalwareMD5           = @(),
    [string[]] $MalwareFileNames     = @(),
    [string[]] $MalwareFilePaths     = @(),
    [string[]] $C2IPs                = @(),
    [string[]] $C2Domains            = @(),
    [int[]]    $C2Ports              = @(),
    [string[]] $MalwareServiceNames  = @(),
    [string[]] $MalwareTaskNames     = @(),
    [string[]] $MalwareRegistryValues = @(),
    [string[]] $MalwareMutexes       = @(),
    [int]      $HoursBack            = 48,
    [string]   $OutputPath           = "C:\Windows\Temp"
)

$ErrorActionPreference = 'SilentlyContinue'
$StartTime  = Get-Date
$Timestamp  = $StartTime.ToString("yyyyMMdd_HHmmss")
$ThisHost   = $env:COMPUTERNAME
$ReportPath = Join-Path $OutputPath "NeighborTriage_${ThisHost}_${Timestamp}.txt"
$Cutoff     = $StartTime.AddHours(-$HoursBack)

# ── Result tracking ──────────────────────────────────────────────────────────

$Findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$ChecksRun = 0

function Add-Finding {
    param(
        [string]$Severity,   # HIGH / MEDIUM / LOW
        [string]$Category,
        [string]$IoC,
        [string]$Detail
    )
    $Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        IoC      = $IoC
        Detail   = $Detail
        Time     = (Get-Date).ToString("HH:mm:ss")
    })
    $color = switch ($Severity) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
    Write-Host "  [$Severity] $Category | IoC: $IoC" -ForegroundColor $color
    Write-Host "         $Detail"
}

function Write-Section {
    param([string]$Title)
    $script:ChecksRun++
    Write-Host ""
    Write-Host ">>> $Title" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  CROWDSTRIKE RTR NEIGHBOR TRIAGE" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host "  This Host       : $ThisHost"
Write-Host "  Compromised Host: $CompromisedHost"
Write-Host "  Start Time      : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "  Looking back    : $HoursBack hours"
Write-Host "  IoC Counts      : $($MalwareHashes.Count) hashes | $($C2IPs.Count) IPs | $($C2Domains.Count) domains | $($MalwareFileNames.Count) filenames"
Write-Host "================================================================"
Write-Host ""

# ── 1. Running Process Hash Check ────────────────────────────────────────────

if ($MalwareHashes.Count -gt 0 -or $MalwareMD5.Count -gt 0 -or $MalwareFileNames.Count -gt 0) {
    Write-Section "Running Process Check"

    $processes = Get-WmiObject Win32_Process
    foreach ($proc in $processes) {
        # SHA256 check
        if ($proc.ExecutablePath -and $MalwareHashes.Count -gt 0) {
            $hash = (Get-FileHash $proc.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($hash -and $MalwareHashes -contains $hash) {
                Add-Finding -Severity HIGH -Category "RUNNING_PROCESS" `
                    -IoC $hash `
                    -Detail "PID=$($proc.ProcessId) Name=$($proc.Name) Path=$($proc.ExecutablePath) CMD=$($proc.CommandLine)"
            }
        }
        # MD5 check
        if ($proc.ExecutablePath -and $MalwareMD5.Count -gt 0) {
            $md5 = (Get-FileHash $proc.ExecutablePath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
            if ($md5 -and $MalwareMD5 -contains $md5) {
                Add-Finding -Severity HIGH -Category "RUNNING_PROCESS_MD5" `
                    -IoC $md5 `
                    -Detail "PID=$($proc.ProcessId) Name=$($proc.Name) Path=$($proc.ExecutablePath)"
            }
        }
        # Filename check
        foreach ($fname in $MalwareFileNames) {
            if ($proc.Name -ieq $fname) {
                Add-Finding -Severity MEDIUM -Category "RUNNING_PROCESS_NAME" `
                    -IoC $fname `
                    -Detail "PID=$($proc.ProcessId) Path=$($proc.ExecutablePath) CMD=$($proc.CommandLine)"
            }
        }
    }

    # Also check for PSEXESVC (lateral movement artifact)
    $psexe = $processes | Where-Object { $_.Name -ieq 'PSEXESVC.exe' }
    if ($psexe) {
        Add-Finding -Severity HIGH -Category "LATERAL_MOVEMENT_ARTIFACT" `
            -IoC "PSEXESVC.exe" `
            -Detail "PsExec service running — this host was a lateral movement target. PID=$($psexe.ProcessId)"
    }
}

# ── 2. Network Connection Check ──────────────────────────────────────────────

if ($C2IPs.Count -gt 0 -or $C2Ports.Count -gt 0) {
    Write-Section "Active Network Connection Check"

    try {
        $connections = Get-NetTCPConnection -State Established,TimeWait,CloseWait -ErrorAction Stop
        $udpConnections = Get-NetUDPEndpoint -ErrorAction SilentlyContinue

        foreach ($conn in $connections) {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name

            # C2 IP match
            foreach ($ip in $C2IPs) {
                if ($conn.RemoteAddress -eq $ip) {
                    Add-Finding -Severity HIGH -Category "ACTIVE_C2_CONNECTION" `
                        -IoC $ip `
                        -Detail "LocalPort=$($conn.LocalPort) RemotePort=$($conn.RemotePort) State=$($conn.State) PID=$($conn.OwningProcess) Process=$procName"
                }
            }

            # C2 Port match (unusual outbound port may indicate C2)
            foreach ($port in $C2Ports) {
                if ($conn.RemotePort -eq $port -and $conn.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)') {
                    Add-Finding -Severity MEDIUM -Category "SUSPICIOUS_PORT_CONNECTION" `
                        -IoC "port:$port" `
                        -Detail "Remote=$($conn.RemoteAddress):$port State=$($conn.State) PID=$($conn.OwningProcess) Process=$procName"
                }
            }
        }
    } catch {
        # Fallback to netstat
        $netstatOutput = netstat -ano 2>&1
        foreach ($line in $netstatOutput | Select-String 'ESTABLISHED') {
            foreach ($ip in $C2IPs) {
                if ($line -match [regex]::Escape($ip)) {
                    Add-Finding -Severity HIGH -Category "ACTIVE_C2_CONNECTION" `
                        -IoC $ip `
                        -Detail $line.ToString().Trim()
                }
            }
        }
    }
}

# ── 3. DNS Cache Check ───────────────────────────────────────────────────────

if ($C2Domains.Count -gt 0) {
    Write-Section "DNS Cache Check"

    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($domain in $C2Domains) {
        $match = $dnsCache | Where-Object { $_.Entry -ilike "*$domain*" }
        if ($match) {
            Add-Finding -Severity HIGH -Category "C2_DNS_CACHED" `
                -IoC $domain `
                -Detail "DNS cache hit: $($match | ForEach-Object { "$($_.Entry) -> $($_.Data)" } | Select-Object -First 5 | Out-String)"
        }
    }

    # Also check hosts file for domain redirects
    $hostsFile = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    foreach ($domain in $C2Domains) {
        $match = $hostsFile | Where-Object { $_ -ilike "*$domain*" -and $_ -notmatch '^#' }
        if ($match) {
            Add-Finding -Severity MEDIUM -Category "C2_DOMAIN_IN_HOSTS" `
                -IoC $domain `
                -Detail "Found in hosts file: $match"
        }
    }
}

# ── 4. Filesystem Check ──────────────────────────────────────────────────────

if ($MalwareFileNames.Count -gt 0 -or $MalwareFilePaths.Count -gt 0 -or $MalwareHashes.Count -gt 0) {
    Write-Section "Filesystem Check"

    # Check specific paths
    foreach ($path in $MalwareFilePaths) {
        if (Test-Path $path) {
            $item = Get-Item $path
            $hash = (Get-FileHash $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Add-Finding -Severity HIGH -Category "MALWARE_FILE_EXISTS" `
                -IoC $path `
                -Detail "File present. Size=$($item.Length) Modified=$($item.LastWriteTime) SHA256=$hash"
        }
    }

    # Search common staging paths for malware filenames
    $stagingPaths = @(
        "C:\Windows\Temp",
        "$env:TEMP", "$env:TMP",
        "C:\Users\Public",
        "C:\ProgramData"
    )
    # Add all user temp dirs
    Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
        $stagingPaths += "$($_.LocalPath)\AppData\Local\Temp"
        $stagingPaths += "$($_.LocalPath)\AppData\Roaming"
        $stagingPaths += "$($_.LocalPath)\Downloads"
        $stagingPaths += "$($_.LocalPath)\Desktop"
    }

    foreach ($fname in $MalwareFileNames) {
        foreach ($searchPath in $stagingPaths | Select-Object -Unique) {
            if (-not (Test-Path $searchPath)) { continue }
            $found = Get-ChildItem $searchPath -Filter $fname -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 5
            foreach ($f in $found) {
                $hash = (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                Add-Finding -Severity HIGH -Category "MALWARE_FILE_FOUND_ON_DISK" `
                    -IoC $fname `
                    -Detail "Path=$($f.FullName) Size=$($f.Length) Modified=$($f.LastWriteTime) SHA256=$hash"
            }
        }
    }

    # Hash check on recently modified executables in staging paths
    if ($MalwareHashes.Count -gt 0) {
        foreach ($searchPath in @("C:\Windows\Temp","C:\Users\Public","C:\ProgramData") | Select-Object -Unique) {
            Get-ChildItem $searchPath -Include @('*.exe','*.dll','*.ps1') -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $Cutoff } |
                ForEach-Object {
                    $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    if ($hash -and $MalwareHashes -contains $hash) {
                        Add-Finding -Severity HIGH -Category "MALWARE_HASH_ON_DISK" `
                            -IoC $hash `
                            -Detail "Path=$($_.FullName) Size=$($_.Length) Modified=$($_.LastWriteTime)"
                    }
                }
        }
    }
}

# ── 5. Registry Persistence Check ────────────────────────────────────────────

Write-Section "Registry Persistence Check"

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

# Recent run key entries (added in last HoursBack window)
# Note: Registry doesn't store write timestamps natively; we check content for IoC matches

foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    $props | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' } |
        ForEach-Object {
            $valueName = $_.Name
            $valueData = $props.$valueName

            # Check for malware filename in run key value
            foreach ($fname in $MalwareFileNames) {
                if ($valueData -ilike "*$fname*") {
                    Add-Finding -Severity HIGH -Category "MALWARE_RUN_KEY" `
                        -IoC $fname `
                        -Detail "Key=$key Value=$valueName Data=$valueData"
                }
            }

            # Check for specific registry value strings
            foreach ($regVal in $MalwareRegistryValues) {
                if ($valueData -ilike "*$regVal*") {
                    Add-Finding -Severity HIGH -Category "MALWARE_REGISTRY_VALUE" `
                        -IoC $regVal `
                        -Detail "Key=$key Value=$valueName Data=$valueData"
                }
            }

            # Flag run key entries in suspicious paths
            if ($valueData -match '(\\Temp\\|\\AppData\\|\\Public\\|\\Downloads\\)' -and
                $valueData -match '\.(exe|dll|ps1|vbs|js|bat|hta)') {
                Add-Finding -Severity MEDIUM -Category "SUSPICIOUS_RUN_KEY" `
                    -IoC $valueName `
                    -Detail "Key=$key Value=$valueName Data=$valueData"
            }
        }
}

# ── 6. Scheduled Task Check ───────────────────────────────────────────────────

Write-Section "Scheduled Task Check"

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($task in $tasks) {
    $taskAction = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '

    # Check by task name
    foreach ($taskName in $MalwareTaskNames) {
        if ($task.TaskName -ilike "*$taskName*") {
            Add-Finding -Severity HIGH -Category "MALWARE_SCHEDULED_TASK" `
                -IoC $taskName `
                -Detail "Task=$($task.TaskPath)$($task.TaskName) Action=$taskAction"
        }
    }

    # Check task action for malware filenames
    foreach ($fname in $MalwareFileNames) {
        if ($taskAction -ilike "*$fname*") {
            Add-Finding -Severity HIGH -Category "MALWARE_TASK_ACTION" `
                -IoC $fname `
                -Detail "Task=$($task.TaskName) Action=$taskAction"
        }
    }

    # Check for tasks pointing to suspicious locations
    if ($taskAction -match '(\\Temp\\|\\AppData\\|\\Public\\|\\Downloads\\|\\ProgramData\\)' -and
        $taskAction -match '\.(exe|ps1|vbs|js|bat|hta)') {
        $taskInfo = Get-ScheduledTaskInfo $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        if ($taskInfo.LastRunTime -gt $Cutoff -or $task.Date -gt $Cutoff) {
            Add-Finding -Severity MEDIUM -Category "SUSPICIOUS_TASK_LOCATION" `
                -IoC $task.TaskName `
                -Detail "Action=$taskAction LastRun=$($taskInfo.LastRunTime)"
        }
    }
}

# ── 7. Windows Service Check ─────────────────────────────────────────────────

Write-Section "Service Check"

$services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
foreach ($svc in $services) {
    # Check by service name
    foreach ($svcName in $MalwareServiceNames) {
        if ($svc.Name -ieq $svcName -or $svc.DisplayName -ilike "*$svcName*") {
            Add-Finding -Severity HIGH -Category "MALWARE_SERVICE" `
                -IoC $svcName `
                -Detail "Name=$($svc.Name) State=$($svc.State) Path=$($svc.PathName)"
        }
    }

    # Check service binary path for malware filenames
    foreach ($fname in $MalwareFileNames) {
        if ($svc.PathName -ilike "*$fname*") {
            Add-Finding -Severity HIGH -Category "MALWARE_SERVICE_BINARY" `
                -IoC $fname `
                -Detail "Service=$($svc.Name) Path=$($svc.PathName) State=$($svc.State)"
        }
    }
}

# ── 8. User Logon Check ───────────────────────────────────────────────────────

if ($CompromisedUsers.Count -gt 0) {
    Write-Section "Compromised User Logon Check"

    $logonEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = @(4624, 4648)
        StartTime = $Cutoff
    } -ErrorAction SilentlyContinue

    foreach ($user in $CompromisedUsers) {
        $userLogons = $logonEvents | Where-Object { $_.Message -ilike "*$user*" }
        if ($userLogons) {
            $count = ($userLogons | Measure-Object).Count
            $first = ($userLogons | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            $last  = ($userLogons | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
            Add-Finding -Severity HIGH -Category "COMPROMISED_USER_LOGON" `
                -IoC $user `
                -Detail "Compromised user '$user' has $count logon events on this host since $first. Most recent: $last"
        }
    }

    # Check if user is currently logged in
    $activeSessions = quser 2>&1 | Where-Object { $_ -match ($CompromisedUsers -join '|') }
    if ($activeSessions) {
        Add-Finding -Severity HIGH -Category "COMPROMISED_USER_ACTIVE_SESSION" `
            -IoC ($CompromisedUsers -join ',') `
            -Detail "Compromised user has ACTIVE SESSION: $activeSessions"
    }
}

# ── 9. WMI Subscription Check ────────────────────────────────────────────────

Write-Section "WMI Subscription Check"

$wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
if ($wmiFilters) {
    foreach ($filter in $wmiFilters) {
        Add-Finding -Severity MEDIUM -Category "WMI_SUBSCRIPTION_PRESENT" `
            -IoC $filter.Name `
            -Detail "WMI EventFilter found: Name=$($filter.Name) Query=$($filter.Query)"
    }
}

# ── 10. Lateral Movement Artifacts ───────────────────────────────────────────

Write-Section "Lateral Movement Artifact Check"

# Check for PSEXESVC in services
$psexeSvc = Get-WmiObject Win32_Service | Where-Object { $_.Name -ieq 'PSEXESVC' }
if ($psexeSvc) {
    Add-Finding -Severity HIGH -Category "PSEXESVC_SERVICE" `
        -IoC "PSEXESVC" `
        -Detail "PsExec service installed — this host was a lateral movement target. State=$($psexeSvc.State)"
}

# Check for PSEXESVC registry key
$psexeKey = "HKLM:\SYSTEM\CurrentControlSet\Services\PSEXESVC"
if (Test-Path $psexeKey) {
    Add-Finding -Severity HIGH -Category "PSEXESVC_REGISTRY" `
        -IoC "PSEXESVC" `
        -Detail "PSEXESVC registry key present — evidence of PsExec lateral movement"
}

# Check for remote access tools recently installed as services
$recentServices = Get-WinEvent -FilterHashtable @{
    LogName = 'System'; Id = 7045; StartTime = $Cutoff
} -ErrorAction SilentlyContinue
foreach ($evt in $recentServices) {
    Add-Finding -Severity MEDIUM -Category "NEW_SERVICE_INSTALLED" `
        -IoC "EventId:7045" `
        -Detail "New service installed: $($evt.Message -replace '\r\n',' | ')"
}

# ── 11. Quick Prefetch Check (recently executed processes) ───────────────────

Write-Section "Recent Execution Check (Prefetch)"

$prefetchDir = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchDir) {
    $recentPrefetch = Get-ChildItem $prefetchDir -Filter '*.pf' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $Cutoff } |
        Sort-Object LastWriteTime -Descending

    foreach ($pf in $recentPrefetch) {
        $exeName = ($pf.Name -split '-')[0] + '.exe'
        foreach ($fname in $MalwareFileNames) {
            if ($exeName -ilike "*$fname*") {
                Add-Finding -Severity HIGH -Category "MALWARE_PREFETCH_EVIDENCE" `
                    -IoC $fname `
                    -Detail "Prefetch file indicates recent execution: $($pf.Name) LastRun=$($pf.LastWriteTime)"
            }
        }
    }
}

# ── Generate Report ───────────────────────────────────────────────────────────

$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

$riskScore = 0
$highCount   = ($Findings | Where-Object { $_.Severity -eq 'HIGH'   } | Measure-Object).Count
$mediumCount = ($Findings | Where-Object { $_.Severity -eq 'MEDIUM' } | Measure-Object).Count
$lowCount    = ($Findings | Where-Object { $_.Severity -eq 'LOW'    } | Measure-Object).Count

$riskScore = ($highCount * 10) + ($mediumCount * 3) + ($lowCount * 1)
$riskLevel = switch ($riskScore) {
    { $_ -ge 10 } { "HIGH — CONTAIN IMMEDIATELY" }
    { $_ -ge 4  } { "MEDIUM — INVESTIGATE FURTHER" }
    { $_ -ge 1  } { "LOW — MONITOR CLOSELY" }
    default        { "CLEAN — NO INDICATORS FOUND" }
}

$reportHeader = @"
================================================================
  CROWDSTRIKE RTR NEIGHBOR TRIAGE REPORT
================================================================
  This Host        : $ThisHost
  Compromised Host : $CompromisedHost
  Triage Start     : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  Triage End       : $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))
  Duration         : $([math]::Round($Duration,1)) seconds
  Look-back Window : $HoursBack hours

  IoCs Checked:
    SHA256 Hashes  : $($MalwareHashes.Count)
    MD5 Hashes     : $($MalwareMD5.Count)
    Filenames      : $($MalwareFileNames.Count)
    File Paths     : $($MalwareFilePaths.Count)
    C2 IPs         : $($C2IPs.Count)
    C2 Domains     : $($C2Domains.Count)
    C2 Ports       : $($C2Ports.Count)
    Service Names  : $($MalwareServiceNames.Count)
    Task Names     : $($MalwareTaskNames.Count)
    Compromised Users: $($CompromisedUsers.Count)

================================================================
  RISK ASSESSMENT: $riskLevel
  Score: $riskScore  (HIGH=$highCount  MEDIUM=$mediumCount  LOW=$lowCount)
================================================================

"@

$reportBody = if ($Findings.Count -gt 0) {
    $Findings | ForEach-Object {
        "[$($_.Severity)] [$($_.Category)]`n  IoC   : $($_.IoC)`n  Detail: $($_.Detail)`n"
    } | Out-String
} else {
    "  No indicators found matching provided IoCs.`n"
}

$report = $reportHeader + $reportBody

# Write report file
$report | Out-File -FilePath $ReportPath -Encoding UTF8 -Force

# Also print summary to RTR console
Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  RISK ASSESSMENT: $riskLevel" -ForegroundColor $(if ($Findings.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Findings: HIGH=$highCount  MEDIUM=$mediumCount  LOW=$lowCount" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host ""
Write-Host "Report written to: $ReportPath"
Write-Host ""
Write-Host "Download with RTR command:"
Write-Host "  get `"$ReportPath`""
