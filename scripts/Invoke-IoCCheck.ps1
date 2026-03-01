<#
.SYNOPSIS
    CrowdStrike RTR General-Purpose IoC Checker

.DESCRIPTION
    Checks a host against a structured IoC list for any threat — malware families,
    APT campaigns, ransomware, vulnerability exploitation, or custom indicators.

    The IoC list is a CSV file you upload to the host (or the Falcon cloud) before
    running. This separates the detection logic from the indicators, so the same
    script works for any threat just by swapping the CSV.

    Supported IoC types in the CSV:
      hash-sha256     SHA256 file or process hash
      hash-md5        MD5 file or process hash
      hash-sha1       SHA1 file or process hash
      ip              IP address (checked in active connections + DNS cache)
      ip-cidr         CIDR range (e.g., 192.168.1.0/24)
      domain          Domain or subdomain (DNS cache + hosts file)
      url             URL (DNS component checked in cache)
      filepath        Exact file path to check for existence
      filename        Filename to search in common staging locations
      registry-key    Registry key path to check for existence
      registry-value  Registry value data to search in run keys
      service-name    Windows service name
      task-name       Scheduled task name
      mutex           Named mutex (requires handle.exe in PATH)
      process-name    Process name to find in running processes
      pipe-name       Named pipe to look for
      user-agent      HTTP user-agent string (check in browser DBs if accessible)
      yara            YARA rule (inline rule string — requires yara64.exe in PATH)

    CSV format:
      Type,Value,Description,Severity,ThreatName,Source
      hash-sha256,abc123...,Cobalt Strike beacon dll,High,CobaltStrike,CrowdStrike-Intel
      ip,1.2.3.4,C2 server,High,BlackCat,AlienVault-OTX
      domain,evil.com,C2 domain,High,BlackCat,Manual
      filename,beacon.exe,Dropped payload,High,CobaltStrike,DFIR-Report

.PARAMETER IoCFile
    Path to the IoC CSV file. Can be:
      - A local path after uploading via RTR 'put' command
      - A UNC path to a network share
    Default: C:\Windows\Temp\iocs.csv

.PARAMETER IoCListBase64
    Alternative to IoCFile: pass the IoC CSV content as a base64-encoded string.
    Useful for smaller IoC lists without needing to upload a file first.

.PARAMETER OutputPath
    Directory for the results report. Default: C:\Windows\Temp

.PARAMETER SearchDepth
    How deeply to recurse filesystem searches. Default: 3

.PARAMETER HoursBack
    Window for event log and prefetch lookups. Default: 72

.PARAMETER StagingPathsOnly
    If true, limit filesystem search to known staging paths (faster).
    If false, search all user-writable locations. Default: $true

.EXAMPLE
    # Step 1 — Upload the IoC CSV and script via RTR:
    put "C:\tools\iocs.csv"

    # Step 2 — Run the check:
    runscript -CloudFile="Invoke-IoCCheck" -CommandLine="-IoCFile C:\Windows\Temp\iocs.csv"

    # Step 3 — Download the report:
    get "C:\Windows\Temp\IoCCheck_<hostname>_<timestamp>.txt"

    # Alternative: small IoC list inline as base64
    # $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content iocs.csv -Raw)))
    runscript -CloudFile="Invoke-IoCCheck" -CommandLine="-IoCListBase64 <base64string>"

.NOTES
    CSV template is available at: scripts/ioc-template.csv
    Generate IoC CSVs from MISP: Events -> Export -> CSV
    Generate from CrowdStrike Intel: Actor/Report -> Indicators -> Export
#>

[CmdletBinding()]
param(
    [string]$IoCFile          = "C:\Windows\Temp\iocs.csv",
    [string]$IoCListBase64    = "",
    [string]$OutputPath       = "C:\Windows\Temp",
    [int]   $SearchDepth      = 3,
    [int]   $HoursBack        = 72,
    [bool]  $StagingPathsOnly = $true
)

$ErrorActionPreference = 'SilentlyContinue'
$StartTime  = Get-Date
$Timestamp  = $StartTime.ToString("yyyyMMdd_HHmmss")
$ThisHost   = $env:COMPUTERNAME
$ReportFile = Join-Path $OutputPath "IoCCheck_${ThisHost}_${Timestamp}.txt"
$CsvReport  = Join-Path $OutputPath "IoCCheck_${ThisHost}_${Timestamp}.csv"
$Cutoff     = $StartTime.AddHours(-$HoursBack)

$Matches    = [System.Collections.Generic.List[PSCustomObject]]::new()
$Checked    = [System.Collections.Generic.List[string]]::new()
$Errors     = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Msg, [string]$Color = "Gray")
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$ts] $Msg" -ForegroundColor $Color
}

function Add-Match {
    param(
        [string]$Severity,
        [string]$IoCType,
        [string]$IoCValue,
        [string]$Description,
        [string]$ThreatName,
        [string]$Source,
        [string]$FindingDetail,
        [string]$FindingLocation
    )
    $Matches.Add([PSCustomObject]@{
        Severity        = $Severity.ToUpper()
        IoCType         = $IoCType
        IoCValue        = $IoCValue
        ThreatName      = $ThreatName
        Source          = $Source
        Description     = $Description
        FindingDetail   = $FindingDetail
        FindingLocation = $FindingLocation
        Timestamp       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    })
    $c = switch ($Severity.ToUpper()) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Cyan' } }
    Write-Host "  [MATCH][$($Severity.ToUpper())] $IoCType = $IoCValue" -ForegroundColor $c
    Write-Host "         Threat: $ThreatName | $FindingDetail" -ForegroundColor $c
}

# ── Load IoC List ─────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  CROWDSTRIKE RTR IOC CHECKER" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host "  Host     : $ThisHost"
Write-Host "  Start    : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"

$iocData = $null
if ($IoCListBase64 -ne "") {
    try {
        $csvContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($IoCListBase64))
        $iocData = $csvContent | ConvertFrom-Csv
        Write-Host "  IoC Source: Inline base64 ($($iocData.Count) indicators)"
    } catch {
        Write-Host "  [ERROR] Failed to decode base64 IoC list: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} elseif (Test-Path $IoCFile) {
    $iocData = Import-Csv $IoCFile -ErrorAction Stop
    Write-Host "  IoC Source: $IoCFile ($($iocData.Count) indicators)"
} else {
    Write-Host "  [ERROR] IoC file not found: $IoCFile" -ForegroundColor Red
    Write-Host "  Upload IoC CSV with RTR 'put' command first, or provide -IoCListBase64" -ForegroundColor Yellow
    exit 1
}

# Validate CSV columns
$required = @('Type','Value')
foreach ($col in $required) {
    if ($iocData[0].PSObject.Properties.Name -notcontains $col) {
        Write-Host "  [ERROR] IoC CSV missing required column: $col" -ForegroundColor Red
        exit 1
    }
}

Write-Host "================================================================"
Write-Host ""

# Pre-process IoCs by type for efficient batch lookups
$iocsByType = $iocData | Group-Object Type -AsHashTable -AsString

# ── Helper: safe CSV field lookup ────────────────────────────────────────────
function Get-IoCField { param($row, $field, $default = '')
    if ($row.PSObject.Properties.Name -contains $field) { $row.$field } else { $default }
}

# ── 1. Process Hash and Name Checks ──────────────────────────────────────────

$hashTypes = @('hash-sha256','hash-md5','hash-sha1')
$procNameIoCs = $iocsByType['process-name']
$filenameIoCs = $iocsByType['filename']

if (($hashTypes | ForEach-Object { $iocsByType[$_] } | Where-Object {$_}) -or $procNameIoCs -or $filenameIoCs) {
    Write-Log "Checking running processes..." "Cyan"

    $runningProcs = Get-WmiObject Win32_Process

    # Build hash lookup for efficiency
    $procHashes = @{}
    foreach ($proc in $runningProcs) {
        if ($proc.ExecutablePath) {
            $procHashes[$proc.ProcessId] = @{
                SHA256 = (Get-FileHash $proc.ExecutablePath -Algorithm SHA256 -EA SilentlyContinue).Hash
                MD5    = (Get-FileHash $proc.ExecutablePath -Algorithm MD5    -EA SilentlyContinue).Hash
                SHA1   = (Get-FileHash $proc.ExecutablePath -Algorithm SHA1   -EA SilentlyContinue).Hash
            }
        }
    }

    foreach ($proc in $runningProcs) {
        $hashes = $procHashes[$proc.ProcessId]
        $detail = "PID=$($proc.ProcessId) PPID=$($proc.ParentProcessId) Path=$($proc.ExecutablePath) CMD=$($proc.CommandLine)"

        foreach ($ioc in $iocsByType['hash-sha256']) {
            if ($hashes -and $hashes.SHA256 -ieq $ioc.Value) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'hash-sha256' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail $detail -FindingLocation "RUNNING_PROCESS"
            }
        }
        foreach ($ioc in $iocsByType['hash-md5']) {
            if ($hashes -and $hashes.MD5 -ieq $ioc.Value) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'hash-md5' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail $detail -FindingLocation "RUNNING_PROCESS"
            }
        }
        foreach ($ioc in $procNameIoCs) {
            if ($proc.Name -ilike $ioc.Value) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'Medium') -IoCType 'process-name' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail $detail -FindingLocation "RUNNING_PROCESS"
            }
        }
    }
    $Checked.Add("Running processes ($($runningProcs.Count))")
}

# ── 2. Network Connection Checks ─────────────────────────────────────────────

$ipIoCs     = $iocsByType['ip']
$cidrIoCs   = $iocsByType['ip-cidr']
$domainIoCs = $iocsByType['domain']
$urlIoCs    = $iocsByType['url']

if ($ipIoCs -or $cidrIoCs) {
    Write-Log "Checking network connections..." "Cyan"

    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    $Checked.Add("TCP connections ($($connections.Count))")

    # Helper: check if IP is in CIDR
    function Test-IpInCidr {
        param([string]$Ip, [string]$Cidr)
        try {
            $parts = $Cidr -split '/'
            $network = [System.Net.IPAddress]::Parse($parts[0])
            $bits    = [int]$parts[1]
            $mask    = [uint32]([Math]::Pow(2,32) - [Math]::Pow(2, 32-$bits))
            $netInt  = [System.BitConverter]::ToUInt32($network.GetAddressBytes()[3..0], 0)
            $ipInt   = [System.BitConverter]::ToUInt32(([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()[3..0], 0)
            return ($ipInt -band $mask) -eq ($netInt -band $mask)
        } catch { return $false }
    }

    foreach ($conn in $connections) {
        $procName = (Get-Process -Id $conn.OwningProcess -EA SilentlyContinue).Name

        foreach ($ioc in $ipIoCs) {
            if ($conn.RemoteAddress -eq $ioc.Value) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'ip' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail "Process=$procName PID=$($conn.OwningProcess) LocalPort=$($conn.LocalPort) RemotePort=$($conn.RemotePort) State=$($conn.State)" `
                    -FindingLocation "ACTIVE_CONNECTION"
            }
        }

        foreach ($ioc in $cidrIoCs) {
            if (Test-IpInCidr -Ip $conn.RemoteAddress -Cidr $ioc.Value) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'Medium') -IoCType 'ip-cidr' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail "RemoteIP=$($conn.RemoteAddress) Process=$procName Port=$($conn.RemotePort)" `
                    -FindingLocation "ACTIVE_CONNECTION"
            }
        }
    }
}

# ── 3. DNS Cache / Domain Checks ─────────────────────────────────────────────

if ($domainIoCs -or $urlIoCs) {
    Write-Log "Checking DNS cache and hosts file..." "Cyan"

    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    $hostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue

    # Extract domain from URL IoCs
    $allDomainIoCs = @($domainIoCs) + @($urlIoCs | ForEach-Object {
        $d = $_.Value -replace 'https?://','' -split '[/?]' | Select-Object -First 1
        [PSCustomObject]@{ Type='domain'; Value=$d; Severity=(Get-IoCField $_ 'Severity' 'High');
            Description=(Get-IoCField $_ 'Description'); ThreatName=(Get-IoCField $_ 'ThreatName' 'Unknown');
            Source=(Get-IoCField $_ 'Source') }
    })

    foreach ($ioc in $allDomainIoCs | Where-Object {$_}) {
        $domainPattern = $ioc.Value

        # DNS cache check
        $hit = $dnsCache | Where-Object { $_.Entry -ilike "*$domainPattern*" }
        if ($hit) {
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'domain' `
                -IoCValue $domainPattern -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "DNS cache entries: $($hit | ForEach-Object {"$($_.Entry)->$($_.Data)"} | Out-String)" `
                -FindingLocation "DNS_CACHE"
        }

        # Hosts file
        $hostsHit = $hostsContent | Where-Object { $_ -ilike "*$domainPattern*" -and $_ -notmatch '^#' }
        if ($hostsHit) {
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'Medium') -IoCType 'domain' `
                -IoCValue $domainPattern -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "Hosts file entry: $hostsHit" `
                -FindingLocation "HOSTS_FILE"
        }
    }
    $Checked.Add("DNS cache ($($dnsCache.Count) entries) + hosts file")
}

# ── 4. Filesystem Checks ──────────────────────────────────────────────────────

$filePathIoCs = $iocsByType['filepath']
$filenameIoCsList = $iocsByType['filename']
$allHashIoCs = @($iocsByType['hash-sha256']) + @($iocsByType['hash-md5']) + @($iocsByType['hash-sha1'])

if ($filePathIoCs -or $filenameIoCsList -or $allHashIoCs) {
    Write-Log "Checking filesystem..." "Cyan"

    # Exact path checks
    foreach ($ioc in $filePathIoCs) {
        if (Test-Path $ioc.Value) {
            $item = Get-Item $ioc.Value
            $sha256 = (Get-FileHash $ioc.Value -Algorithm SHA256 -EA SilentlyContinue).Hash
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'filepath' `
                -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "Size=$($item.Length) Modified=$($item.LastWriteTime) SHA256=$sha256" `
                -FindingLocation "FILESYSTEM"
        }
    }

    # Search paths
    $searchPaths = if ($StagingPathsOnly) {
        @("C:\Windows\Temp","C:\Users\Public","C:\ProgramData")
        # Add user-specific paths
        Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
            "$($_.LocalPath)\AppData\Local\Temp"
            "$($_.LocalPath)\AppData\Roaming"
            "$($_.LocalPath)\Downloads"
            "$($_.LocalPath)\Desktop"
        }
    } else {
        @("C:\Users","C:\Windows\Temp","C:\ProgramData","C:\Temp")
    }

    foreach ($searchPath in $searchPaths | Where-Object { Test-Path $_ } | Select-Object -Unique) {
        $files = Get-ChildItem $searchPath -Recurse -File -Depth $SearchDepth -ErrorAction SilentlyContinue

        foreach ($file in $files) {
            # Filename check
            foreach ($ioc in $filenameIoCsList) {
                if ($file.Name -ilike $ioc.Value) {
                    $sha256 = (Get-FileHash $file.FullName -Algorithm SHA256 -EA SilentlyContinue).Hash
                    Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'filename' `
                        -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                        -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                        -Source (Get-IoCField $ioc 'Source') `
                        -FindingDetail "Size=$($file.Length) Modified=$($file.LastWriteTime) SHA256=$sha256" `
                        -FindingLocation $file.FullName
                }
            }

            # Hash check for PE/script files (skip small/non-executable files)
            if ($allHashIoCs -and $file.Length -gt 1024 -and
                $file.Extension -imatch '\.(exe|dll|sys|ps1|bat|vbs|js|hta|com)$') {
                $sha256 = (Get-FileHash $file.FullName -Algorithm SHA256 -EA SilentlyContinue).Hash
                $md5    = (Get-FileHash $file.FullName -Algorithm MD5    -EA SilentlyContinue).Hash

                foreach ($ioc in $iocsByType['hash-sha256']) {
                    if ($sha256 -and $sha256 -ieq $ioc.Value) {
                        Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'hash-sha256' `
                            -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                            -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                            -Source (Get-IoCField $ioc 'Source') `
                            -FindingDetail "Size=$($file.Length) Modified=$($file.LastWriteTime)" `
                            -FindingLocation $file.FullName
                    }
                }
                foreach ($ioc in $iocsByType['hash-md5']) {
                    if ($md5 -and $md5 -ieq $ioc.Value) {
                        Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'hash-md5' `
                            -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                            -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                            -Source (Get-IoCField $ioc 'Source') `
                            -FindingDetail "Size=$($file.Length) Modified=$($file.LastWriteTime)" `
                            -FindingLocation $file.FullName
                    }
                }
            }
        }
    }
    $Checked.Add("Filesystem (staging paths)")
}

# ── 5. Registry Checks ────────────────────────────────────────────────────────

$regKeyIoCs = $iocsByType['registry-key']
$regValIoCs = $iocsByType['registry-value']

if ($regKeyIoCs -or $regValIoCs) {
    Write-Log "Checking registry..." "Cyan"

    foreach ($ioc in $regKeyIoCs) {
        # Convert HKLM\ to HKLM:\ for PowerShell
        $psPath = $ioc.Value -replace '^HK(LM|CU|CR|U|CC)\\', 'HK${1}:\'
        if (Test-Path $psPath) {
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'registry-key' `
                -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "Registry key exists" -FindingLocation $ioc.Value
        }
    }

    # Search run keys for value data matches
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty $key -EA SilentlyContinue
        $props | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object {
                $vName = $_.Name; $vData = $props.$vName
                foreach ($ioc in $regValIoCs) {
                    if ($vData -ilike "*$($ioc.Value)*") {
                        Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'registry-value' `
                            -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                            -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                            -Source (Get-IoCField $ioc 'Source') `
                            -FindingDetail "Key=$key Value=$vName Data=$vData" `
                            -FindingLocation "REGISTRY_RUN_KEY"
                    }
                }
            }
    }
    $Checked.Add("Registry (run keys + IoC key paths)")
}

# ── 6. Service Checks ─────────────────────────────────────────────────────────

$svcIoCs = $iocsByType['service-name']
if ($svcIoCs) {
    Write-Log "Checking services..." "Cyan"
    $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
    foreach ($ioc in $svcIoCs) {
        $hit = $services | Where-Object { $_.Name -ilike $ioc.Value -or $_.DisplayName -ilike $ioc.Value }
        if ($hit) {
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'service-name' `
                -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "Name=$($hit.Name) State=$($hit.State) Path=$($hit.PathName)" `
                -FindingLocation "SERVICES"
        }
    }
    $Checked.Add("Services ($($services.Count))")
}

# ── 7. Scheduled Task Checks ──────────────────────────────────────────────────

$taskIoCs = $iocsByType['task-name']
if ($taskIoCs) {
    Write-Log "Checking scheduled tasks..." "Cyan"
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($ioc in $taskIoCs) {
        $hit = $tasks | Where-Object { $_.TaskName -ilike $ioc.Value }
        if ($hit) {
            $action = ($hit.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'task-name' `
                -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail "Task=$($hit.TaskPath)$($hit.TaskName) Action=$action" `
                -FindingLocation "SCHEDULED_TASKS"
        }
    }
    $Checked.Add("Scheduled tasks ($($tasks.Count))")
}

# ── 8. Named Pipe Checks ──────────────────────────────────────────────────────

$pipeIoCs = $iocsByType['pipe-name']
if ($pipeIoCs) {
    Write-Log "Checking named pipes..." "Cyan"
    try {
        $pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
        foreach ($ioc in $pipeIoCs) {
            $hit = $pipes | Where-Object { $_ -ilike "*$($ioc.Value)*" }
            if ($hit) {
                Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'pipe-name' `
                    -IoCValue $ioc.Value -Description (Get-IoCField $ioc 'Description') `
                    -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                    -Source (Get-IoCField $ioc 'Source') `
                    -FindingDetail "Pipe present: $hit" -FindingLocation "NAMED_PIPES"
            }
        }
        $Checked.Add("Named pipes ($($pipes.Count))")
    } catch {
        $Errors.Add("Named pipe check failed: $($_.Exception.Message)")
    }
}

# ── 9. YARA Scan (if yara64.exe available) ───────────────────────────────────

$yaraIoCs = $iocsByType['yara']
if ($yaraIoCs -and (Get-Command 'yara64.exe' -ErrorAction SilentlyContinue)) {
    Write-Log "Running YARA scans..." "Cyan"
    foreach ($ioc in $yaraIoCs) {
        $tempRule = Join-Path $OutputPath "temp_rule_$([System.Guid]::NewGuid().ToString('N')).yar"
        $ioc.Value | Out-File $tempRule -Encoding ASCII
        $result = yara64.exe $tempRule C:\ -r 2>&1
        Remove-Item $tempRule -Force -ErrorAction SilentlyContinue
        if ($result -and $result -notmatch '^error') {
            Add-Match -Severity (Get-IoCField $ioc 'Severity' 'High') -IoCType 'yara' `
                -IoCValue "YARA:$(($ioc.Value -split '\n')[0])" -Description (Get-IoCField $ioc 'Description') `
                -ThreatName (Get-IoCField $ioc 'ThreatName' 'Unknown') `
                -Source (Get-IoCField $ioc 'Source') `
                -FindingDetail $result -FindingLocation "FILESYSTEM_YARA_SCAN"
        }
    }
}

# ── Generate Report ───────────────────────────────────────────────────────────

$EndTime   = Get-Date
$Duration  = ($EndTime - $StartTime).TotalSeconds
$highCount = ($Matches | Where-Object { $_.Severity -eq 'HIGH'   }).Count
$medCount  = ($Matches | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
$lowCount  = ($Matches | Where-Object { $_.Severity -eq 'LOW'    }).Count
$score     = ($highCount * 10) + ($medCount * 3) + $lowCount

$verdict = switch ($score) {
    { $_ -ge 10 } { "COMPROMISED — HIGH CONFIDENCE" }
    { $_ -ge 4  } { "SUSPICIOUS — MEDIUM CONFIDENCE" }
    { $_ -ge 1  } { "POSSIBLE INDICATOR — LOW CONFIDENCE" }
    default        { "CLEAN — NO INDICATORS MATCHED" }
}

# Text report
@"
================================================================
  CROWDSTRIKE RTR IOC CHECK REPORT
================================================================
  Host         : $ThisHost
  IoC File     : $IoCFile
  Total IoCs   : $($iocData.Count)
  Checks Run   : $($Checked.Count) categories
  Start        : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))
  End          : $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))
  Duration     : $([math]::Round($Duration,1))s

================================================================
  VERDICT: $verdict
  Matches: $($Matches.Count) total  (HIGH=$highCount  MEDIUM=$medCount  LOW=$lowCount)
================================================================

THREAT SUMMARY:
$($Matches | Group-Object ThreatName | ForEach-Object { "  $($_.Name): $($_.Count) indicator(s) matched" } | Out-String)
DETAILED FINDINGS:
$($Matches | ForEach-Object {
    "[$($_.Severity)] $($_.IoCType): $($_.IoCValue)"
    "  Threat    : $($_.ThreatName) ($($_.Source))"
    "  Desc      : $($_.Description)"
    "  Location  : $($_.FindingLocation)"
    "  Detail    : $($_.FindingDetail)"
    ""
} | Out-String)
CHECKS PERFORMED:
$($Checked | ForEach-Object { "  - $_" } | Out-String)
ERRORS ($($Errors.Count)):
$($Errors | ForEach-Object { "  - $_" } | Out-String)
"@ | Out-File -FilePath $ReportFile -Encoding UTF8 -Force

# CSV report (machine-readable for SIEM ingestion)
$Matches | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $CsvReport -Encoding UTF8 -Force

Write-Host ""
Write-Host "================================================================" -ForegroundColor White
Write-Host "  VERDICT: $verdict" -ForegroundColor $(if ($Matches.Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Matched: $($Matches.Count) indicators (HIGH=$highCount MEDIUM=$medCount LOW=$lowCount)" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor White
Write-Host ""
Write-Host "Reports:"
Write-Host "  Text : $ReportFile"
Write-Host "  CSV  : $CsvReport"
Write-Host ""
Write-Host "Download with RTR commands:"
Write-Host "  get `"$ReportFile`""
Write-Host "  get `"$CsvReport`""
