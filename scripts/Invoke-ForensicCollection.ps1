<#
.SYNOPSIS
    CrowdStrike RTR Forensic Collection Script

.DESCRIPTION
    Collects forensic artifacts from a Windows endpoint via CrowdStrike Real-Time Response.
    Bundles all artifacts into a timestamped ZIP file for download with the RTR `get` command.

    Collected artifact categories:
      - System information (OS, hardware, installed software, patches)
      - Network state (connections, ARP, DNS cache, routing, firewall)
      - Processes and services (running procs, tree, services, drivers)
      - User accounts and sessions (local users, groups, active sessions)
      - Persistence (run keys, scheduled tasks, services, startup folders)
      - Event logs (Security, System, Application, PowerShell — EVTX + CSV)
      - File system artifacts (temp files, prefetch, LNK/recent docs)
      - Registry exports (run keys, USB history, typed paths, BAM/DAM)
      - Browser artifacts (Chrome, Edge, Firefox — history DBs copied)
      - Chain of custody manifest (SHA256 hashes of all collected files)

.PARAMETER OutputPath
    Root directory where the collection folder is created. Default: C:\Windows\Temp

.PARAMETER IncludeEventLogs
    Copy full EVTX log files in addition to CSV exports. Increases output size. Default: $true

.PARAMETER MaxEventLogEntries
    Maximum number of entries to export per event log channel to CSV. Default: 5000

.PARAMETER IncludeBrowserArtifacts
    Copy browser SQLite databases for all user profiles. Default: $true

.EXAMPLE
    # Run directly:
    .\Invoke-ForensicCollection.ps1

    # Run via RTR (after uploading to cloud scripts):
    runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-OutputPath C:\Windows\Temp"

    # Run via RTR with event logs disabled for faster collection:
    runscript -CloudFile="Invoke-ForensicCollection" -CommandLine="-IncludeEventLogs:`$false"

.NOTES
    Designed to run as SYSTEM via CrowdStrike RTR.
    After execution, download the ZIP with the RTR command:
        get C:\Windows\Temp\CS_Forensics_<hostname>_<timestamp>.zip
#>

[CmdletBinding()]
param(
    [string]$OutputPath    = "C:\Windows\Temp",
    [bool]$IncludeEventLogs        = $true,
    [int]$MaxEventLogEntries       = 5000,
    [bool]$IncludeBrowserArtifacts = $true
)

#region ── Initialization ──────────────────────────────────────────────────────

$ErrorActionPreference = 'SilentlyContinue'
$StartTime   = Get-Date
$Timestamp   = $StartTime.ToString("yyyyMMdd_HHmmss")
$Hostname    = $env:COMPUTERNAME
$CollectName = "CS_Forensics_${Hostname}_${Timestamp}"
$CollectDir  = Join-Path $OutputPath $CollectName
$ZipPath     = "${CollectDir}.zip"

# Sub-directories
$Dirs = @('system','network','processes','users','persistence','logs','files','registry','browser')

# Manifest tracking
$Manifest    = [System.Collections.Generic.List[PSCustomObject]]::new()
$Errors      = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$ts][$Level] $Message"
}

function Add-Manifest {
    param([string]$Category, [string]$File, [string]$Description)
    $fullPath = Join-Path $CollectDir $File
    if (Test-Path $fullPath) {
        $hash = (Get-FileHash -Path $fullPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $size = (Get-Item $fullPath).Length
        $Manifest.Add([PSCustomObject]@{
            Category    = $Category
            File        = $File
            Description = $Description
            SHA256      = $hash
            SizeBytes   = $size
            Collected   = $true
        })
    } else {
        $Manifest.Add([PSCustomObject]@{
            Category    = $Category
            File        = $File
            Description = $Description
            SHA256      = 'N/A'
            SizeBytes   = 0
            Collected   = $false
        })
    }
}

function Invoke-Collect {
    param(
        [string]$Category,
        [string]$RelativePath,
        [string]$Description,
        [scriptblock]$Action
    )
    $fullPath = Join-Path $CollectDir $RelativePath
    $dir = Split-Path $fullPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    try {
        & $Action | Out-File -FilePath $fullPath -Encoding UTF8 -Force
        Write-Log "Collected: $RelativePath"
    } catch {
        $msg = "FAILED [$RelativePath]: $($_.Exception.Message)"
        $Errors.Add($msg)
        Write-Log $msg -Level "WARN"
    }
    Add-Manifest -Category $Category -File $RelativePath -Description $Description
}

function Copy-Artifact {
    param(
        [string]$Category,
        [string]$Source,
        [string]$RelativeDest,
        [string]$Description
    )
    $fullDest = Join-Path $CollectDir $RelativeDest
    $dir = Split-Path $fullDest -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    try {
        Copy-Item -Path $Source -Destination $fullDest -Force -ErrorAction Stop
        Write-Log "Copied: $RelativeDest"
    } catch {
        # Try rawcopy method for locked files
        try {
            $reader = [System.IO.File]::Open($Source, 'Open', 'Read', 'ReadWrite')
            $writer = [System.IO.File]::Create($fullDest)
            $reader.CopyTo($writer)
            $writer.Close(); $reader.Close()
            Write-Log "Copied (raw): $RelativeDest"
        } catch {
            $msg = "FAILED COPY [$RelativeDest]: $($_.Exception.Message)"
            $Errors.Add($msg)
            Write-Log $msg -Level "WARN"
        }
    }
    Add-Manifest -Category $Category -File $RelativeDest -Description $Description
}

Write-Log "=== CrowdStrike RTR Forensic Collection ==="
Write-Log "Host      : $Hostname"
Write-Log "Output    : $ZipPath"
Write-Log "Collector : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Log "Start     : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Log ""

# Create directory structure
foreach ($d in $Dirs) {
    New-Item -ItemType Directory -Path (Join-Path $CollectDir $d) -Force | Out-Null
}

#endregion

#region ── System Information ─────────────────────────────────────────────────

Write-Log "--- System Information ---"

Invoke-Collect -Category 'System' -RelativePath 'system\systeminfo.txt' `
    -Description 'systeminfo output — OS, hardware, hotfixes, network config' `
    -Action { cmd /c systeminfo 2>&1 }

Invoke-Collect -Category 'System' -RelativePath 'system\hostname_ip.txt' `
    -Description 'Hostname, IP addresses, FQDN' `
    -Action {
        "Hostname: $env:COMPUTERNAME"
        "Domain  : $env:USERDOMAIN"
        ""
        ipconfig /all
    }

Invoke-Collect -Category 'System' -RelativePath 'system\installed_software.csv' `
    -Description 'Installed programs from registry (32-bit and 64-bit)' `
    -Action {
        $paths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
            Where-Object { $_.DisplayName } |
            Sort-Object DisplayName |
            ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'System' -RelativePath 'system\hotfixes.csv' `
    -Description 'Installed Windows patches and hotfixes' `
    -Action {
        Get-HotFix | Sort-Object InstalledOn -Descending |
            Select-Object HotFixID, Description, InstalledBy, InstalledOn |
            ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'System' -RelativePath 'system\environment_vars.txt' `
    -Description 'System and process environment variables' `
    -Action { Get-ChildItem Env: | Format-Table -AutoSize | Out-String }

Invoke-Collect -Category 'System' -RelativePath 'system\disk_info.txt' `
    -Description 'Disk volumes, sizes, and free space' `
    -Action {
        Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize | Out-String
        ""
        Get-Partition | Format-Table -AutoSize | Out-String
    }

Invoke-Collect -Category 'System' -RelativePath 'system\loaded_drivers.csv' `
    -Description 'Loaded kernel drivers' `
    -Action {
        Get-WmiObject Win32_SystemDriver |
            Select-Object Name, DisplayName, State, StartMode, PathName |
            Sort-Object State |
            ConvertTo-Csv -NoTypeInformation
    }

#endregion

#region ── Network State ──────────────────────────────────────────────────────

Write-Log "--- Network State ---"

Invoke-Collect -Category 'Network' -RelativePath 'network\netstat.txt' `
    -Description 'Active TCP/UDP connections with PIDs' `
    -Action { netstat -ano }

Invoke-Collect -Category 'Network' -RelativePath 'network\netstat_with_process.txt' `
    -Description 'Active connections resolved to process names' `
    -Action {
        $connections = netstat -ano | Select-Object -Skip 4
        $processes   = Get-Process | Group-Object Id -AsHashTable -AsString
        $connections | ForEach-Object {
            $parts = $_ -split '\s+' | Where-Object { $_ }
            if ($parts.Count -ge 5) {
                $pid = $parts[-1]
                $proc = if ($processes[$pid]) { $processes[$pid].Name } else { 'Unknown' }
                "$_ --> [$proc]"
            } else { $_ }
        }
    }

Invoke-Collect -Category 'Network' -RelativePath 'network\arp_cache.txt' `
    -Description 'ARP cache — recently seen MAC-to-IP mappings' `
    -Action { arp -a }

Invoke-Collect -Category 'Network' -RelativePath 'network\dns_cache.txt' `
    -Description 'DNS client resolver cache' `
    -Action {
        Get-DnsClientCache | Sort-Object TimeToLive -Descending |
            Format-Table -AutoSize | Out-String
    }

Invoke-Collect -Category 'Network' -RelativePath 'network\route_table.txt' `
    -Description 'IP routing table' `
    -Action { route print }

Invoke-Collect -Category 'Network' -RelativePath 'network\firewall_rules.csv' `
    -Description 'Windows Firewall rules (enabled rules only)' `
    -Action {
        Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
            Select-Object Name, DisplayName, Direction, Action, Profile, @{
                N='Program';E={ ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program }
            } |
            ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'Network' -RelativePath 'network\network_shares.txt' `
    -Description 'Active network shares (SMB)' `
    -Action { net share }

Invoke-Collect -Category 'Network' -RelativePath 'network\smb_sessions.txt' `
    -Description 'Active SMB sessions to this host' `
    -Action { net session }

Invoke-Collect -Category 'Network' -RelativePath 'network\hosts_file.txt' `
    -Description 'Windows hosts file — check for DNS poisoning or redirects' `
    -Action { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

#endregion

#region ── Processes and Services ─────────────────────────────────────────────

Write-Log "--- Processes and Services ---"

Invoke-Collect -Category 'Processes' -RelativePath 'processes\running_processes.csv' `
    -Description 'All running processes with path, hash, and parent PID' `
    -Action {
        Get-WmiObject Win32_Process | ForEach-Object {
            $hash = if (Test-Path $_.ExecutablePath) {
                (Get-FileHash $_.ExecutablePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            } else { 'N/A' }
            [PSCustomObject]@{
                PID             = $_.ProcessId
                ParentPID       = $_.ParentProcessId
                Name            = $_.Name
                ExecutablePath  = $_.ExecutablePath
                CommandLine     = $_.CommandLine
                SessionId       = $_.SessionId
                CreationDate    = $_.ConvertToDateTime($_.CreationDate)
                WorkingSetKB    = [math]::Round($_.WorkingSetSize / 1KB, 0)
                SHA256          = $hash
            }
        } | Sort-Object PID | ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'Processes' -RelativePath 'processes\process_tree.txt' `
    -Description 'Parent-child process tree' `
    -Action {
        $procs = Get-WmiObject Win32_Process
        $byId  = $procs | Group-Object ProcessId -AsHashTable -AsString
        function Show-Tree($pid, $depth = 0) {
            $p = $byId[$pid.ToString()]
            if (-not $p) { return }
            $p = $p | Select-Object -First 1
            $indent = "  " * $depth
            "${indent}[$($p.ProcessId)] $($p.Name)  |  $($p.CommandLine)"
            foreach ($child in $procs | Where-Object { $_.ParentProcessId -eq $pid }) {
                Show-Tree $child.ProcessId ($depth + 1)
            }
        }
        Show-Tree 0
    }

Invoke-Collect -Category 'Processes' -RelativePath 'processes\services.csv' `
    -Description 'All Windows services with state and binary path' `
    -Action {
        Get-WmiObject Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, PathName,
                StartName, Description |
            Sort-Object State, Name |
            ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'Processes' -RelativePath 'processes\dll_list.txt' `
    -Description 'Loaded modules for all running processes' `
    -Action {
        Get-Process | ForEach-Object {
            "=== PID: $($_.Id) | $($_.Name) ==="
            try {
                $_.Modules | Select-Object -ExpandProperty FileName
            } catch { "  [Access Denied]" }
            ""
        }
    }

#endregion

#region ── User Accounts and Sessions ────────────────────────────────────────

Write-Log "--- Users and Sessions ---"

Invoke-Collect -Category 'Users' -RelativePath 'users\local_users.txt' `
    -Description 'Local user accounts and properties' `
    -Action {
        Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet,
            PasswordExpires, Description -AutoSize | Out-String
    }

Invoke-Collect -Category 'Users' -RelativePath 'users\local_groups.txt' `
    -Description 'Local groups and members' `
    -Action {
        Get-LocalGroup | ForEach-Object {
            "=== $($_.Name) ==="
            Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue |
                Format-Table Name, ObjectClass, PrincipalSource -AutoSize | Out-String
            ""
        }
    }

Invoke-Collect -Category 'Users' -RelativePath 'users\logged_on_users.txt' `
    -Description 'Currently logged-on interactive sessions' `
    -Action {
        quser 2>&1
        ""
        "--- Logon Sessions (WMI) ---"
        Get-WmiObject Win32_LogonSession | ForEach-Object {
            $s = $_
            $users = Get-WmiObject Win32_LoggedOnUser | Where-Object { $_.Dependent -match "LogonId=`"$($s.LogonId)`"" }
            [PSCustomObject]@{
                LogonId    = $s.LogonId
                LogonType  = $s.LogonType
                StartTime  = $s.ConvertToDateTime($s.StartTime)
                User       = ($users | ForEach-Object { ($_.Antecedent -split '"')[1] }) -join '; '
            }
        } | Format-Table -AutoSize | Out-String
    }

Invoke-Collect -Category 'Users' -RelativePath 'users\user_profiles.txt' `
    -Description 'User profile paths and last use times' `
    -Action {
        Get-WmiObject Win32_UserProfile |
            Select-Object LocalPath, LastUseTime, Loaded, Special |
            Sort-Object LastUseTime -Descending |
            Format-Table -AutoSize | Out-String
    }

Invoke-Collect -Category 'Users' -RelativePath 'users\recent_logon_events.csv' `
    -Description 'Security event log: logon events (4624, 4625, 4648, 4672)' `
    -Action {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id      = @(4624, 4625, 4634, 4648, 4672, 4776)
        } -MaxEvents $MaxEventLogEntries -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated  = $_.TimeCreated
                EventId      = $_.Id
                Message      = $_.Message -replace "`r`n",' | '
                UserId       = $_.UserId
            }
        } | ConvertTo-Csv -NoTypeInformation
    }

#endregion

#region ── Persistence Mechanisms ────────────────────────────────────────────

Write-Log "--- Persistence ---"

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\run_keys.txt' `
    -Description 'HKLM and HKCU autorun registry keys' `
    -Action {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
            'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        )
        foreach ($key in $runKeys) {
            "=== $key ==="
            try {
                Get-ItemProperty $key -ErrorAction Stop |
                    Get-Member -MemberType NoteProperty |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        $val = (Get-ItemProperty $key -ErrorAction SilentlyContinue).($_.Name)
                        "  $($_.Name) = $val"
                    }
            } catch { "  [Not found or access denied]" }
            ""
        }
    }

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\scheduled_tasks.csv' `
    -Description 'All scheduled tasks with actions and triggers' `
    -Action {
        Get-ScheduledTask | ForEach-Object {
            $t = $_
            $info = Get-ScheduledTaskInfo $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                TaskName    = $t.TaskName
                TaskPath    = $t.TaskPath
                State       = $t.State
                Author      = $t.Author
                Description = $t.Description
                LastRunTime = $info.LastRunTime
                NextRunTime = $info.NextRunTime
                Actions     = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '
                Triggers    = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ' | '
            }
        } | ConvertTo-Csv -NoTypeInformation
    }

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\startup_folders.txt' `
    -Description 'Contents of all-users and per-user startup folders' `
    -Action {
        $startupPaths = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        # Also check all user profiles
        Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
            $startupPaths += "$($_.LocalPath)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        }
        foreach ($path in $startupPaths | Select-Object -Unique) {
            "=== $path ==="
            if (Test-Path $path) {
                Get-ChildItem $path -Force | Format-Table Name, LastWriteTime, Length -AutoSize | Out-String
            } else { "  [Not found]" }
            ""
        }
    }

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\image_file_execution_options.txt' `
    -Description 'IFEO debugger keys — used for accessibility backdoors (Utilman, sethc)' `
    -Action {
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $debugger = Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
            if ($debugger) {
                "$($_.PSChildName) --> Debugger: $($debugger.Debugger)"
            }
        }
    }

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\wmi_subscriptions.txt' `
    -Description 'WMI event subscriptions (filter + consumer + binding)' `
    -Action {
        "=== Filters ==="
        Get-WmiObject -Namespace root\subscription -Class __EventFilter |
            Select-Object Name, Query, QueryLanguage | Format-List | Out-String
        "=== Consumers ==="
        Get-WmiObject -Namespace root\subscription -Class __EventConsumer |
            Select-Object * | Format-List | Out-String
        "=== Bindings ==="
        Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
            Format-List | Out-String
    }

Invoke-Collect -Category 'Persistence' -RelativePath 'persistence\com_hijack_check.txt' `
    -Description 'HKCU COM object overrides — COM hijacking indicators' `
    -Action {
        $hkcuCLSID = 'HKCU:\Software\Classes\CLSID'
        if (Test-Path $hkcuCLSID) {
            Get-ChildItem $hkcuCLSID -ErrorAction SilentlyContinue |
                ForEach-Object { "$($_.PSPath)" }
        } else { "[No HKCU CLSID overrides found]" }
    }

#endregion

#region ── Event Logs ─────────────────────────────────────────────────────────

Write-Log "--- Event Logs ---"

# CSV exports of key event channels
$EventChannels = @(
    @{ Name='Security';          Path='logs\security_events.csv';     Ids=@(4624,4625,4634,4647,4648,4656,4657,4663,4672,4688,4697,4698,4699,4700,4701,4702,4720,4722,4724,4732,4740,4756,4776,7045) }
    @{ Name='System';            Path='logs\system_events.csv';       Ids=@(7034,7036,7040,7045,104) }
    @{ Name='Application';       Path='logs\application_events.csv';  Ids=$null }
    @{ Name='Microsoft-Windows-PowerShell/Operational'; Path='logs\powershell_events.csv'; Ids=@(4103,4104,4105,4106) }
    @{ Name='Microsoft-Windows-Sysmon/Operational';     Path='logs\sysmon_events.csv';     Ids=$null }
    @{ Name='Microsoft-Windows-TaskScheduler/Operational'; Path='logs\taskscheduler_events.csv'; Ids=@(106,140,141,200,201) }
)

foreach ($channel in $EventChannels) {
    $relPath = $channel.Path
    $fullPath = Join-Path $CollectDir $relPath
    $filter = @{ LogName = $channel.Name }
    if ($channel.Ids) { $filter['Id'] = $channel.Ids }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventLogEntries -ErrorAction Stop |
            ForEach-Object {
                [PSCustomObject]@{
                    TimeCreated  = $_.TimeCreated
                    EventId      = $_.Id
                    Level        = $_.LevelDisplayName
                    ProviderName = $_.ProviderName
                    Message      = ($_.Message -replace "`r`n",' | ') -replace '"','`"'
                    UserId       = $_.UserId
                    MachineName  = $_.MachineName
                }
            } | ConvertTo-Csv -NoTypeInformation

        $events | Out-File -FilePath $fullPath -Encoding UTF8 -Force
        Write-Log "Collected: $relPath"
    } catch {
        "[No events or channel not found: $($channel.Name)]" | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "No data for log channel: $($channel.Name)" -Level "INFO"
    }
    Add-Manifest -Category 'Logs' -File $relPath -Description "Event log CSV: $($channel.Name)"
}

# Copy raw EVTX files
if ($IncludeEventLogs) {
    $evtxChannels = @(
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Security.evtx";           Dest='logs\Security.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\System.evtx";             Dest='logs\System.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Application.evtx";        Dest='logs\Application.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"; Dest='logs\PowerShell-Operational.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"; Dest='logs\Sysmon-Operational.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx"; Dest='logs\TaskScheduler-Operational.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx"; Dest='logs\WinRM-Operational.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"; Dest='logs\RDP-LocalSession.evtx' }
        @{ Source="$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx"; Dest='logs\RDP-Core.evtx' }
    )
    foreach ($evtx in $evtxChannels) {
        if (Test-Path $evtx.Source) {
            Copy-Artifact -Category 'Logs' -Source $evtx.Source `
                -RelativeDest $evtx.Dest -Description "EVTX: $($evtx.Dest)"
        }
    }
}

#endregion

#region ── File System Artifacts ─────────────────────────────────────────────

Write-Log "--- File System Artifacts ---"

Invoke-Collect -Category 'Files' -RelativePath 'files\prefetch_list.txt' `
    -Description 'Prefetch files — recently executed programs (last 128)' `
    -Action {
        $prefetchDir = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchDir) {
            Get-ChildItem $prefetchDir -Filter '*.pf' |
                Sort-Object LastWriteTime -Descending |
                Select-Object Name, LastWriteTime, Length |
                Format-Table -AutoSize | Out-String
        } else { "[Prefetch disabled or inaccessible]" }
    }

# Copy prefetch files
$prefetchDest = Join-Path $CollectDir 'files\prefetch'
New-Item -ItemType Directory -Path $prefetchDest -Force | Out-Null
$pfFiles = Get-ChildItem "$env:SystemRoot\Prefetch" -Filter '*.pf' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 128
foreach ($pf in $pfFiles) {
    Copy-Artifact -Category 'Files' -Source $pf.FullName `
        -RelativeDest "files\prefetch\$($pf.Name)" `
        -Description "Prefetch: $($pf.Name)"
}
Write-Log "Copied $($pfFiles.Count) prefetch files"

Invoke-Collect -Category 'Files' -RelativePath 'files\temp_recent_files.txt' `
    -Description 'Recently modified files in TEMP directories (last 200)' `
    -Action {
        $tempPaths = @($env:TEMP, $env:TMP, "$env:SystemRoot\Temp", "C:\Windows\Temp")
        # Also check user temp dirs
        Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
            $tempPaths += "$($_.LocalPath)\AppData\Local\Temp"
        }
        foreach ($tp in $tempPaths | Select-Object -Unique) {
            if (Test-Path $tp) {
                "=== $tp ==="
                Get-ChildItem $tp -Recurse -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 100 |
                    Select-Object FullName, LastWriteTime, Length |
                    Format-Table -AutoSize | Out-String
            }
        }
    }

Invoke-Collect -Category 'Files' -RelativePath 'files\recently_modified_executables.txt' `
    -Description 'PE files (EXE/DLL/PS1) modified in the last 30 days in user-writable paths' `
    -Action {
        $cutoff = (Get-Date).AddDays(-30)
        $searchPaths = @("C:\Users","C:\ProgramData","$env:SystemRoot\Temp")
        foreach ($sp in $searchPaths) {
            "=== $sp ==="
            Get-ChildItem $sp -Recurse -File -Include @('*.exe','*.dll','*.ps1','*.bat','*.vbs','*.js','*.hta') `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 200 |
                Select-Object FullName, LastWriteTime, Length |
                Format-Table -AutoSize | Out-String
        }
    }

Invoke-Collect -Category 'Files' -RelativePath 'files\lnk_recent_files.txt' `
    -Description 'LNK (shortcut) files from all user Recent folders — recently opened files' `
    -Action {
        Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
            $recentPath = "$($_.LocalPath)\AppData\Roaming\Microsoft\Windows\Recent"
            if (Test-Path $recentPath) {
                "=== $recentPath ==="
                Get-ChildItem $recentPath -File |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 100 |
                    Select-Object Name, LastWriteTime |
                    Format-Table -AutoSize | Out-String
            }
        }
    }

Invoke-Collect -Category 'Files' -RelativePath 'files\downloads_folders.txt' `
    -Description 'Contents of all user Downloads folders (last 60 days)' `
    -Action {
        $cutoff = (Get-Date).AddDays(-60)
        Get-WmiObject Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
            $dlPath = "$($_.LocalPath)\Downloads"
            if (Test-Path $dlPath) {
                "=== $dlPath ==="
                Get-ChildItem $dlPath -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoff } |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object FullName, LastWriteTime, Length |
                    Format-Table -AutoSize | Out-String
            }
        }
    }

#endregion

#region ── Registry Exports ───────────────────────────────────────────────────

Write-Log "--- Registry Exports ---"

$RegExports = @(
    @{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';        File='registry\run_hklm.reg' }
    @{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';    File='registry\runonce_hklm.reg' }
    @{ Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';        File='registry\run_hkcu.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Services';                    File='registry\services.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR';                File='registry\usb_history.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Enum\USB';                    File='registry\usb_devices.reg' }
    @{ Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'; File='registry\typed_paths.reg' }
    @{ Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'; File='registry\recent_docs.reg' }
    @{ Key='HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU';     File='registry\run_mru.reg' }
    @{ Key='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; File='registry\ifeo.reg' }
    @{ Key='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels';     File='registry\evtx_channels.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Lsa';                 File='registry\lsa_settings.reg' }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell';       File='registry\ps_policy.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'; File='registry\shimcache.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation';  File='registry\timezone.reg' }
    @{ Key='HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers';     File='registry\rdp_mru.reg' }
    @{ Key='HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'; File='registry\bam_dam.reg' }
)

foreach ($export in $RegExports) {
    $fullDest = Join-Path $CollectDir $export.File
    $dir = Split-Path $fullDest -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        reg export $export.Key $fullDest /y 2>&1 | Out-Null
        Write-Log "Registry export: $($export.File)"
    } catch {
        $Errors.Add("FAILED registry export: $($export.Key)")
    }
    Add-Manifest -Category 'Registry' -File $export.File -Description "Registry export: $($export.Key)"
}

# AmCache hive (execution evidence)
Invoke-Collect -Category 'Registry' -RelativePath 'registry\amcache_info.txt' `
    -Description 'AmCache recently executed applications (from hive if accessible)' `
    -Action {
        $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
        if (Test-Path $amcachePath) {
            "AmCache hive found at: $amcachePath"
            "File size: $((Get-Item $amcachePath).Length) bytes"
            "Last modified: $((Get-Item $amcachePath).LastWriteTime)"
            ""
            "Note: Full AmCache parsing requires offline analysis tools (RegRipper, AmcacheParser)"
        } else { "[AmCache.hve not found]" }
    }

Copy-Artifact -Category 'Registry' `
    -Source "$env:SystemRoot\AppCompat\Programs\Amcache.hve" `
    -RelativeDest 'registry\Amcache.hve' `
    -Description 'AmCache hive — recently executed application history'

#endregion

#region ── Browser Artifacts ─────────────────────────────────────────────────

if ($IncludeBrowserArtifacts) {
    Write-Log "--- Browser Artifacts ---"

    $UserProfiles = Get-WmiObject Win32_UserProfile |
        Where-Object { -not $_.Special -and (Test-Path $_.LocalPath) } |
        Select-Object -ExpandProperty LocalPath

    $BrowserPaths = @{
        'Chrome'  = @{
            History     = 'AppData\Local\Google\Chrome\User Data\Default\History'
            Downloads   = 'AppData\Local\Google\Chrome\User Data\Default\History'
            Cookies     = 'AppData\Local\Google\Chrome\User Data\Default\Cookies'
            Extensions  = 'AppData\Local\Google\Chrome\User Data\Default\Extensions'
        }
        'Edge'    = @{
            History     = 'AppData\Local\Microsoft\Edge\User Data\Default\History'
            Cookies     = 'AppData\Local\Microsoft\Edge\User Data\Default\Cookies'
        }
        'Firefox' = @{
            ProfileRoot = 'AppData\Roaming\Mozilla\Firefox\Profiles'
        }
    }

    foreach ($profile in $UserProfiles) {
        $username = Split-Path $profile -Leaf

        # Chrome / Edge
        foreach ($browser in @('Chrome','Edge')) {
            foreach ($artifact in $BrowserPaths[$browser].GetEnumerator()) {
                $src = Join-Path $profile $artifact.Value
                if (Test-Path $src) {
                    Copy-Artifact -Category 'Browser' `
                        -Source $src `
                        -RelativeDest "browser\${username}_${browser}_$($artifact.Key)" `
                        -Description "$browser $($artifact.Key) DB for $username"
                }
            }
        }

        # Firefox (profile-based)
        $ffRoot = Join-Path $profile $BrowserPaths['Firefox'].ProfileRoot
        if (Test-Path $ffRoot) {
            Get-ChildItem $ffRoot -Directory | ForEach-Object {
                $ffProfile = $_.FullName
                foreach ($dbFile in @('places.sqlite','cookies.sqlite','downloads.sqlite','formhistory.sqlite')) {
                    $src = Join-Path $ffProfile $dbFile
                    if (Test-Path $src) {
                        Copy-Artifact -Category 'Browser' `
                            -Source $src `
                            -RelativeDest "browser\${username}_Firefox_$($_.Name)_${dbFile}" `
                            -Description "Firefox $dbFile for $username"
                    }
                }
            }
        }
    }
}

#endregion

#region ── Chain of Custody Manifest ─────────────────────────────────────────

Write-Log "--- Generating Manifest ---"

$EndTime    = Get-Date
$Duration   = ($EndTime - $StartTime).TotalSeconds

# Collection summary header
$summaryPath = Join-Path $CollectDir '00_collection_manifest.txt'
@"
================================================================
  CROWDSTRIKE RTR FORENSIC COLLECTION — CHAIN OF CUSTODY
================================================================
Hostname         : $Hostname
FQDN             : $($env:COMPUTERNAME).$($env:USERDNSDOMAIN)
Collector        : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Collection Start : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC
Collection End   : $($EndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC
Duration (sec)   : $([math]::Round($Duration, 1))
Total Artifacts  : $($Manifest.Count)
Failed           : $($Manifest | Where-Object { -not $_.Collected } | Measure-Object | Select-Object -Expand Count)
Output Directory : $CollectDir
ZIP File         : $ZipPath

OS Information:
$((Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption) 2>&1)
Version: $([System.Environment]::OSVersion.VersionString)
Install Date: $((Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate))

================================================================
  COLLECTION ERRORS ($($Errors.Count))
================================================================
$($Errors | ForEach-Object { "  - $_" } | Out-String)

================================================================
  ARTIFACT MANIFEST (SHA256 HASHES)
================================================================
"@ | Out-File -FilePath $summaryPath -Encoding UTF8

$Manifest | Format-Table -AutoSize | Out-String |
    Out-File -FilePath $summaryPath -Encoding UTF8 -Append

# CSV version for easier parsing
$Manifest | ConvertTo-Csv -NoTypeInformation |
    Out-File -FilePath (Join-Path $CollectDir '00_manifest.csv') -Encoding UTF8

Write-Log "Manifest written"

#endregion

#region ── Zip and Cleanup ────────────────────────────────────────────────────

Write-Log "--- Compressing Collection ---"

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $CollectDir,
        $ZipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $true  # include base dir in zip
    )
    $zipSize = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)
    Write-Log "ZIP created: $ZipPath ($zipSize MB)"
} catch {
    Write-Log "ZIP creation failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Artifacts remain unzipped in: $CollectDir" -Level "WARN"
}

# Remove unzipped directory to save disk space (ZIP is the deliverable)
if (Test-Path $ZipPath) {
    Remove-Item -Path $CollectDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Cleaned up staging directory"
}

#endregion

Write-Log ""
Write-Log "=== Collection Complete ==="
Write-Log "Duration : $([math]::Round($Duration,1)) seconds"
Write-Log "Output   : $ZipPath"
Write-Log ""
Write-Log "Download with RTR command:"
Write-Log "  get `"$ZipPath`""
