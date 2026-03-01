# Shadow Copy and Backup Deletion

## Description

Detects deletion of Volume Shadow Copies (VSS) and backup catalogs — a nearly universal ransomware pre-encryption step designed to prevent victims from recovering files without paying the ransom. Common methods include `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set recoveryenabled no`, and `wbadmin delete catalog`. This behavior is seen across virtually all modern ransomware families including LockBit, BlackCat (ALPHV), Cl0p, and Ryuk.

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Impact |
| **Technique** | T1490 — Inhibit System Recovery |
| **Sub-technique** | VSS deletion, backup destruction |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2` |

## Severity

**High** — Shadow copy deletion is a critical, near-certain ransomware indicator. Treat as a P1 incident.

## Query

```logscale
// VSS and backup deletion — comprehensive coverage of common methods
#event_simpleName=ProcessRollup2
| CommandLine=/(
    vssadmin.*delete.*shadows|
    vssadmin.*resize.*shadowstorage|
    wmic.*shadowcopy.*delete|
    wmic.*shadowcopy.*where.*delete|
    bcdedit.*(recoveryenabled.*no|bootstatuspolicy.*ignoreallfailures)|
    wbadmin.*delete.*(catalog|backup|systemstatebackup)|
    del.*\\\\.\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy|
    powershell.*Win32_ShadowCopy.*Delete|
    diskshadow.*delete|
    ntdsutil.*ifm.*create
  )/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Boot recovery disabled via bcdedit**

```logscale
// Disable Windows recovery — prevents booting to recovery environment
#event_simpleName=ProcessRollup2
| FileName=bcdedit.exe
| CommandLine=/(recoveryenabled.*no|bootstatuspolicy|safeboot|noeventlog)/i
| table([ComputerName, UserName, CommandLine, ParentBaseFileName], limit=200)
```

**Variant: Firewall and AV disabled before encryption**

```logscale
// Security tool disabling — common ransomware pre-encryption step
#event_simpleName=ProcessRollup2
| in(FileName, values=["netsh.exe", "sc.exe", "taskkill.exe", "wmic.exe"])
| CommandLine=/(
    netsh.*firewall.*set.*opmode.*disable|
    netsh.*advfirewall.*allprofiles.*state.*off|
    sc.*stop.*(windefend|mssense|sense|wscsvc|wsatpbroker)|
    taskkill.*\/(MDS|CylanceSvc|bdagent|MBAMService|ekrn|fshoster)|
    wmic.*antivirus.*delete
  )/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=200)
```

## Response Notes

**Triage steps:**
1. **Immediately isolate the host** — if shadow copies are being deleted, encryption may be imminent or already in progress
2. Check if this is the only affected host or if lateral movement preceded this — pivot on `UserName` credentials used
3. Identify the parent process — ransomware typically runs as a standalone binary; check for dropped PEs in temp directories
4. Notify IR team immediately — SLA from shadow copy deletion to encryption completion is often under 10 minutes
5. Attempt to take a snapshot of remaining VSS copies on other systems before they're reached

**False positives:**
- Disk cleanup utilities may delete old shadow copies for space management — but should not disable recovery
- Some backup solutions rotate VSS copies — verify the initiating process and user account
- The `bcdedit` and firewall disable variants have very low false positive rates

## References

- https://attack.mitre.org/techniques/T1490/
- https://www.crowdstrike.com/blog/ransomware-hunting-with-crowdstrike-falcon/
- https://redcanary.com/threat-detection-report/trends/ransomware/
