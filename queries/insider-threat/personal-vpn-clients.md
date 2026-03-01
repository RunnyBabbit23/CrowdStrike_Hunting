# Personal VPN Client Usage on Corporate Endpoints

## Description

Detects personal VPN client software installed and running on corporate endpoints — used by insiders and attackers to tunnel traffic outside corporate proxy and DLP inspection, encrypt outbound connections to hide destination sites, and bypass network-level monitoring. Popular personal VPN clients include Mullvad, ProtonVPN, NordVPN, ExpressVPN, and WireGuard clients configured to non-corporate endpoints. This is distinct from authorized corporate VPN (GlobalProtect, Cisco AnyConnect, Pulse Secure).

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Tactic** | Defense Evasion / Exfiltration |
| **Technique** | T1090.002 — Proxy: External Proxy |
| **Sub-technique** | T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |

## Data Source

| Field | Value |
|---|---|
| **Sensor** | Endpoint EDR |
| **Repository** | `base_sensor_activity` |
| **Event Types** | `ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest` |

## Severity

**Medium** — Personal VPN bypasses corporate monitoring; elevated to High when combined with data staging, after-hours access, or other insider threat signals.

## Query

```logscale
// Personal VPN client process execution
#event_simpleName=ProcessRollup2
| in(FileName, values=[
    "mullvad-vpn.exe", "mullvad.exe",
    "ProtonVPN.exe", "ProtonVPNService.exe",
    "NordVPN.exe", "NordVPNService.exe",
    "ExpressVPN.exe", "ExpressVPNService.exe",
    "Surfshark.exe", "SurfsharkService.exe",
    "CyberGhostVPN.exe",
    "PIA.exe", "pia-client.exe",
    "windscribe.exe", "WindscribeService.exe",
    "TunnelBear.exe",
    "HotspotShield.exe",
    "hide.me.exe",
    "AirVPN.exe",
    "IVPN.exe",
    "WireGuard.exe"
  ])
| FileName!=/GlobalProtect|AnyConnect|PulseSecure|FortiClient|ZscalerApp|Cisco.*VPN/i
| table([ComputerName, UserName, FileName, FilePath, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: WireGuard connections to non-corporate endpoints**

```logscale
// WireGuard UDP connections to external IPs — personal WireGuard config (not corporate)
#event_simpleName=NetworkConnectIP4
| FileName=/wireguard\.exe/i
| RemotePort=51820
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| table([ComputerName, UserName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: OpenVPN client connecting to non-corporate servers**

```logscale
// OpenVPN process making external connections — personal config or unauthorized VPN
#event_simpleName=NetworkConnectIP4
| FileName=/(openvpn|openvpn-gui)\.exe/i
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/
| RemoteAddressIP4!=/your\.corporate\.vpn\.ip/
| table([ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, @timestamp], limit=200)
```

**Variant: Personal VPN DNS queries**

```logscale
// DNS to known personal VPN provider infrastructure
#event_simpleName=DnsRequest
| DomainName=/(
    mullvad\.net|
    protonvpn\.com|proton\.me|
    nordvpn\.com|
    expressvpn\.com|
    surfshark\.com|
    cyberghostvpn\.com|
    privateinternetaccess\.com|pia\.com|
    windscribe\.com|
    tunnelbear\.com|
    hotspotshield\.com|
    hide\.me|
    airvpn\.org|
    ivpn\.net|
    vpnunlimited\.com|
    vyprvpn\.com|
    purevpn\.com
  )/i
| table([ComputerName, UserName, DomainName, @timestamp], limit=500)
```

**Variant: VPN software installation**

```logscale
// Installer for personal VPN software executed
#event_simpleName=ProcessRollup2
| FileName=/(mullvad|nordvpn|expressvpn|protonvpn|surfshark|cyberghost|windscribe|tunnelbear|wireguard).*(setup|install|installer|_x64|_x86)/i
| table([ComputerName, UserName, FileName, CommandLine, ParentBaseFileName, @timestamp], limit=200)
```

**Variant: Network adapter creation (VPN TAP/TUN interface)**

```logscale
// New virtual network adapter driver loaded — may indicate VPN TAP adapter installation
#event_simpleName=DriverLoad
| FileName=/(tap0901|tapoas|wintun|ovpn|wireguard|nordvpntap)/i
| table([ComputerName, UserName, FileName, FilePath, @timestamp], limit=200)
```

## Response Notes

**Triage steps:**
1. Confirm whether the VPN software is authorized — some organizations allow VPN for specific roles; check approved software list
2. Review the timing relative to other suspicious activity — VPN activation immediately before bulk file access or cloud uploads is the key correlation
3. When VPN is active, outbound traffic attribution becomes difficult — focus on activity before VPN activation and immediately after VPN disconnect
4. Check if the VPN was installed via a user-initiated installer (`ParentBaseFileName=chrome.exe` or `MicrosoftEdge.exe`) or pre-existed on the system
5. For WireGuard specifically: check if the configuration file was recently created or modified — WireGuard configs may reveal the remote server

**False positives:**
- Security researchers and penetration testers use personal VPNs for operational purposes — validate with the security team
- Privacy-conscious employees may use personal VPNs for non-work traffic — policy violation but not malicious
- Remote workers may use personal VPNs to protect home network traffic before corporate VPN — common and usually benign
- Authorized corporate VPNs (GlobalProtect, AnyConnect, Zscaler) should be excluded from this hunt

## References

- https://attack.mitre.org/techniques/T1090/002/
- https://www.crowdstrike.com/blog/network-monitoring-vpn-detection/
