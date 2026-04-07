# Switch Security Audit Report

| Field | Value |
|-------|-------|
| Target | `devnetsandboxiosxec9k.cisco.com` |
| Device OS | Cisco IOS XE 17.15.1 / C9KV-UADP-8P |
| Audit started | 2026-04-07T13:48:14.949143+00:00 |
| Report generated | 2026-04-07 14:01 UTC |
| Trials executed | 20 |
| Commands executed | 20 |

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 2 |
| 🟠 High | 3 |
| 🟡 Medium | 4 |
| 🟢 Low | 0 |
| **Total chains** | **9** |
| Confirmed chains | 8 |
| Facts extracted | 69 |

---

## Recovered Credentials

> **Note**: Type 7 is NOT encryption. Any attacker with config access can decode these instantly.

| Plaintext Password | Original Ciphertext | Found In |
|-------------------|---------------------|----------|
| `C1sco12345` | `password 7 013057175804575D72181B` | `show running-config` |
| `C1sco12345` | `password 7 096F1F1A1A0A4640585851` | `show running-config` |
| `isecat8k` | `key 7 12101612110A185C21` | `show running-config` |

---

## Attack Chains

### [CRITICAL] Reversible Passwords → Unrestricted HTTP/HTTPS Admin Access

- **ID**: `c1-0`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) decode the Type 7 enable password from the running config → 2) authenticate to the HTTP management interface on port 80 (or supplementary port 21111) using the 'enable' authentication method → 3) gain full device administrative access via the web interface, which has no source IP restrictions.

**Supporting facts**

- `f1-0` (show running-config): Enable password is encoded with Type 7 reversible encryption.
  > `enable password 7 013057175804575D72181B`
- `f1-1` (show running-config): Username 'admin' with privilege level 15 has a password encoded with Type 7 reversible encryption.
  > `username admin privilege 15 password 7 096F1F1A1A0A4640585851`
- `f1-3` (show running-config): HTTP server is enabled (`ip http server` present).
  > `ip http server`
- `f1-4` (show running-config): HTTPS server is enabled (`ip http secure-server` present).
  > `ip http secure-server`
- `f1-5` (show running-config): No `ip http access-class` is configured.
  > `ip http server  ip http secure-server`
- `f2-0` (show ip http server status): HTTP server authentication method is set to 'enable'.
  > `HTTP server authentication method: enable`
- `f2-1` (show ip http server status): HTTP server has no IPv4 access class configured.
  > `HTTP server IPv4 access class: None`
- `f2-2` (show ip http server status): HTTP server has no IPv6 access class configured.
  > `HTTP server IPv6 access class: None`

---

### [CRITICAL] Reversible Password → SSH Brute-Force or Decoded Login

- **ID**: `c8-0`
- **Confidence**: confirmed
- **First seen**: trial 8

**Attack narrative**

Attacker can: 1) decode the Type 7 enable password and/or admin user password from the running config → 2) use the decoded credentials to authenticate via SSH (version 2.0, password authentication enabled) → 3) gain full administrative access to the device.

**Supporting facts**

- `f1-0` (show running-config): Enable password is encoded with Type 7 reversible encryption.
  > `enable password 7 013057175804575D72181B`
- `f1-1` (show running-config): Username 'admin' with privilege level 15 has a password encoded with Type 7 reversible encryption.
  > `username admin privilege 15 password 7 096F1F1A1A0A4640585851`
- `f8-0` (show ip ssh): SSH version 2.0 is enabled.
  > `SSH Enabled - version 2.0`
- `f8-1` (show ip ssh): SSH authentication methods include password.
  > `Authentication methods:publickey,keyboard-interactive,password`

---

### [HIGH] Reversible TACACS+ Key → AAA Bypass & Credential Theft

- **ID**: `c1-1`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) decode the Type 7 TACACS+ shared secret from the running config → 2) intercept or spoof traffic to the live TACACS+ server at 10.17.248.43 → 3) forge valid authentication responses or decrypt credentials in transit, bypassing AAA controls.

**Supporting facts**

- `f1-2` (show running-config): TACACS+ server key is encoded with Type 7 reversible encryption.
  > `key 7 12101612110A185C21`
- `f3-0` (show aaa servers): No AAA servers (RADIUS/TACACS+) are configured.
  > `(empty output)`
- `f4-0` (show tacacs): A TACACS+ server is configured and reachable (status: Alive).
  > `Server address: 10.17.248.43               Server Status: Alive`

---

### [HIGH] Missing BPDU Guard → STP Manipulation & Network Disruption

- **ID**: `c1-3`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) Connect a rogue switch to an access port (e.g., Gi1/0/1) → 2) Since no spanning tree instance exists, the attacker's switch can immediately become the root bridge without BPDU Guard to block it → 3) Redirect or disrupt network traffic across the switched infrastructure.

**Supporting facts**

- `f1-10` (show running-config): Spanning-tree mode is set to rapid-pvst (`spanning-tree mode rapid-pvst`).
  > `spanning-tree mode rapid-pvst`
- `f1-11` (show running-config): No `spanning-tree portfast bpduguard default` is configured.
  > `spanning-tree mode rapid-pvst  spanning-tree extend system-id`
- `f5-0` (show spanning-tree summary): PortFast BPDU Guard Default is disabled globally.
  > `PortFast BPDU Guard Default            is disabled`
- `f6-0` (show spanning-tree detail): No spanning tree instance exists on the device.
  > `No spanning tree instance exists.`

---

### [HIGH] Missing DHCP Snooping → Rogue DHCP Server Attack

- **ID**: `c16-0`
- **Confidence**: confirmed
- **First seen**: trial 16

**Attack narrative**

Attacker can: 1) connect an unauthorized device to an access port (f1-13, f7-0) → 2) deploy a rogue DHCP server to assign malicious IP/gateway settings to clients (f16-0, f16-1, f16-2) → 3) perform ARP spoofing/man-in-the-middle attacks without detection, as Dynamic ARP Inspection (DAI) is completely disabled (f18-0) and all validation checks are off (f18-1, f18-2, f18-3) → 4) intercept and manipulate client traffic, leading to credential theft or network disruption.

**Supporting facts**

- `f16-0` (show ip dhcp snooping): DHCP snooping is disabled globally.
  > `Switch DHCP snooping is disabled`
- `f16-1` (show ip dhcp snooping): DHCP snooping is not configured on any VLANs.
  > `DHCP snooping is configured on following VLANs:  none`
- `f16-2` (show ip dhcp snooping): DHCP snooping is not operational on any VLANs.
  > `DHCP snooping is operational on following VLANs:  none`
- `f16-3` (show ip dhcp snooping): No interfaces are configured as DHCP snooping trusted.
  > `Interface                  Trusted    Allow option    Rate limit (pps)  -----------------------    -------    ------------    ----------------`
- `f13-0` (show vlan brief): VLAN 1 (default) is active and includes multiple access ports.
  > `1    default                          active    Gi1/0/2, Gi1/0/3, Gi1/0/4, Gi1/0/5, Gi1/0/6, Gi1/0/7, Gi1/0/8`
- `f13-1` (show vlan brief): VLAN 10 is active and includes access port GigabitEthernet1/0/1.
  > `10   VLAN0010                         active    Gi1/0/1`
- `f14-0` (show interfaces switchport): Interface GigabitEthernet1/0/1 is administratively configured as an access port for VLAN 10.
  > `Name: Gi1/0/1  Access Mode VLAN: 10 (VLAN0010)`
- `f14-4` (show interfaces switchport): Interfaces GigabitEthernet1/0/2 through GigabitEthernet1/0/8 are administratively configured as access ports for VLAN 1 (default).
  > `Name: Gi1/0/2  Access Mode VLAN: 1 (default)  Name: Gi1/0/3`
- `f17-0` (show ip dhcp snooping binding): DHCP snooping binding table is empty (no learned IP-MAC-port bindings).
  > `Total number of bindings: 0`
- `f18-0` (show ip arp inspection): Dynamic ARP Inspection (DAI) is disabled globally (no active or enabled VLANs).
  > `No active or enabled vlans on switch.`
- `f18-1` (show ip arp inspection): Source MAC validation for ARP packets is disabled.
  > `Source Mac Validation      : Disabled`
- `f18-2` (show ip arp inspection): Destination MAC validation for ARP packets is disabled.
  > `Destination Mac Validation : Disabled`
- `f18-3` (show ip arp inspection): IP address validation for ARP packets is disabled.
  > `IP Address Validation      : Disabled`

---

### [MEDIUM] Missing Session Timeout → Post-Compromise Persistence

- **ID**: `c1-2`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) decode the Type 7 enable password (f1-0) or admin password (f1-1) → 2) authenticate via SSH (f1-6, f9-0) → 3) establish a VTY session with no exec-timeout (f1-7, f1-8, f9-1), allowing indefinite persistence even if the attacker's initial access point is lost. The presence of active sessions (f10-1) and historical usage (f10-0) demonstrates the VTY lines are in use.

**Supporting facts**

- `f1-6` (show running-config): VTY lines 0-4 and 5-15 are configured with `transport input ssh`.
  > `line vty 0 4   transport input ssh  line vty 5 15`
- `f1-7` (show running-config): No `exec-timeout` is configured on VTY lines 0-4.
  > `line vty 0 4   transport input ssh`
- `f1-8` (show running-config): No `exec-timeout` is configured on VTY lines 5-15.
  > `line vty 5 15   transport input ssh`
- `f9-1` (show line vty 0 15): No `exec-timeout` is configured on VTY lines 0-15.
  > `1 VTY              -    -      -    -    -    174       0     0/0       -`
- `f10-0` (show line vty 0 4): VTY lines 1-5 have been used for remote sessions (Uses count > 0).
  > `*     1 VTY              -    -      -    -    -    176       0     0/0       -`
- `f10-1` (show line vty 0 4): VTY line 1 is currently active (asterisk in first column).
  > `*     1 VTY              -    -      -    -    -    176       0     0/0       -`

---

### [MEDIUM] Missing Port Security → MAC Flooding & Unauthorized Access

- **ID**: `c1-4`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) connect an unauthorized device to an access port (e.g., Gi1/0/1) → 2) flood the switch with spoofed MAC addresses to overflow the CAM table (no storm control to limit traffic) → 3) cause the switch to fail-open, flooding traffic to all ports → 4) perform packet sniffing or man-in-the-middle attacks on VLAN 1 or VLAN 10 traffic.

**Supporting facts**

- `f1-12` (show running-config): Interface GigabitEthernet1/0/1 is configured as an access port for VLAN 10 (`switchport access vlan 10`).
  > `interface GigabitEthernet1/0/1   switchport access vlan 10   shutdown`
- `f1-13` (show running-config): No `switchport port-security` is configured on access port GigabitEthernet1/0/1.
  > `interface GigabitEthernet1/0/1   switchport access vlan 10   shutdown`
- `f7-0` (show port-security): No ports have port security enabled.
  > `---------------------------------------------------------------------------  ---------------------------------------------------------------------------`
- `f7-1` (show port-security): Total learned secure MAC addresses in the system is zero.
  > `Total Addresses in System (excluding one mac per port)     : 0`
- `f13-0` (show vlan brief): VLAN 1 (default) is active and includes multiple access ports.
  > `1    default                          active    Gi1/0/2, Gi1/0/3, Gi1/0/4, Gi1/0/5, Gi1/0/6, Gi1/0/7, Gi1/0/8`
- `f13-1` (show vlan brief): VLAN 10 is active and includes access port GigabitEthernet1/0/1.
  > `10   VLAN0010                         active    Gi1/0/1`
- `f14-0` (show interfaces switchport): Interface GigabitEthernet1/0/1 is administratively configured as an access port for VLAN 10.
  > `Name: Gi1/0/1  Access Mode VLAN: 10 (VLAN0010)`
- `f14-4` (show interfaces switchport): Interfaces GigabitEthernet1/0/2 through GigabitEthernet1/0/8 are administratively configured as access ports for VLAN 1 (default).
  > `Name: Gi1/0/2  Access Mode VLAN: 1 (default)  Name: Gi1/0/3`
- `f15-0` (show mac address-table): A static MAC address entry for 0050.56bf.2919 is bound to VLAN 1 interface Vlan1.
  > `1    0050.56bf.2919    STATIC      Vl1`
- `f15-1` (show mac address-table): No dynamic MAC address entries are present in the MAC address table.
  > `Total Mac Addresses for this criterion: 22`
- `f19-0` (show storm-control): No storm control is configured on any interface.
  > `Interface       Filter State   Upper        Lower        Current         Action     Type  ---------       -------------  -----------  -----------  -------------   ---------  ----`

---

### [MEDIUM] Unauthenticated NTP → Time Manipulation & Log/AAA Evasion

- **ID**: `c1-5`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) spoof the configured NTP server (10.17.251.250) or become a man-in-the-middle → 2) feed incorrect time to the switch, as NTP authentication is not configured → 3) disrupt time-dependent services (certificate validation, AAA logging), facilitate replay attacks, or corrupt forensic timelines.

**Supporting facts**

- `f1-14` (show running-config): NTP server is configured (`ntp server 10.17.251.250`).
  > `ntp server 10.17.251.250`
- `f1-15` (show running-config): No `ntp authenticate` or `ntp trusted-key` configuration is present.
  > `ntp server 10.17.251.250`

---

### [MEDIUM] Weak SSH Algorithms → Cryptographic Downgrade Attack

- **ID**: `c8-1`
- **Confidence**: speculative
- **First seen**: trial 8

**Attack narrative**

Attacker can: 1) exploit the presence of weak SSH algorithms (ssh-rsa for public key authentication and host key) → 2) perform a cryptographic downgrade or algorithm confusion attack against the SSH service → 3) potentially compromise SSH session integrity or authentication.

**Supporting facts**

- `f8-2` (show ip ssh): SSH authentication publickey algorithms include ssh-rsa.
  > `Authentication Publickey Algorithms:ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,x509v3-ecdsa-sha2-nistp256,x509v3-ecdsa-sha2-nistp384,x509v3-ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,x509v3-rsa2048-sha256`
- `f8-3` (show ip ssh): SSH hostkey algorithms include ssh-rsa.
  > `Hostkey Algorithms:ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa`

**Verification commands needed**

- `show line vty 0 4`
- `show line vty 0 15`

---

## Facts Index

All 69 security-relevant facts extracted during this audit.

- **`f0-0`** (trial 0, `show version`): Device is running Cisco IOS XE Software, Version 17.15.01.
- **`f0-1`** (trial 0, `show version`): Device model is C9KV-UADP-8P.
- **`f0-2`** (trial 0, `show version`): Base Ethernet MAC Address is 00:50:56:bf:29:d2.
- **`f1-0`** (trial 1, `show running-config`): Enable password is encoded with Type 7 reversible encryption.
- **`f1-1`** (trial 1, `show running-config`): Username 'admin' with privilege level 15 has a password encoded with Type 7 reversible encryption.
- **`f1-2`** (trial 1, `show running-config`): TACACS+ server key is encoded with Type 7 reversible encryption.
- **`f1-3`** (trial 1, `show running-config`): HTTP server is enabled (`ip http server` present).
- **`f1-4`** (trial 1, `show running-config`): HTTPS server is enabled (`ip http secure-server` present).
- **`f1-5`** (trial 1, `show running-config`): No `ip http access-class` is configured.
- **`f1-6`** (trial 1, `show running-config`): VTY lines 0-4 and 5-15 are configured with `transport input ssh`.
- **`f1-7`** (trial 1, `show running-config`): No `exec-timeout` is configured on VTY lines 0-4.
- **`f1-8`** (trial 1, `show running-config`): No `exec-timeout` is configured on VTY lines 5-15.
- **`f1-9`** (trial 1, `show running-config`): No `banner login` or `banner motd` block is present in the configuration.
- **`f1-10`** (trial 1, `show running-config`): Spanning-tree mode is set to rapid-pvst (`spanning-tree mode rapid-pvst`).
- **`f1-11`** (trial 1, `show running-config`): No `spanning-tree portfast bpduguard default` is configured.
- **`f1-12`** (trial 1, `show running-config`): Interface GigabitEthernet1/0/1 is configured as an access port for VLAN 10 (`switchport access vlan 10`).
- **`f1-13`** (trial 1, `show running-config`): No `switchport port-security` is configured on access port GigabitEthernet1/0/1.
- **`f1-14`** (trial 1, `show running-config`): NTP server is configured (`ntp server 10.17.251.250`).
- **`f1-15`** (trial 1, `show running-config`): No `ntp authenticate` or `ntp trusted-key` configuration is present.
- **`f1-16`** (trial 1, `show running-config`): SNMP is not configured (no `snmp-server` lines present).
- **`f2-0`** (trial 2, `show ip http server status`): HTTP server authentication method is set to 'enable'.
- **`f2-1`** (trial 2, `show ip http server status`): HTTP server has no IPv4 access class configured.
- **`f2-2`** (trial 2, `show ip http server status`): HTTP server has no IPv6 access class configured.
- **`f2-3`** (trial 2, `show ip http server status`): HTTP server digest algorithm is set to MD5.
- **`f2-4`** (trial 2, `show ip http server status`): HTTP server is listening on an active supplementary port 21111.
- **`f3-0`** (trial 3, `show aaa servers`): No AAA servers (RADIUS/TACACS+) are configured.
- **`f4-0`** (trial 4, `show tacacs`): A TACACS+ server is configured and reachable (status: Alive).
- **`f5-0`** (trial 5, `show spanning-tree summary`): PortFast BPDU Guard Default is disabled globally.
- **`f5-1`** (trial 5, `show spanning-tree summary`): Portfast Default is disabled globally.
- **`f6-0`** (trial 6, `show spanning-tree detail`): No spanning tree instance exists on the device.
- **`f7-0`** (trial 7, `show port-security`): No ports have port security enabled.
- **`f7-1`** (trial 7, `show port-security`): Total learned secure MAC addresses in the system is zero.
- **`f8-0`** (trial 8, `show ip ssh`): SSH version 2.0 is enabled.
- **`f8-1`** (trial 8, `show ip ssh`): SSH authentication methods include password.
- **`f8-2`** (trial 8, `show ip ssh`): SSH authentication publickey algorithms include ssh-rsa.
- **`f8-3`** (trial 8, `show ip ssh`): SSH hostkey algorithms include ssh-rsa.
- **`f8-4`** (trial 8, `show ip ssh`): SSH authentication timeout is 120 seconds.
- **`f8-5`** (trial 8, `show ip ssh`): SSH authentication retries is 3.
- **`f8-6`** (trial 8, `show ip ssh`): SSH minimum expected Diffie Hellman key size is 2048 bits.
- **`f8-7`** (trial 8, `show ip ssh`): SSH RSA host key modulus size is 2048 bits.
- **`f9-0`** (trial 9, `show line vty 0 15`): VTY lines 0-15 are configured with `transport input ssh`.
- **`f9-1`** (trial 9, `show line vty 0 15`): No `exec-timeout` is configured on VTY lines 0-15.
- **`f10-0`** (trial 10, `show line vty 0 4`): VTY lines 1-5 have been used for remote sessions (Uses count > 0).
- **`f10-1`** (trial 10, `show line vty 0 4`): VTY line 1 is currently active (asterisk in first column).
- **`f11-0`** (trial 11, `show cdp neighbors detail`): No CDP neighbors are detected on any interface.
- **`f12-0`** (trial 12, `show interfaces trunk`): No trunk interfaces are configured on the device.
- **`f13-0`** (trial 13, `show vlan brief`): VLAN 1 (default) is active and includes multiple access ports.
- **`f13-1`** (trial 13, `show vlan brief`): VLAN 10 is active and includes access port GigabitEthernet1/0/1.
- **`f13-2`** (trial 13, `show vlan brief`): VLAN 188 is active but has no assigned ports.
- **`f14-0`** (trial 14, `show interfaces switchport`): Interface GigabitEthernet1/0/1 is administratively configured as an access port for VLAN 10.
- **`f14-1`** (trial 14, `show interfaces switchport`): Interface GigabitEthernet1/0/1 has administrative trunking mode 'dynamic auto' with negotiation enabled.
- **`f14-2`** (trial 14, `show interfaces switchport`): Interface GigabitEthernet1/0/1 has administrative native VLAN set to 1 (default).
- **`f14-3`** (trial 14, `show interfaces switchport`): Interface GigabitEthernet1/0/1 has administrative trunking VLANs enabled set to ALL.
- **`f14-4`** (trial 14, `show interfaces switchport`): Interfaces GigabitEthernet1/0/2 through GigabitEthernet1/0/8 are administratively configured as access ports for VLAN 1 (default).
- **`f14-5`** (trial 14, `show interfaces switchport`): Interfaces GigabitEthernet1/0/2 through GigabitEthernet1/0/8 have administrative trunking mode 'dynamic auto' with negotiation enabled.
- **`f14-6`** (trial 14, `show interfaces switchport`): Interfaces GigabitEthernet1/0/2 through GigabitEthernet1/0/8 have administrative trunking VLANs enabled set to ALL.
- **`f14-7`** (trial 14, `show interfaces switchport`): All interfaces GigabitEthernet1/0/1 through GigabitEthernet1/0/8 are operationally down.
- **`f15-0`** (trial 15, `show mac address-table`): A static MAC address entry for 0050.56bf.2919 is bound to VLAN 1 interface Vlan1.
- **`f15-1`** (trial 15, `show mac address-table`): No dynamic MAC address entries are present in the MAC address table.
- **`f16-0`** (trial 16, `show ip dhcp snooping`): DHCP snooping is disabled globally.
- **`f16-1`** (trial 16, `show ip dhcp snooping`): DHCP snooping is not configured on any VLANs.
- **`f16-2`** (trial 16, `show ip dhcp snooping`): DHCP snooping is not operational on any VLANs.
- **`f16-3`** (trial 16, `show ip dhcp snooping`): No interfaces are configured as DHCP snooping trusted.
- **`f17-0`** (trial 17, `show ip dhcp snooping binding`): DHCP snooping binding table is empty (no learned IP-MAC-port bindings).
- **`f18-0`** (trial 18, `show ip arp inspection`): Dynamic ARP Inspection (DAI) is disabled globally (no active or enabled VLANs).
- **`f18-1`** (trial 18, `show ip arp inspection`): Source MAC validation for ARP packets is disabled.
- **`f18-2`** (trial 18, `show ip arp inspection`): Destination MAC validation for ARP packets is disabled.
- **`f18-3`** (trial 18, `show ip arp inspection`): IP address validation for ARP packets is disabled.
- **`f19-0`** (trial 19, `show storm-control`): No storm control is configured on any interface.
