# Switch Security Audit Report

| Field | Value |
|-------|-------|
| Target | `devnetsandboxiosxec9k.cisco.com` |
| Device OS | Cisco IOS XE 17.15.1 / C9KV-UADP-8P |
| Audit started | 2026-04-07T15:41:28.347985+00:00 |
| Report generated | 2026-04-07 15:46 UTC |
| Trials executed | 8 |
| Commands executed | 8 |

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 1 |
| 🟢 Low | 0 |
| **Active chains** | **4** |
| Confirmed chains | 4 |
| Refuted paths | 1 |
| Facts extracted | 35 |

---

## Recovered Credentials

> **Note**: Type 7 is NOT encryption. Any attacker with config access can decode these instantly.

| Account / Context | Plaintext | Ciphertext | Found In |
|-------------------|-----------|------------|----------|
| enable password | `C1sco12345` | `013057175804575D72181B` | `show running-config` |
| username admin (privilege 15) | `C1sco12345` | `096F1F1A1A0A4640585851` | `show running-config` |
| Shared key (TACACS+/RADIUS) | `isecat8k` | `12101612110A185C21` | `show running-config` |

---

## Attack Chains

### [CRITICAL] Reversible Enable Password → HTTP/HTTPS Admin Access

- **ID**: `c1-0`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) decode the Type 7 enable password from the running config → 2) authenticate to the HTTP (port 80) or HTTPS (port 443) management interface, which uses the enable password for authentication and has no source IP restrictions → 3) gain full device administrative access.

**Supporting facts**

- `f1-0` (show running-config): Enable password is encoded with Type 7 reversible encryption.
  > `enable password 7 013057175804575D72181B`
- `f1-1` (show running-config): Enable password plaintext is 'C1sco12345'.
  > `enable password 7 013057175804575D72181B`
- `f1-6` (show running-config): HTTP server is enabled (`ip http server` present).
  > `ip http server`
- `f1-7` (show running-config): HTTPS server is enabled (`ip http secure-server` present).
  > `ip http secure-server`
- `f1-8` (show running-config): No `ip http access-class` is configured.
  > `ip http server  ip http secure-server`
- `f2-0` (show ip http server status): HTTP server is enabled on port 80.
  > `HTTP server status: Enabled  HTTP server port: 80`
- `f2-1` (show ip http server status): HTTP server authentication method is 'enable'.
  > `HTTP server authentication method: enable`
- `f2-2` (show ip http server status): HTTP server has no IPv4 access class restriction.
  > `HTTP server IPv4 access class: None`
- `f2-3` (show ip http server status): HTTP server has no IPv6 access class restriction.
  > `HTTP server IPv6 access class: None`
- `f2-4` (show ip http server status): HTTP secure server (HTTPS) is enabled on port 443.
  > `HTTP secure server status: Enabled  HTTP secure server port: 443`

---

### [HIGH] Missing BPDU Guard → STP Manipulation

- **ID**: `c1-2`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) Connect a rogue switch to an access port → 2) Send BPDUs to manipulate the spanning tree topology (since no STP instance exists, the device will not generate BPDUs to defend itself) → 3) Become the root bridge and intercept traffic, causing a denial of service or man-in-the-middle attack.

**Supporting facts**

- `f1-12` (show running-config): Spanning-tree mode is set to rapid-pvst.
  > `spanning-tree mode rapid-pvst`
- `f1-13` (show running-config): No `spanning-tree portfast bpduguard default` is configured.
  > `spanning-tree mode rapid-pvst`
- `f4-0` (show spanning-tree summary): PortFast BPDU Guard Default is disabled globally.
  > `PortFast BPDU Guard Default            is disabled`
- `f5-0` (show spanning-tree detail): No spanning tree instance exists on the device.
  > `No spanning tree instance exists.`

---

### [HIGH] Missing Port Security → MAC Flooding & Unauthorized Access

- **ID**: `c1-3`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) connect to access port GigabitEthernet1/0/1 (VLAN 10) → 2) flood the switch with spoofed MAC addresses to overflow the MAC address table → 3) cause the switch to fail-open, forwarding all traffic to all ports (MAC flooding attack) → 4) sniff traffic or connect an unauthorized device to gain network access.

**Supporting facts**

- `f1-14` (show running-config): Interface GigabitEthernet1/0/1 is configured as an access port in VLAN 10.
  > `interface GigabitEthernet1/0/1   switchport access vlan 10   shutdown`
- `f1-15` (show running-config): No `switchport port-security` is configured on access interface GigabitEthernet1/0/1.
  > `interface GigabitEthernet1/0/1   switchport access vlan 10   shutdown`
- `f6-0` (show port-security): Port security is globally disabled (no secure ports listed).
  > `---------------------------------------------------------------------------`
- `f6-1` (show port-security): No secure MAC addresses are currently learned in the system.
  > `Total Addresses in System (excluding one mac per port)     : 0`

---

### [MEDIUM] Unauthenticated NTP → Time Manipulation & Log/AAA Impact

- **ID**: `c1-4`
- **Confidence**: confirmed
- **First seen**: trial 1

**Attack narrative**

Attacker can: 1) spoof the configured but unreachable NTP server (10.17.251.250) → 2) inject malicious time updates due to lack of NTP authentication → 3) manipulate device time, potentially causing certificate validation failures, log timestamp confusion, and AAA session timing issues.

**Supporting facts**

- `f1-16` (show running-config): NTP server is configured with IP address 10.17.251.250.
  > `ntp server 10.17.251.250`
- `f1-17` (show running-config): No `ntp authenticate` or `ntp trusted-key` is configured.
  > `ntp server 10.17.251.250`
- `f7-0` (show ntp associations): NTP server 10.17.251.250 is configured but unreachable (reach=0).
  > `~10.17.251.250   .TIME.          16      -     64     0  0.000   0.000 15937.`
- `f7-1` (show ntp associations): NTP server 10.17.251.250 is configured as a stratum 16 server (unsynchronized).
  > `~10.17.251.250   .TIME.          16      -     64     0  0.000   0.000 15937.`

---

## Refuted Attack Paths

> The following hypotheses were **eliminated** by subsequent evidence. They are preserved for audit trail purposes.

- **[c1-1] Reversible TACACS+ Key → Authentication Bypass** (originally critical, first seen trial 1)
  The attack chain 'Reversible TACACS+ Key → Authentication Bypass' has been refuted. The command `show aaa servers` returned no output, indicating no TACACS+ servers are configured or reachable. Therefore, the reversible TACACS+ key (f1-4, f1-5) cannot be used to attack an active AAA infrastructure.

---

## Facts Index

All 35 security-relevant facts extracted during this audit.

- **`f0-0`** (trial 0, `show version`): Device is running Cisco IOS XE Software, Version 17.15.01.
- **`f0-1`** (trial 0, `show version`): Device model is C9KV-UADP-8P (Catalyst 9000 Virtual Switch).
- **`f0-2`** (trial 0, `show version`): Base Ethernet MAC address is 00:50:56:bf:29:d2.
- **`f0-3`** (trial 0, `show version`): System serial number is 98DVJUONW1X.
- **`f1-0`** (trial 1, `show running-config`): Enable password is encoded with Type 7 reversible encryption.
- **`f1-1`** (trial 1, `show running-config`): Enable password plaintext is 'C1sco12345'.
- **`f1-2`** (trial 1, `show running-config`): Local user 'admin' with privilege level 15 has a Type 7 encoded password.
- **`f1-3`** (trial 1, `show running-config`): Local user 'admin' password plaintext is 'C1sco12345'.
- **`f1-4`** (trial 1, `show running-config`): TACACS+ server key is encoded with Type 7 reversible encryption.
- **`f1-5`** (trial 1, `show running-config`): TACACS+ server key plaintext is 'isecat8k'.
- **`f1-6`** (trial 1, `show running-config`): HTTP server is enabled (`ip http server` present).
- **`f1-7`** (trial 1, `show running-config`): HTTPS server is enabled (`ip http secure-server` present).
- **`f1-8`** (trial 1, `show running-config`): No `ip http access-class` is configured.
- **`f1-9`** (trial 1, `show running-config`): VTY lines 0-4 and 5-15 are configured with `transport input ssh` only.
- **`f1-10`** (trial 1, `show running-config`): No `exec-timeout` is configured on VTY lines.
- **`f1-11`** (trial 1, `show running-config`): No `banner login` or `banner motd` is configured.
- **`f1-12`** (trial 1, `show running-config`): Spanning-tree mode is set to rapid-pvst.
- **`f1-13`** (trial 1, `show running-config`): No `spanning-tree portfast bpduguard default` is configured.
- **`f1-14`** (trial 1, `show running-config`): Interface GigabitEthernet1/0/1 is configured as an access port in VLAN 10.
- **`f1-15`** (trial 1, `show running-config`): No `switchport port-security` is configured on access interface GigabitEthernet1/0/1.
- **`f1-16`** (trial 1, `show running-config`): NTP server is configured with IP address 10.17.251.250.
- **`f1-17`** (trial 1, `show running-config`): No `ntp authenticate` or `ntp trusted-key` is configured.
- **`f2-0`** (trial 2, `show ip http server status`): HTTP server is enabled on port 80.
- **`f2-1`** (trial 2, `show ip http server status`): HTTP server authentication method is 'enable'.
- **`f2-2`** (trial 2, `show ip http server status`): HTTP server has no IPv4 access class restriction.
- **`f2-3`** (trial 2, `show ip http server status`): HTTP server has no IPv6 access class restriction.
- **`f2-4`** (trial 2, `show ip http server status`): HTTP secure server (HTTPS) is enabled on port 443.
- **`f2-5`** (trial 2, `show ip http server status`): HTTP secure server uses a self-signed certificate.
- **`f4-0`** (trial 4, `show spanning-tree summary`): PortFast BPDU Guard Default is disabled globally.
- **`f4-1`** (trial 4, `show spanning-tree summary`): Portfast Default is disabled globally.
- **`f5-0`** (trial 5, `show spanning-tree detail`): No spanning tree instance exists on the device.
- **`f6-0`** (trial 6, `show port-security`): Port security is globally disabled (no secure ports listed).
- **`f6-1`** (trial 6, `show port-security`): No secure MAC addresses are currently learned in the system.
- **`f7-0`** (trial 7, `show ntp associations`): NTP server 10.17.251.250 is configured but unreachable (reach=0).
- **`f7-1`** (trial 7, `show ntp associations`): NTP server 10.17.251.250 is configured as a stratum 16 server (unsynchronized).
