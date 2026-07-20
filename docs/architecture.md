# Architecture

## Hardware

Two Dell OptiPlex 3050s, 32GB RAM each. Both run VMware Workstation Pro as a type-2 hypervisor, so both machines stay usable desktops — this was a deliberate choice over a headless type-1 setup (Proxmox, ESXi), trading a little "enterprise" resume polish for actually being able to sit at either box and work.

## Network

Everything lives on one locked subnet: **`10.10.10.0/24`**. No secondary ranges, no VLANs — segmentation (a pfSense gateway, a separate SOC subnet) is a deliberately deferred Phase 3, not a requirement for the detection work to be real.

Each host gets internet over its own WiFi adapter. A single direct Ethernet cable between the two OptiPlexes carries all lab traffic — that cable *is* the network. VMs get two virtual NICs: one bridged to the Ethernet adapter for the static `10.10.10.x` lab address (no gateway — the lab plane has no internet route), and one on NAT riding the host's WiFi for updates and tool downloads. The NAT NIC is plumbing only and is never referenced by hostname, DNS, or any attack/detection logic.

### Host split

| Host | Lab IP | Role |
|---|---|---|
| **CORP** | `10.10.10.10` | The domain estate — DC, member server, workstations |
| **BLUETEAM** | `10.10.10.20` | The detection stack — SIEM, hunt platform, attacker box |

CORP holds the assets; BLUETEAM holds the analyst seat and the attacker. Detonating something on CORP's VMs (a simulated ransomware run, a popped DC) doesn't touch BLUETEAM's stack, and vice versa — the Ethernet cable is the only path between them, so "attacker reaches the enterprise over the network" is literal, not simulated.

### VM inventory

| VM | Host | Lab IP | Role |
|---|---|---|---|
| DC01 | CORP | `10.10.10.11` | Windows Server 2022 — AD DS + DNS |
| SRV01 | CORP | `10.10.10.12` | Windows Server 2022 — member server, file shares (NTFS permissions realism) |
| WS01 | CORP | `10.10.10.21` | Windows 11 — workstation, RMM/phishing detection endpoint |
| WS02 | CORP | `10.10.10.22` | Windows 11 — second workstation, lateral-movement realism |
| WAZUH01 | BLUETEAM | `10.10.10.5` | Ubuntu — Wazuh SIEM/XDR (manager, indexer, dashboard), always-on |
| Kali | BLUETEAM | `10.10.10.30` | Attacker box |
| RPTR01 | BLUETEAM | *(in progress)* | Velociraptor hunt platform |

**Address plan:** `.5-.9` monitoring/SIEM · `.10`/`.20` physical hosts · `.11-.19` servers · `.21-.49` workstations · `.50+` reserved for future attacker/misc VMs.

## Domain

`corp.local` (NetBIOS `CORP`). Every domain-joined VM points DNS at DC01 (`10.10.10.11`); DC01 forwards upstream to a public resolver. See [active-directory.md](active-directory.md) for how the domain is populated and what's intentionally misconfigured in it.

## Why this split, not a single all-in-one box

A single-box lab squeezes the estate and the SIEM onto the same 32GB machine, which starves the SIEM's indexer of RAM and blurs the "attacker vs. defender vs. asset" separation that makes detection engineering meaningful. Splitting estate and detection stack across two physical hosts costs a cable and nothing else, and buys a real blast-radius boundary: telemetry keeps flowing to WAZUH01 even if something on CORP gets fully compromised.
