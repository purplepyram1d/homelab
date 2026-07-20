# Homelab

A two-host Windows Active Directory environment and a purple-team lab built on top of it, meant to reproduce the kind of environment a Windows-focused MSP/MDR shop like Huntress actually defends: a real domain, real endpoint telemetry, a SIEM, and detection rules tested against my own simulated attacks.

The lab is the substrate. The point is the detection engineering that runs on top of it.

## Hardware and network

Two Dell OptiPlex 3050s, 32GB RAM each, on a single locked lab subnet `10.10.10.0/24`. Both hosts get internet over WiFi; a direct Ethernet cable between them carries the lab traffic. VMware Workstation Pro, type-2, on both, so both boxes stay usable desktops.

| Host | Role | Lab IP |
|---|---|---|
| CORP | Domain estate — DC, member server, workstations | `10.10.10.10` |
| BLUETEAM | Detection stack — SIEM, hunt platform, attacker box | `10.10.10.20` |

| VM | Runs on | Lab IP | Role |
|---|---|---|---|
| DC01 | CORP | `10.10.10.11` | Windows Server 2022 — AD DS + DNS |
| SRV01 | CORP | `10.10.10.12` | Windows Server 2022 — member server, file shares |
| WS01 | CORP | `10.10.10.21` | Windows 11 — workstation |
| WS02 | CORP | `10.10.10.22` | Windows 11 — workstation |
| WAZUH01 | BLUETEAM | `10.10.10.5` | Wazuh SIEM/XDR, always-on |
| Kali | BLUETEAM | `10.10.10.30` | attacker box |
| RPTR01 *(in progress)* | BLUETEAM | — | Velociraptor hunt platform |

Full detail: [docs/architecture.md](docs/architecture.md).

## The domain

`corp.local` (NetBIOS `CORP`), populated with [BadBlood](https://github.com/davidprowe/BadBlood) so it looks and behaves like a real company instead of an empty lab shell: roughly 2,500 users, 550 groups, and 220+ department-realistic OUs. A handful of shadow-admin accounts are planted in privileged groups on purpose, as a live "audit your privileged group membership" detection exercise.

More on the AD build: [docs/active-directory.md](docs/active-directory.md).

## Detection platform

- **Sysmon** on every Windows VM (SwiftOnSecurity baseline, moving to Olaf Hartong's modular config) — the endpoint telemetry source.
- **Wazuh** SIEM on WAZUH01 — manager, indexer, and dashboard, with agents on every domain endpoint.
- **Velociraptor** *(in progress)* — a hunt/DFIR layer for the things Wazuh alone can't do cleanly: rename-proof tool identification via signing certificate, and true process lineage instead of inferred parent-child pairs.

More on the platform: [docs/detection-platform.md](docs/detection-platform.md).

## Attacker infrastructure

A Kali box on the BLUETEAM host generates the activity the rest of the stack is built to catch — RMM daisy-chain simulations, DNS attacks (zone transfer, rogue WPAD via dynamic update), and Kerberos attacks (Kerberoasting, AS-REP roasting) against the BadBlood-populated domain.

## Detection engineering that runs on this lab

The lab itself is the shared substrate. Individual detection projects built and tested against it get their own repos so each one stands on its own:

| Project | Status | Repo |
|---|---|---|
| RMM multiplicity detection | Published | [rmm-multiplicity](https://github.com/purplepyram1d/rmm-multiplicity) |
| HTB / platform writeups | Active | [Writeups](https://github.com/purplepyram1d/Writeups) |
| BYOVD detection | Planned | — |
| DNS attack detection (Sigma) | In progress | — |
| Kerberos attack detection | Planned | — |

## What's next

Stand up Velociraptor (RPTR01), capture cert-verified RMM lineage to close out the [RMM multiplicity](https://github.com/purplepyram1d/rmm-multiplicity) write-up, then move into the BYOVD and Sigma-rule-contribution work above.

## License

MIT
