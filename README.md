# Homelab

This is where I break things and put them back together to learn how they work.

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

## Learning as I go

- [docs/tips-and-tricks.md](docs/tips-and-tricks.md) — real gotchas hit building this, symptom → fix.
- [docs/exercises.md](docs/exercises.md) — what actually gets run against this lab.

## Detection engineering that runs on this lab

The lab itself is the shared substrate. Substantial projects with their own sustained scope get a dedicated repo; smaller rule sets backing a single write-up live right here under [`wazuh/rules/`](wazuh/rules).

| Project | Status | Location |
|---|---|---|
| RMM multiplicity detection | Published | [rmm-multiplicity](https://github.com/purplepyram1d/rmm-multiplicity) *(own repo)* |
| DNS attack detection | Published | [`wazuh/rules/dns`](wazuh/rules/dns) |
| HTB / platform writeups | Active | [Writeups](https://github.com/purplepyram1d/Writeups) *(own repo)* |
| BYOVD detection | Planned | — |
| Sigma rule contributions (sourced from the DNS lab) | In progress | — |
| Kerberos attack detection | Planned | — |

## What's next

Stand up Velociraptor (RPTR01), capture cert-verified RMM lineage to close out the [RMM multiplicity](https://github.com/purplepyram1d/rmm-multiplicity) write-up, then move into the BYOVD and Sigma-rule-contribution work above.

## License

MIT
