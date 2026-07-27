# Homelab

This is where I break things and put them back together to learn how they work.

## The domain

`corp.local` (NetBIOS `CORP`), populated with [BadBlood](https://github.com/davidprowe/BadBlood) so it looks and behaves like a real company instead of an empty lab shell: roughly 2,500 users, 550 groups, and 220+ department-realistic OUs.

More on the AD build: [docs/active-directory.md](docs/active-directory.md).

## Detection platform

- **Sysmon** on every Windows VM (SwiftOnSecurity baseline, moving to Olaf Hartong's modular config) — the endpoint telemetry source.
- **Wazuh** SIEM on WAZUH01 — manager, indexer, and dashboard, with agents on every domain endpoint.
- **Velociraptor** *(in progress)* — a hunt/DFIR layer for the things Wazuh alone can't do cleanly: rename-proof tool identification via signing certificate, and true process lineage instead of inferred parent-child pairs.

More on the platform: [docs/detection-platform.md](docs/detection-platform.md).

## Attacker infrastructure

A Kali box on the BLUETEAM host generates the activity the rest of the stack is built to catch.. RMM daisy-chain simulations, DNS attacks (zone transfer, rogue WPAD via dynamic update), and Kerberos attacks (Kerberoasting, AS-REP roasting) against the BadBlood-populated domain.

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
