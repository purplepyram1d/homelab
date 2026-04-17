# homelab-detection-lab

Detection engineering lab built on a 7-VM Windows domain environment (cjcs.local). Phase 1 used Wazuh 4.14.0 for custom rule development; Phase 2 migrated to Splunk with Universal Forwarders across all Windows hosts.

## Environment

| Host | Role | OS |
|---|---|---|
| DC01 | Domain Controller | Windows Server 2022 |
| APP01 | Web + DB Server | Windows Server 2022 |
| MGR1 | Executive Workstation | Windows 11 |
| DEV1 | Developer Workstation | Windows 11 |
| USER1 | Standard User Workstation | Windows 11 |
| SIEM01 | Wazuh Manager / Splunk Indexer | Ubuntu 24.04.3 |
| Kali | Attack Platform | Kali Linux |

## Repository Structure

```
wazuh/
  rules/
    local_rules.xml          # Custom detection rules (IDs 100001–100021)
  config/
    ossec-sysmon.conf        # Agent config snippet for Sysmon eventchannel ingestion
  alert-utils/
    alert-query.sh           # wazuhgrep / jqwazuh / live_alerts bash utilities

splunk/
  queries/
    brute-force-detection.spl        # EventCodes 4625/4624/4672 + attack chain
    process-execution-monitoring.spl # Sysmon EventCode 1/11 + LOLBins + chain viz
    noise-reduction.spl              # NCSI filter, process categorization, baseline
  diagnostic/
    splunk-indexer-diagnostic.sh     # Linux: disk, ports, service, log tail
    splunk-forwarder-diagnostic.ps1  # Windows: service, inputs.conf, btool, Sysmon
```

## Custom Wazuh Rules

| Rule ID | Description | MITRE | Severity |
|---|---|---|---|
| 100001 | Brute force: 3+ failed logons in 60s | T1110.001 | High |
| 100002 | Password spray: 5+ accounts in 120s | T1110.003 | Critical |
| 100010 | LSASS memory access (Sysmon EventCode 10) | T1003.001 | Critical |
| 100011 | Known credential dumping tools (mimikatz, procdump, etc.) | T1003.001 | Critical |
| 100012 | Privileged account logon to DC01 (SOC 2 CC7.1) | — | High |
| 100020 | RDP re-enabled via registry (fDenyTSConnections = 0) | T1021.001 | High |
| 100021 | RDP enabled and process spawned from terminal services | T1021.001 | High |

## Splunk SPL Coverage

- **Brute force**: severity tiering (MEDIUM >5, HIGH >10, CRITICAL >20 failures), attack chain correlation (fail→success)
- **Process execution**: LOLBins detection (whoami, ipconfig, net, nltest, wmic, powershell), file drop + execution chain visualization
- **Noise reduction**: NCSI DNS probe filter, Splunk self-monitoring process exclusion, log receipt verification

## Related Articles

Full build documentation published on Medium [@johnnymeintel](https://medium.com/@johnnymeintel):

- [Splunk Basics: Homelab "SOC In A Box"](https://medium.com/@johnnymeintel/splunk-basics-homelab-soc-in-a-box-b7f0d2746fdc)
- [Splunk Homelab Noise Reduction — Part 1](https://medium.com/@johnnymeintel/splunk-homelab-noise-reduction-part-1-6a092164bbc0)
- [Splunk Homelab Noise Reduction — Part 2](https://medium.com/@johnnymeintel/splunk-homelab-noise-reduction-part-2-db1a775a675f)
- [Sysmon Event ID Chaining as Indicators of Compromise](https://medium.com/@johnnymeintel/sysmon-is-coming-to-windows-lets-celebrate-by-talking-about-event-id-chaining-as-indicators-of-ac0076cac754)
