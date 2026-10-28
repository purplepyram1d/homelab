# Validation status, October 27, 2026

| Component | Evidence accepted | Limit |
| --- | --- | --- |
| Sysmon healthy reports, 100892 | Live DC01 and SRV01 reports; fresh manager-to-Elastic records October 27 | Healthy now does not prove every past interval was covered |
| Sysmon stop/termination, 100890/100891 | Installed XML and predicate checks | October 27 guarded live attempts were denied by ANTIMALWARE LIGHT protection; no stop/termination event was created |
| Failed health, 100893 | Offline JSON controls | No real failed health stimulus accepted |
| Missing report/recovery, 100894/100895 | Real SRV01 reporting-task pause October 24, stale lead and recovery in Wazuh/Elastic; exact-source case worked | DC01 was a fresh negative comparison, not a separately paused positive |
| Observer source failure/recovery, 100896/100897 | Actual installed-service denied source read and restored access October 25; duplicate transition suppressed | Clock rollback and every source fault were not live-tested |
| Encoded PowerShell companion, 100863 | Learner's benign SRV01 positive October 21: encoded Get-Date, source and case matched | Separate DC01 live acceptance and encoded pwsh child are not inferred |
| Other fileless-family rules, 100860-100862 | Installed source and documented historical scoped checks | This export does not add blanket live acceptance or prove every PowerShell 7 script-block chain |
| Server logging after boot | October 27: exact 4688 command lines and 4104 markers for Windows PowerShell 5.1 / PowerShell 7 on both servers; all eight records in Wazuh archive | Quiet archived events need not appear as alerts |
| Cross-sensor readiness | October 27 single marked request: native Zeek + Suricata, matching indexed Community ID, authenticated EveBox event | No signature match, TLS decryption, vendor RMM session or full network coverage claimed |
| RMM current delivery | Separate manual source adapter, restricted publisher and exact-source existing-case intake accepted October 25 | Unattended delivery, automatic rotation/retraction and automatic response remain unarmed |

Case resolution records a supported disposition. It does not prove a host is universally clean. Local tests validate behavior under their fixtures; deployment acceptance needs actual source, delivery, recovery and cleanup evidence.
