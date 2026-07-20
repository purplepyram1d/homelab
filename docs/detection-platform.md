# Detection Platform

The detection stack is layered so each piece covers what the layer below it can't.

## Layer 1 — Sysmon (endpoint telemetry)

[Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) runs on every Windows VM in the domain, starting from the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) baseline config and moving toward [Olaf Hartong's modular config](https://github.com/olafhartong/sysmon-modular) for finer per-technique tuning. This is the single highest-value logging change on a Windows box — it turns a blind endpoint into a real telemetry source, and it's the layer everything above depends on. No Sysmon coverage means no detection, full stop.

The events that matter most for this lab's detection work: Event ID 1 (process creation, with full command line and parent process), Event ID 3 (network connection), Event ID 6 (driver loaded — for BYOVD detection), and Event ID 7 (image load).

## Layer 2 — Wazuh (SIEM/XDR)

[Wazuh](https://wazuh.com/) runs as an all-in-one deployment on WAZUH01 (manager, indexer, dashboard), with an agent on every domain endpoint shipping the Sysmon channel. Wazuh was picked over a pure log-aggregation tool like Splunk specifically because it's agent-based endpoint detection — conceptually closer to how an MDR platform like Huntress actually works than a log-search product is.

Custom detection rules live in the individual project repos rather than this one — see the [README](../README.md) for links. The general pattern across all of them: identify a technique behaviorally (a company/vendor field on a process, a correlation across event types, a timing window), not by a brittle filename or hash signature alone.

## Layer 3 — Velociraptor (hunt / DFIR) *(in progress)*

Wazuh's rule engine is good at correlation but has two structural blind spots this lab is building Velociraptor to close:

- **Rename-proof identification.** A Sysmon `Company` field tag survives a renamed binary, but a fully spoofed one doesn't. Velociraptor's `authenticode()` VQL function checks the actual code-signing certificate, which is a stronger identity claim than a file's internal metadata.
- **True process lineage.** Wazuh's parent-child correlation infers lineage from two events landing close together in time. Velociraptor's process tracker (`Windows.Events.TrackProcesses`) captures actual process ancestry, which is the difference between "these two things happened near each other" and "this process launched that one."

RPTR01 is the next VM to come online on BLUETEAM. Once it's live, the goal is a cert-verified, lineage-confirmed detection that closes the last gap in the [RMM multiplicity](https://github.com/purplepyram1d/rmm-multiplicity) write-up.

## Why this order

Telemetry before correlation before hunting. There's no point tuning a SIEM rule against an endpoint that isn't logging the right events, and there's no point reaching for a hunt platform before the SIEM layer has proven out what it can and can't catch on its own. Each layer earns its place by covering a gap the layer below it demonstrably has.
