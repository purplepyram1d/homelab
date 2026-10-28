# Health-report arrival watchdog

This complete component contains the observer, isolated tests, systemd units, guarded first-install helper and the Windows producer source. The canonical XML lives under `detections/wazuh/telemetry-health`; do not maintain a second rule copy here.

## What it does

DC01 and SRV01 normally produce a Sysmon health sample every five minutes. A minute observer on SIEM01 reads validated Wazuh alert envelopes. It persists the newest accepted sample time and emits a stale transition after 900 seconds, then a resumed transition when reporting returns. A failed health report still proves the reporting task is alive. Separate source/clock errors prevent a broken observer from looking like a clean result.

Only the configured agent IDs/names, manager, rule IDs, protected health-file location and matching host/kind/status may advance time. Old replay cannot extend freshness. The durable outbox is at least once: a crash between append/fsync and acknowledgement can replay the same event ID. Exactly-once downstream incident creation is not claimed. No endpoint commands, network calls, credentials or automatic response occur in the observer.

## First run: isolated tests only

From the repository root on Linux with Python 3:

```bash
# Exercise temporary fixture stores; do not read production state or change services.
python3 -m unittest discover -s tools/telemetry-watch -p 'test_telemetry_watch.py' -v
```

The suite covers threshold boundaries, persistent startup grace, exact source identity, older/future samples, report failure versus absence, source denial/recovery, outbox interruption, bounded tail, rotation and Linux no-follow behavior. It creates temporary directories beside the copied tests and cleans them up. Windows skips the Linux-only no-follow test; use Linux for full acceptance.

## Deployment contract

This candidate retains the lab's exact DC01/001 and SRV01/003 mapping and 900-second deadline. Review `HOSTS`, `LOCATION`, manager identity and expected paths before adapting to another estate. These identifiers are configuration, not universal defaults.

The Windows source `Test-SysmonTelemetry.ps1` checks Sysmon64 running, readable/enabled Sysmon Operational and a recent process event, then appends a bounded JSON line. It must run from a protected directory as the existing SYSTEM five-minute/startup task, with the matching JSON localfile subscription. This package does not silently create that Windows task or weaken PowerShell policy. A producer failure and an absent producer are different controls.

The Linux first-install helper is intended for a fresh reviewed Wazuh manager only. It refuses existing destinations/rule IDs, saves original `ossec.conf`, runs isolated tests and manager configuration tests, and lays down units. It does **not** restart Wazuh or enable the timer. Keep the whole repository layout intact because the installer reads the single canonical XML file.

```bash
# Linux manager only, after reviewing paths/IDs, existing producer collection and rollback.
# This writes protected configuration; do not run it merely to try the Python tests.
sudo python3 tools/telemetry-watch/install_watch.py
```

Then review the installation receipt and unit verification, arrange a separate intentional manager activation window, and verify actual source/delivery before enabling the timer. No automatic restart command is included. Existing lab installations should be inspected in place, not reinstalled.

## Runtime inspection and recovery

Read the timer/service journal and the protected SQLite state. A fresh five-minute producer may look stale for real reasons; check host identity, source availability and event-time offsets before changing thresholds. Do not delete state or reset a cursor to hide a gap. Keep source, state and outbox evidence during an investigation.

The systemd unit has no network, no new privileges, a read-only system/home isolation, 96 MiB memory limit, 10 percent CPU quota and 30-second runtime limit. Code is versioned under `/opt/homelab-telemetry-watch/20261024`; state and output are under `/var/lib/homelab-telemetry-watch` and `/var/log/homelab-telemetry-watch`.

Rollback starts by stopping this timer, preserving its state/outbox and inspecting the exact before/after configuration hashes. Restore only this installation's owned change if configuration still matches its after-hash. Never restore a stale whole manager configuration over newer work. Endpoint reporting, original events and unrelated detections remain separate.

See [accepted live controls and limits](../../docs/validation-status.md). The watcher’s Linux tests passed historically; this candidate records its own fresh test result in the local release receipt.
