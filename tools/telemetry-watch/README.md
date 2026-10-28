# Telemetry watchdog

Checks whether DC01 and SRV01 health reports reach Wazuh and records a missing-report or recovery transition.

Run its isolated tests from the repository root on Linux:

```bash
python3 -m unittest discover -s tools/telemetry-watch -p 'test_telemetry_watch.py' -v
```

Read the [operations guide](OPERATIONS.md) before installing or changing a running manager. [Validation status](../../docs/validation-status.md) lists what was actually tested.
