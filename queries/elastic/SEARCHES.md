# Elastic searches

Open Kibana **Discover**. At the upper left, click the current **Data view** name and select **Homelab Telemetry** (the saved view over `filebeat-*`). This chooses searchable indices; it does not install Filebeat. Use the main query bar, not the left-hand field-name search. Set an absolute time window covering the action and arrival, and clear unrelated filter chips.

## One marked HTTP action

Make one harmless request from a separate physical lab host, record its full path including the slash, UTC time and client status. Search the actual marker:

```text
host.name : "ndr01" and event.dataset : ("zeek.http" or "suricata.eve") and url.original : "/REPLACE-WITH-YOUR-EXACT-PATH"
```

Expand each record and compare timestamp/offset, source/destination IP, destination port, HTTP status and `network.community_id`. HTTP metadata establishes observed activity; an `alert` record establishes a signature match. Row count is not request count.

Use the same Community ID and the action window to find related flow records:

```text
host.name : "ndr01" and network.community_id : "REPLACE-WITH-ACTUAL-COMMUNITY-ID"
```

No results: check exact slash/path, data view, time and field mappings first. Compare native sensor records to indexing; never call an empty query proof of no execution or no compromise.

## Endpoint healthy reports and observer transitions

```text
event.dataset : "wazuh.alerts" and wazuh.rule.id : ("100892" or "100893")
```

```text
event.dataset : "wazuh.alerts" and wazuh.rule.id : ("100894" or "100895" or "100896" or "100897")
```

Health reports are attributed to their endpoint agent. Arrival-watch observations originate at SIEM01 agent 000; the affected endpoint is in the structured target and description. Filtering observer alerts as agent003/SRV01 would hide those records. Open the document, compare its actual Wazuh source ID and target, then match the exact case source in LabWatch. Field names in raw Wazuh indices differ from the normalized Filebeat `wazuh.*` fields used here.
