# Architecture

Names describe lab roles, not Internet-exposed services. Software versions and historical acceptance are in the validation record; this drawing is not a guarantee every machine is running at every moment.

```mermaid
flowchart LR
  subgraph ENDPOINTS[Domain Windows endpoints]
    DC[DC01: AD/DNS and Windows telemetry]
    SRV[SRV01: lab web/mail and LabWatch]
    WS[WS01 / optional WS02]
  end
  subgraph PLATFORM[Monitoring platform VMs]
    W[SIEM01: Wazuh manager/indexer and Velociraptor server]
    E[SIEM02: Elasticsearch and Kibana]
  end
  subgraph ATTACKBOX[ATTACKBOX: separate physical host]
    N[NDR01: Zeek, Suricata, EveBox and Filebeat]
    K[Kali practice guest]
  end
  DC & SRV & WS -->|Windows events and health samples| W
  W -->|separate Wazuh alert forwarder| E
  W -->|direct bounded source reader| SRV
  N -->|Filebeat sensor records| E
  SWITCH[Managed switch: ingress mirror ports 1-3 to 4] -->|USB capture NIC, no IP| N
  ANALYST[Analyst browser / PowerShell] --> E
  ANALYST --> SRV
  ANALYST --> N
```

LabWatch consumes Wazuh independently of Elastic. It keeps incidents, evidence, knowledge and audit history; an Elasticsearch document count is not an incident count. Normal promotion is level 9 or above plus explicitly selected lower-level exceptions, with existing exclusions and bounded grouping.

NDR01's management NIC and passive USB capture NIC serve different purposes. A same-hypervisor conversation can bypass the physical switch mirror. A marked ATTACKBOX-to-SRV01 request exercises the physical observation path; an ordinary 404 response still establishes an HTTP response.

Wazuh is the alert source. Elastic provides search/correlation. EveBox displays Suricata events and alerts, not Zeek. Velociraptor supplies separately scoped endpoint investigation. Splunk is retired; preserved historical imports are not a complete copy of every old source.

Windows/Pacific display time and UTC sensor time must be normalized by offset. A URL marker identifies an action, Zeek uid joins native Zeek records, and Community ID identifies a network flow across sensor datasets. None is a username or a case number.
