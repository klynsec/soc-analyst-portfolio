# Lab 03: Suricata EVE JSON Analysis with Splunk

## Objective
To import Suricata EVE JSON logs into Splunk Enterprise and investigate the recorded network events using Splunk Search Processing Language (SPL).

## Tools Used
- **Suricata 8.0.7** — Network threat detection and traffic monitoring
- **Splunk Enterprise 10.6.0.5** — Log indexing and analysis
- **Kali Linux** — Environment used to generate Suricata logs
- **Windows** — Host environment running Splunk Enterprise

## Lab Methodology
1. Configured Suricata to produce EVE JSON logs.
2. Copied a saved EVE JSON log file from Kali Linux to Windows.
3. Created a dedicated `suricata` index in Splunk.
4. Imported the saved JSON file using the `_json` source type.
5. Searched and analysed the imported events using SPL.

## Results

A total of **962 events** were returned from the imported dataset.

| Event type | Count |
|---|---:|
| Stats | 912 |
| Flow | 48 |
| TLS | 2 |
| **Total** | **962** |

The dataset contained Suricata statistics, network-flow records, and TLS events.

## SPL Queries

### Search all imported events
```spl
index=suricata
```

### Summarise event types
```spl
index=suricata
| stats count by event_type
```

### Investigate network flows
```spl
index=suricata event_type=flow
| table _time src_ip dest_ip src_port dest_port proto app_proto flow.state
```

## Screenshots
Screenshots documenting the import, event-type breakdown, and network-flow investigation will be added to this repository.

## Limitations
- This exercise used a saved EVE JSON snapshot, not a live Suricata-to-Splunk feed.
- The event counts describe the imported dataset only.
- No Suricata alert events have been confirmed in this analysis.
- The presence of flow and TLS records does not, by itself, establish malicious activity.

## Skills Practised
- Importing JSON logs into Splunk
- Searching indexed security telemetry
- Writing basic SPL queries
- Summarising event types
- Inspecting network-flow records
- Documenting investigation evidence and limitations
