# Lab 04: Custom Suricata Rule Detection and Splunk Alert Investigation

## Overview
In this lab, I created and tested a custom Suricata detection rule, generated a matching HTTP request, verified that Suricata detected the activity, and analyzed the resulting alert in Splunk Enterprise.

The objective was to understand how network-based intrusion detection systems (NIDS) identify matching traffic and how security alerts can be reviewed and investigated in a SIEM platform.

## Objectives
- Create a custom Suricata detection rule.
- Validate the Suricata configuration and confirm that the rule loaded successfully.
- Generate HTTP traffic matching the rule.
- Verify the resulting alert in Suricata's EVE JSON log.
- Import the alert event into Splunk Enterprise.
- Search, filter, and analyze the alert using SPL.

## Tools and Environment
- **Suricata 8.0.7** — Network intrusion detection.
- **Splunk Enterprise 10.6.0.5** — Security event search and investigation.
- **Kali Linux** — Virtual machine used to run Suricata and generate test traffic.
- **VirtualBox** — Virtualization environment.
- **Windows** — Host operating system running Splunk Enterprise.
- **EVE JSON** — Suricata event logging format.

## Step 1: Create a Custom Detection Rule

I created a local Suricata rule to detect an HTTP request containing the URI `/suricata-lab-test`.

```text
alert http any any -> any any (msg:"LOCAL TEST - Suricata HTTP detection"; flow:established,to_server; http.uri; content:"/suricata-lab-test"; sid:1000001; rev:1;)
```

The rule uses the following components:

- `alert http` — Generates an alert for matching HTTP traffic.
- `flow:established,to_server` — Matches established traffic travelling toward the server.
- `http.uri` — Inspects the HTTP request URI.
- `content:"/suricata-lab-test"` — Searches for the specified URI content.
- `sid:1000001` — Identifies the custom rule.
- `rev:1` — Indicates the rule revision.

I added the local rule to Suricata's rule configuration and validated the configuration before running the test.

## Step 2: Validate Suricata

I ran Suricata's configuration test to check that the configuration and rules loaded successfully.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
```

The test completed successfully. Suricata reported that **53,236 rules were loaded**, with zero failed or skipped rules.

## Step 3: Generate Test HTTP Traffic

I generated an HTTP request containing the URI specified in my custom rule:

```bash
curl -v --max-time 10 http://neverssl.com/suricata-lab-test
```

The web server returned HTTP status `404`. This was an HTTP response from the server and did not prevent Suricata from detecting the matching request.

## Step 4: Verify the Alert in EVE JSON

I inspected Suricata's EVE JSON log at:

```text
/var/log/suricata/eve.json
```

I located the event associated with my custom rule and extracted the matching alert into a separate JSON file for analysis in Splunk.

The alert contained the following information:

| Field | Observed value |
|---|---|
| Event type | `alert` |
| Signature | `LOCAL TEST - Suricata HTTP detection` |
| Signature ID | `1000001` |
| Source IP | `10.0.2.15` |
| Destination IP | `34.223.124.45` |
| Destination port | `80` |
| Protocol | TCP |
| HTTP method | `GET` |
| HTTP URI | `/suricata-lab-test` |
| HTTP status | `404` |
| Alert action | `allowed` |
| Severity | `3` |

The `allowed` action indicates that Suricata detected and logged the traffic but did not block it.

## Step 5: Import and Investigate the Alert in Splunk

I manually imported the extracted JSON alert into Splunk Enterprise using the `_json` source type and the existing `suricata` index.

I then searched for the custom alert and displayed the relevant fields in a structured investigation table.

```spl
index=suricata sourcetype=_json "LOCAL TEST - Suricata HTTP detection"
| table _time host src_ip dest_ip dest_port event_type alert.signature alert.signature_id alert.severity alert.action http.http_method http.url http.status
```

Splunk successfully returned the matching event, allowing me to review the timestamp, network endpoints, rule signature, severity, action, and HTTP request details in one place.

## Key Findings

- The custom Suricata rule loaded successfully.
- The generated HTTP request matched the rule's URI condition.
- Suricata recorded the matching activity as an alert in EVE JSON.
- The alert was successfully imported into Splunk and retrieved using SPL.
- The destination returned HTTP `404`, while Suricata recorded the alert action as `allowed`.
- The test demonstrated the basic workflow of custom detection, alert logging, SIEM ingestion, and investigation.

## Important Limitation

This lab used a **manually extracted and uploaded JSON alert**. It did not establish continuous, automated ingestion from Suricata into Splunk. The result demonstrates the detection and investigation workflow, rather than a fully integrated real-time monitoring pipeline.

## Skills Practised

- Suricata rule creation and configuration validation.
- HTTP traffic inspection and rule-based detection.
- EVE JSON log analysis.
- Splunk data ingestion and SPL searching.
- Security alert triage and interpretation.
- Documenting investigation findings and technical limitations.

## Conclusion

This lab strengthened my understanding of how custom network detection rules generate security alerts and how those alerts can be examined in a SIEM. It also gave me practical experience with Suricata, structured JSON logs, and Splunk Search Processing Language (SPL).

The next step is to explore automated log forwarding from Suricata to Splunk to support continuous security monitoring.

