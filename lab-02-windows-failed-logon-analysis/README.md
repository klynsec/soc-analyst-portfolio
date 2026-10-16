# [Lab 02: Windows Failed Logon Analysis with Splunk](lab-02-windows-failed-logon-analysis/README.md)
## 1. Objective

The objective of this lab was to collect and analyze Windows Security event logs using Splunk Enterprise, identify failed logon attempts (Event ID 4625), and understand how authentication events can help a Security Operations Center (SOC) analyst investigate potentially suspicious activity.

I generated three failed logon events by deliberately entering an incorrect password on my own Windows machine.

## 2. Lab Environment

- **Host:** Windows laptop (8 GB RAM, HDD)
- **SIEM:** Splunk Enterprise 10.6.0.5
- **Licence:** 60-day trial
- **Data Source:** Windows Application, Security, and System event logs
- **Destination Index:** `main`
- **Test Date:** 15 October 2026

## 3. Tools and Technologies

- Splunk Enterprise
- Windows Event Viewer / Windows Security event logs
- Splunk Search Processing Language (SPL)

## 4. Methodology

### Step 1: Splunk Installation

I installed Splunk Enterprise locally on my Windows laptop and accessed the web interface through `http://localhost:8000`.

### Step 2: Windows Event Log Collection

I configured local Windows event log collection through Splunk's data input settings, selecting the Application, Security, and System logs.

To verify that Security events were being collected, I ran the following SPL search:

```spl
index=main source="WinEventLog:Security"
```

This returned Windows Security events indexed by Splunk.

### Step 3: Generate Controlled Failed Logons

To generate test data, I locked my Windows screen and deliberately entered an incorrect password three times before signing in successfully.

This was a controlled test performed on my own machine.

### Step 4: Identify Failed Logon Events

I searched for Windows Security Event ID 4625, which records failed logon attempts.

```spl
index=main source="WinEventLog:Security" EventCode=4625
```

### Step 5: Extract Relevant Event Fields

I used the following search to display selected fields for investigation:

```spl
index=main source="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Logon_Type, Failure_Reason, Source_Network_Address
```

The table was intended to make it easier to review the event timestamps, account information, logon type, failure reason, and source network address where those fields were available.

## 5. Findings

During the investigation, I observed the following:

- Splunk collected 236 Windows Security events within a 60-minute observation window.
- The collected events included Event ID 4624, associated with successful logons, and Event ID 4672, associated with special privileges assigned to a new logon.
- Three Event ID 4625 events were recorded at approximately 15:47:37, 15:47:41, and 15:47:45.
- The failed logon events occurred approximately four seconds apart, matching the three incorrect-password attempts I deliberately generated.
- I subsequently signed in successfully.

### Summary of Observed Events

| Event ID | Meaning | Observation |
|---|---|---|
| 4624 | Successful logon | Present in the collected logs |
| 4625 | Failed logon | Three events observed during the controlled test |
| 4672 | Special privileges assigned to a new logon | Present in the collected logs |

**Event investigation details:** Account name, logon type, failure reason, and source network address should be documented from the expanded Event ID 4625 event when available.

## 6. Analysis

The three failed logon events occurred within a short period and corresponded with the test I performed. Given the controlled circumstances, the pattern was consistent with repeated incorrect-password attempts by a legitimate user.

However, repeated failed logons can also indicate suspicious activity, including password guessing or brute-force attempts. A SOC analyst should not classify an event as malicious based on Event ID 4625 alone.

Useful investigation factors include:

- **Frequency:** How many failed logons occurred within a specific time window?
- **Account:** Was one account targeted, or were several accounts affected?
- **Source:** Did the attempts originate from the same workstation or network address?
- **Timing:** Did the failures occur in a rapid sequence or at unusual hours?
- **Outcome:** Were the failed attempts followed by a successful logon?
- **Logon type:** Was the activity associated with an interactive session, remote access, or another logon method?

A possible detection approach would be to count failed logons by account or source within a defined time window and flag activity that exceeds a configured threshold. For example, a rule could flag more than five failed logons within five minutes for further investigation.

This threshold is illustrative and would require testing and tuning in a real environment.

No Splunk alert was configured or tested as part of this lab.

## 7. Limitations

- Testing was conducted on my own Windows machine in a controlled environment.
- Only three failed logon events were deliberately generated.
- The exercise did not establish a long-term baseline for normal authentication activity.
- No alerting rule or automated response was implemented.
- The results demonstrate the events observed during this test and do not establish how a detection rule would perform in a production network.

## 8. Lessons Learned

Through this lab, I gained practical experience in:

- Installing and accessing Splunk Enterprise locally.
- Configuring Windows event log collection.
- Searching indexed Windows Security events using SPL.
- Filtering authentication events by Event ID.
- Displaying relevant event fields in a results table.
- Understanding the significance of Windows Event IDs 4624, 4625, and 4672.
- Interpreting repeated failed logons in context rather than automatically treating them as malicious.
- Recognizing the importance of event frequency, account context, source information, and successful logons during an investigation.

## 9. Evidence

Screenshots from the lab are included to demonstrate the data collection and investigation process.

1. **Security Events in Splunk:** Demonstrates that Windows Security events were collected.
2. **Expanded Failed Logon Event:** Shows the details of an Event ID 4625 record.
3. **Failed Logon Results Table:** Shows the timestamps and selected fields from the failed logon events.

## 10. Conclusion

This lab provided hands-on experience collecting Windows Security logs in Splunk Enterprise and investigating failed authentication attempts.

By generating controlled failed logons and searching for Event ID 4625, I observed how Windows records authentication failures and how a SIEM can help an analyst examine them.

The exercise strengthened my understanding of basic log analysis and authentication monitoring. It also provided a foundation for future labs involving correlation searches, threshold-based detections, alert configuration, and security incident investigation.

**Lab Status:** Completed — log collection, SPL searches, and controlled failed-logon analysis performed.

