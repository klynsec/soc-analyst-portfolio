# Lab 02: Windows Failed Logon Analysis with Splunk

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
- Windows Security event logs
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

The table was intended to make it easier to review event timestamps, account information, logon type, failure reason, and source network address where those fields were available.

## 5. Findings

- A search for Event ID 4625 returned three failed logon events at 15:47:37, 15:47:41, and 15:47:45, approximately four seconds apart. This matched the timing of the three incorrect sign-in attempts I deliberately generated at the Windows lock screen.
- All three events contained the same observed details: Logon Type 2 (interactive), Source Network Address `127.0.0.1`, Logon Process `User32`, Authentication Package `Negotiate`, and caller process `svchost.exe`.
- The Subject fields identified the computer's local SYSTEM account, while the target account fields under "Account For Which Logon Failed" were blank.
- The recorded failure reason was "An Error occurred during Logon." The Status was `0xC000006D`, and the Sub Status was `0xC0000380`.
- Splunk also collected Event ID 4624 (successful logon) and Event ID 4672 (special privileges assigned to a new logon) during the same observation period.

### Summary of Observed Events

| Event ID | Meaning | Observation |
|---|---|---|
| 4624 | Successful logon | Present in the collected logs |
| 4625 | Failed logon | Three events observed during the controlled test |
| 4672 | Special privileges assigned to a new logon | Present in the collected logs |

## 6. Analysis

The three Event ID 4625 records occurred within seconds of one another and matched the timing of my controlled test. This makes the incorrect sign-in attempts a plausible explanation for the observed events.

Logon Type 2 indicates an interactive logon attempt. The source address `127.0.0.1` is the IPv4 loopback address, which refers to the local machine. However, this field alone does not establish the complete authentication path or prove that the event could not be associated with other local authentication activity.

The status and substatus values also require careful interpretation. Although `0xC000006D` is a general logon failure status, the observed substatus `0xC0000380` differs from the commonly encountered incorrect-password status `0xC000006A`. I did not establish the exact cause of this substatus, so I have left it as an item for further investigation rather than assuming it represents a simple password mismatch.

The blank target account fields are another important observation. A detection that groups failed logons solely by the extracted account-name field may miss or incorrectly group events where that field is unavailable. In a production environment, an analyst would investigate the original event XML, verify field extraction, and determine whether other available fields could reliably identify the targeted account.

Repeated failed logons can also indicate suspicious activity, including password guessing or brute-force attempts. A SOC analyst should not classify an event as malicious based on Event ID 4625 alone.

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
- The exact cause of the observed substatus was not established.
- The target account fields were blank in the observed events.
- No alerting rule or automated response was implemented.
- The results demonstrate what Splunk recorded during this test and do not establish how a detection rule would perform in a production network.

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
- Identifying missing event fields and recognizing when additional investigation is necessary.

## 9. Evidence

The following screenshots document the data collection and investigation process.

1. **Security Events in Splunk:** Demonstrates that Windows Security events were collected.
2. **Expanded Failed Logon Event:** Shows the details of an Event ID 4625 record.
3. **Failed Logon Results Table:** Shows the timestamps and selected fields from the failed logon events.

If the screenshots are stored in an `evidence` folder alongside this README, use the following Markdown references:

```markdown
![Security events in Splunk](evidence/lab02-security-events.png)

![Expanded failed logon event](evidence/lab02-failed-logon-4625.png)

![Failed logon table](evidence/lab02-failed-logon-table.png)
```

Ensure that the filenames and folder paths match the files uploaded to GitHub.

## 10. Conclusion

This lab provided hands-on experience collecting Windows Security logs in Splunk Enterprise and investigating failed authentication attempts.

By generating controlled failed logons and searching for Event ID 4625, I observed how Windows records authentication failures and how a SIEM can help an analyst examine them.

The exercise strengthened my understanding of basic log analysis, authentication monitoring, event interpretation, and the importance of investigating unusual or incomplete event fields.

It also provided a foundation for future labs involving correlation searches, threshold-based detections, alert configuration, and security incident investigation.

**Lab Status:** Completed — Windows log collection, SPL searches, and controlled failed-logon analysis performed.
