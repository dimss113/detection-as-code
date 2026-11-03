# UC-02: Security event log cleared

| | |
| --- | --- |
| Rule | [`rules/windows/uc02_security_log_cleared.yml`](../../rules/windows/uc02_security_log_cleared.yml) |
| Splunk | [`queries/splunk/uc02_security_log_cleared.spl`](../../queries/splunk/uc02_security_log_cleared.spl) |
| ATT&CK | Defense Impairment, T1685.005 (Clear Windows Event Logs, ATT&CK v20) |
| Severity | high |

## Why it matters

Attackers clear the Security log to remove evidence of logons, privilege use and account changes. Legitimate clearing is rare, so the event itself is the signal.

## Data source

- Security log, event 1102. Windows always writes it when the Security log is cleared; no extra audit policy is needed.
- The provider is `Microsoft-Windows-Eventlog`, not `Microsoft-Windows-Security-Auditing`. A mapping that filters the Security channel by the auditing provider never sees it.

## Logic

Any event 1102 in the Security channel.

## False positives and tuning

- Planned maintenance. It should be announced and done by a known admin account; record it as a time-boxed exception, not a permanent filter.

## Triage

1. Which account cleared the log (`SubjectUserName`), and from which host?
2. What happened just before? Use the SIEM copy of the log: events already forwarded are not lost.
3. Look for the same account on other hosts in the same time window.

## Test evidence

Attack sample `Defense Evasion/DE_1102_security_log_cleared.evtx`. Event 1102 also appears in several other samples because their authors cleared the log before recording.

## Limitations

- Covers the Security log only. Clearing the System log (event 104) or stopping the event log service is not covered yet.
