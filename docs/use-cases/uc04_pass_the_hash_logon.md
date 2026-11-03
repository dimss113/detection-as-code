# UC-04: Logon with new credentials via seclogo (pass-the-hash)

| | |
| --- | --- |
| Rule | [`rules/windows/uc04_pass_the_hash_logon.yml`](../../rules/windows/uc04_pass_the_hash_logon.yml) |
| Splunk | [`queries/splunk/uc04_pass_the_hash_logon.spl`](../../queries/splunk/uc04_pass_the_hash_logon.spl) |
| ATT&CK | Lateral Movement, T1550.002 Use Alternate Authentication Material: Pass the Hash |
| Severity | high |

## Why it matters

With a stolen NTLM hash, Mimikatz `sekurlsa::pth` starts a process that authenticates to other hosts as the victim, without knowing the password. On the attacker's host this leaves a logon type 9 (new credentials) through `seclogo`.

## Data source

- Security log, event 4624, on the host where the tool runs.
- Requires "Audit Logon" (Success).

## Logic

Event 4624 with `LogonType` 9, `LogonProcessName` `seclogo` and `AuthenticationPackageName` `Negotiate`.

## False positives and tuning

- Admins using `runas /netonly` produce the same pattern. Exceptions should name the admin account and host, with an expiry.

## Triage

1. Which account started it (`SubjectUserName`)? Newer Windows versions also record the credentials that were used (`TargetOutboundUserName`); the attack sample does not have it.
2. Look for network logons (4624 type 3, NTLM) by the outbound account on other hosts right after.
3. If unexpected: reset the outbound account and investigate where its hash was taken (see UC-01, UC-09).

## Test evidence

Attack sample `Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`.

## Limitations

- Detects the source host only. Pass-the-hash seen from the target side (network logon with NTLM) needs a separate rule.
