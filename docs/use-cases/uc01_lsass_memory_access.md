# UC-01: LSASS memory access by unexpected process

| | |
| --- | --- |
| Rule | [`rules/windows/uc01_lsass_memory_access.yml`](../../rules/windows/uc01_lsass_memory_access.yml) |
| Splunk | [`queries/splunk/uc01_lsass_memory_access.spl`](../../queries/splunk/uc01_lsass_memory_access.spl) |
| ATT&CK | Credential Access, T1003.001 OS Credential Dumping: LSASS Memory |
| Severity | high |

## Why it matters

LSASS holds the credentials of logged-on users: NTLM hashes, Kerberos tickets and sometimes cleartext passwords. Reading its memory (Mimikatz `sekurlsa::logonpasswords`, ProcDump, comsvcs MiniDump) gives an attacker credentials to move to other hosts.

## Data source

- Sysmon event 10 (ProcessAccess) for `TargetImage` `lsass.exe`.
- Many Sysmon configs turn event 10 off because it is noisy. Include it at least for `lsass.exe`.

## Logic

A process opens `lsass.exe` with an access mask that includes memory read (`0x1010`, `0x1410`, `0x1438`, `0x143a`) or full access (`0x1fffff`), and the process does not run from `C:\Windows\System32\` or `C:\Program Files\`.

## False positives and tuning

- EDR, antivirus and backup agents that read LSASS. Most run from `C:\Program Files\` and are filtered already.
- Agents installed elsewhere: add an exception for the exact `SourceImage`, with an owner and expiry. Do not exclude by file name only.

## Triage

1. Who is `SourceImage`? Check its path, signer and hash.
2. Which user ran it, and was that user an admin on this host?
3. Look for a dump file written at the same time (Sysmon 11, `*.dmp`) and for new logons from this account on other hosts.
4. If it is not a known tool: isolate the host and reset the passwords of accounts that were logged on.

## Test evidence

Attack sample `Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx` (Mimikatz, `0x1010`).

## Limitations

- Matches exact access masks. A tool that asks for another combination with memory read is missed.
- A tool copied into `C:\Windows\System32\` by an admin is filtered.
