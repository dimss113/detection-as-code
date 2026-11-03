# UC-09: PowerShell script block with credential dumping functions

| | |
| --- | --- |
| Rule | [`rules/windows/uc09_powershell_credential_dumping.yml`](../../rules/windows/uc09_powershell_credential_dumping.yml) |
| Splunk | [`queries/splunk/uc09_powershell_credential_dumping.spl`](../../queries/splunk/uc09_powershell_credential_dumping.spl) |
| ATT&CK | Credential Access, T1003.001 LSASS Memory; Execution, T1059.001 PowerShell |
| Severity | high |

## Why it matters

Attackers dump credentials from PowerShell without dropping a binary: `Invoke-Mimikatz`, or a script that calls `MiniDumpWriteDump` on LSASS. Script block logging records the code even when it is loaded only in memory.

## Data source

- PowerShell Operational log, event 4104.
- Requires "Turn on PowerShell Script Block Logging" (Group Policy).

## Logic

`ScriptBlockText` contains `MiniDumpWriteDump`, `Invoke-Mimikatz`, `sekurlsa::` or `kerberos::`.

## False positives and tuning

- Red team or training scripts. Exceptions should name the host and account, with an expiry.

## Triage

1. Read the full script block, and the blocks around it (same `ScriptBlockId`).
2. Which user and parent process ran PowerShell?
3. Look for LSASS access (UC-01) and dump files on the same host.

## Test evidence

Attack sample `Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx`.

## Limitations

- Obfuscated scripts that build these strings at run time are missed until they are decoded.
