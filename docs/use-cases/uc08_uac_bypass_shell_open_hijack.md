# UC-08: UAC bypass via shell open command hijack

| | |
| --- | --- |
| Rule | [`rules/windows/uc08_uac_bypass_shell_open_hijack.yml`](../../rules/windows/uc08_uac_bypass_shell_open_hijack.yml) |
| Splunk | [`queries/splunk/uc08_uac_bypass_shell_open_hijack.spl`](../../queries/splunk/uc08_uac_bypass_shell_open_hijack.spl) |
| ATT&CK | Privilege Escalation, T1548.002 Abuse Elevation Control Mechanism: Bypass UAC |
| Severity | high |

## Why it matters

Some Windows binaries elevate automatically without a UAC prompt (`eventvwr.exe`, `fodhelper.exe`, `sdclt.exe`). They read a `shell\open\command` key in the user's registry first. An attacker writes their command there and gets admin rights without a prompt.

## Data source

- Sysmon event 13 (registry value set) covering the user classes keys. Sysmon records them as `HKU\<SID>_Classes\...`, which is the same place as `HKCU\Software\Classes`.

## Logic

A registry value is set under `mscfile`, `ms-settings`, `exefile` or `Folder` `\shell\open\command`.

## False positives and tuning

- Unlikely in user hives. Software that changes file associations writes to other keys.

## Triage

1. What command was written (`Details`)?
2. Which process wrote it, and did an auto-elevating binary start right after?
3. Remove the key, then investigate what the elevated process did.

## Test evidence

Attack sample `Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx`.

## Limitations

- UAC bypasses that use other keys (for example `DelegateExecute` alone, or COM hijacks) are not covered.
