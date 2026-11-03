# UC-07: WMI provider host spawns a shell

| | |
| --- | --- |
| Rule | [`rules/windows/uc07_wmi_spawns_shell.yml`](../../rules/windows/uc07_wmi_spawns_shell.yml) |
| Splunk | [`queries/splunk/uc07_wmi_spawns_shell.spl`](../../queries/splunk/uc07_wmi_spawns_shell.spl) |
| ATT&CK | Execution, T1047 Windows Management Instrumentation |
| Severity | high |

## Why it matters

Impacket `wmiexec`, `wmic process call create` and many frameworks run commands on remote hosts through WMI. The command runs as a child of `WmiPrvSE.exe`.

## Data source

- Sysmon event 1 (process creation).

## Logic

`ParentImage` is `WmiPrvSE.exe` and `Image` is `cmd.exe`, `powershell.exe` or `pwsh.exe`.

## False positives and tuning

- Management and monitoring tools that run scripts through WMI. Exceptions should match the exact command line pattern, not the whole parent.

## Triage

1. Read the command line. `wmiexec` writes output to `\\127.0.0.1\ADMIN$\__<timestamp>`, a strong sign.
2. Which account logged on remotely (4624 type 3) just before, and from which host?
3. If unknown: isolate the host and investigate the source host and account.

## Test evidence

Attack sample `Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx`.

## Limitations

- WMI that runs a binary directly, without a shell, is missed.
