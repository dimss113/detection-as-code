# UC-05: Service installed with a command shell or admin share path

| | |
| --- | --- |
| Rule | [`rules/windows/uc05_suspicious_service_installed.yml`](../../rules/windows/uc05_suspicious_service_installed.yml) |
| Splunk | [`queries/splunk/uc05_suspicious_service_installed.spl`](../../queries/splunk/uc05_suspicious_service_installed.spl) |
| ATT&CK | Execution, T1569.002 System Services: Service Execution; Lateral Movement, T1021.002 SMB/Windows Admin Shares |
| Severity | high |

## Why it matters

PsExec, Impacket `psexec`/`smbexec` and many attack frameworks run commands on a remote host by creating a service. The service command line usually contains a shell or points to a binary copied through `ADMIN$` or `C$`.

## Data source

- System log, event 7045 (a service was installed), from provider `Service Control Manager`. Logged by default.

## Logic

Event 7045 where `ImagePath` contains `cmd.exe`, `cmd /c`, `%COMSPEC%`, `powershell`, `rundll32`, `\ADMIN$\` or `\C$\`, or the service name is `PSEXESVC`.

## False positives and tuning

- Software deployment tools (SCCM, PDQ) and admins using PsExec. Exceptions should match the exact service name and path, with an owner and expiry.

## Triage

1. Read `ImagePath`: what does the service run?
2. Which account installed it, and from which host (match the 4624 type 3 logon at the same time)?
3. If unknown: stop and delete the service, isolate the host, and check the source host.

## Test evidence

Attack sample `Lateral Movement/LM_Remote_Service02_7045.evtx`.

## Limitations

- A service that runs a renamed binary from a local path, without a shell, is missed.
