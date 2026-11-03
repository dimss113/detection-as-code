# Use cases

Each rule in `rules/windows/` has a use case doc here with the same file name. `make test` fails when one is missing.

| UC | Use case | ATT&CK | Log source | Severity |
| --- | --- | --- | --- | --- |
| [01](uc01_lsass_memory_access.md) | LSASS memory access by unexpected process | T1003.001 | Sysmon 10 | high |
| [02](uc02_security_log_cleared.md) | Security event log cleared | T1685.005 | Security 1102 | high |
| [03](uc03_dcsync_replication_request.md) | DCSync by a non-computer account | T1003.006 | Security 4662 (DC) | critical |
| [04](uc04_pass_the_hash_logon.md) | Pass-the-hash logon (type 9, seclogo) | T1550.002 | Security 4624 | high |
| [05](uc05_suspicious_service_installed.md) | Service with a shell or admin share path | T1569.002, T1021.002 | System 7045 | high |
| [06](uc06_regsvr32_scriptlet.md) | Regsvr32 scriptlet (Squiblydoo) | T1218.010 | Sysmon 1 | high |
| [07](uc07_wmi_spawns_shell.md) | WMI provider host spawns a shell | T1047 | Sysmon 1 | high |
| [08](uc08_uac_bypass_shell_open_hijack.md) | UAC bypass via shell open command | T1548.002 | Sysmon 13 | high |
| [09](uc09_powershell_credential_dumping.md) | PowerShell credential dumping | T1003.001, T1059.001 | PowerShell 4104 | high |
| [10](uc10_member_added_to_local_admins.md) | Member added to local Administrators | T1098 | Security 4732 | medium |

## Logging the rules depend on

| Requirement | Needed by |
| --- | --- |
| Sysmon with process creation (1), process access (10) for `lsass.exe`, registry value set (13) for user classes keys | UC-01, 06, 07, 08 |
| Audit Logon (Success) | UC-04 |
| Audit Security Group Management (Success) | UC-10 |
| Audit Directory Service Access (Success) on domain controllers, with auditing of the replication rights on the domain root | UC-03 |
| PowerShell Script Block Logging | UC-09 |
| Defaults (no extra policy) | UC-02, UC-05 |
