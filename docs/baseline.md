# Lab baseline

`baseline/win11-lab.json` is normal activity from a lab Windows workstation. `make test` fails if any rule matches it, so a rule that would be noisy in production is caught before it is merged.

## Machine

| | |
| --- | --- |
| OS | Windows 11 Pro ARM64 in a UTM virtual machine, not joined to a domain |
| Sysmon | 15.23 (`Sysmon64a.exe`, the ARM64 build) |
| Sysmon config | `sysmonconfig-15.21.xml` from sysmon-modular release [`configs-a45dedb13a43`](https://github.com/olafhartong/sysmon-modular/releases/tag/configs-a45dedb13a43), SHA-256 `64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e` |
| Audit policy | Logon (success and failure), Security Group Management (success) |
| PowerShell | Script block logging on (event 4104) |
| Collected | November 2026, about 40 minutes including one restart |

## Activity

User activity:
- Sign in, browse public websites in Edge
- Install 7-Zip and Notepad++ with winget
- File Explorer and Notepad, compress a folder with 7-Zip
- Check for Windows updates, run a Microsoft Defender quick scan
- Task Manager

IT support activity, done by an administrator:
- PowerShell inventory: processes, services, local administrators, network configuration
- Create a support account `helpdesk`, add it to the local Administrators group, remove it at the end
- `runas /netonly` with the `helpdesk` account, to use it for network access only
- Run an inventory command through WMI (`Win32_Process.Create`), the way management tools do
- Restart

The IT support tasks are known false positive sources for UC-04, UC-07 and UC-10. They are in the baseline on purpose, so those rules must handle them before they can be merged.

## Events kept

Only the events the rules can match, the same channels and event IDs as the Chainsaw mapping:

| Channel | Event IDs |
| --- | --- |
| Microsoft-Windows-Sysmon/Operational | 1, 10, 13 |
| Microsoft-Windows-PowerShell/Operational | 4104 |
| Security | all |
| System | all |

## Sanitization

`scripts/baseline.py build` replaces these values before anything is written to the repository:

| Real value | Replaced with |
| --- | --- |
| Computer name | `WS-LAB01` |
| User names (profile folders, the Sysmon `User` field) | `labuser` |
| Domain SIDs `S-1-5-21-...` | `S-1-5-21-1111111111-2222222222-3333333333`, the last part (RID) is kept |
| IP addresses, except loopback and multicast | `192.0.2.0/24` and `2001:db8::/120`, ranges reserved for documentation |
| Email addresses | `labuser@example.com` |

- `make test` runs `scripts/baseline.py check` first. It fails if a file in `baseline/` still has another computer name, a domain SID, an IP address or an email address.
- Raw `.evtx` files stay outside the repository.
- The replacement does not change what the rules see: the 10 public attack samples, sanitized the same way, still give the same 17 detections.

## Rebuild

On the VM, in an administrator PowerShell, export everything after the start time saved in `C:\baseline\start.txt`:

```powershell
$start = Get-Content C:\baseline\start.txt
$query = "*[System[TimeCreated[@SystemTime>='$start']]]"
$logs = 'Microsoft-Windows-Sysmon/Operational', 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational'
foreach ($log in $logs) {
    $file = 'C:\baseline\raw\' + ($log -replace '[/-]', '_') + '.evtx'
    wevtutil epl $log $file "/q:$query" /ow:true
}
```

Copy the `.evtx` files to a folder outside the repository, then:

```bash
make baseline RAW=~/lab-baseline-raw
make test
```

## Limitations

- One workstation and about 40 minutes of activity. A bank's fleet runs software this VM does not (EDR, backup agents, software deployment), and that software will cause false positives this baseline cannot show.
- The VM is not a domain controller, so the baseline cannot show false positives for UC-03 (DCSync).
- Only events the Sysmon config logs can be tested. The config filters process creation, so a rule can stay quiet here because the event was never logged.
- User names are found in profile folders and the Sysmon `User` field. A name that appears only somewhere else would not be replaced, so the file is also searched by hand before each commit.
