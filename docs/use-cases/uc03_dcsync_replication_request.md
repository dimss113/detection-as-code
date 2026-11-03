# UC-03: Directory replication requested by a non-computer account (DCSync)

| | |
| --- | --- |
| Rule | [`rules/windows/uc03_dcsync_replication_request.yml`](../../rules/windows/uc03_dcsync_replication_request.yml) |
| Splunk | [`queries/splunk/uc03_dcsync_replication_request.spl`](../../queries/splunk/uc03_dcsync_replication_request.spl) |
| ATT&CK | Credential Access, T1003.006 OS Credential Dumping: DCSync |
| Severity | critical |

## Why it matters

DCSync (Mimikatz `lsadump::dcsync`, Impacket `secretsdump`) asks a domain controller to replicate password data, the same way domain controllers sync with each other. The attacker gets the hash of any account, including `krbtgt`, which means full domain compromise.

## Data source

- Security log on domain controllers, event 4662.
- Requires "Audit Directory Service Access" (Success) and auditing of the replication rights on the domain root object.

## Logic

Event 4662 where `Properties` contains one of the replication rights (`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, `DS-Replication-Get-Changes-In-Filtered-Set`), and the account does not end in `$`. Domain controllers replicate with their computer accounts, which end in `$`.

## False positives and tuning

- Entra ID (Azure AD) Connect and other directory sync accounts. Add an exception for the exact sync account, with an owner and expiry.

## Triage

1. Treat as an incident until proven otherwise.
2. Which account and which source IP (match with the 4624 logon on the same DC)?
3. If not a known sync account: disable the account, isolate the source host, and plan a `krbtgt` reset (twice).

## Test evidence

Attack sample `Credential Access/CA_DCSync_4662.evtx`.

## Limitations

- Only works with directory service auditing enabled on every domain controller.
- An attacker who controls a computer account (name ending in `$`) is filtered.
