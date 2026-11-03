# UC-10: Member added to the local Administrators group

| | |
| --- | --- |
| Rule | [`rules/windows/uc10_member_added_to_local_admins.yml`](../../rules/windows/uc10_member_added_to_local_admins.yml) |
| Splunk | [`queries/splunk/uc10_member_added_to_local_admins.spl`](../../queries/splunk/uc10_member_added_to_local_admins.spl) |
| ATT&CK | Persistence, T1098 Account Manipulation |
| Severity | medium |

## Why it matters

Adding an account to Administrators keeps admin access even after the original foothold is removed. It is also a common step for insiders.

## Data source

- Security log, event 4732.
- Requires "Audit Security Group Management" (Success).

## Logic

Event 4732 where the group SID (`TargetSid`) is `S-1-5-32-544`, the built-in Administrators group. Matching the SID works on any Windows language.

## False positives and tuning

- Approved admin changes. Medium severity, because the right response is to match it with a change ticket.

## Triage

1. Who was added (`MemberSid`, `MemberName`) and by whom (`SubjectUserName`)?
2. Is there an approved change ticket?
3. If not: remove the member and investigate the account that made the change.

## Test evidence

Attack sample `Persistence/Network_Service_Guest_added_to_admins_4732.evtx`.

## Limitations

- Domain groups such as Domain Admins (event 4728 and 4756) are not covered yet.
