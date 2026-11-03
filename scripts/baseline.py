"""Builds the lab baseline from raw Windows event logs, and checks that a baseline is sanitized.

build: converts every .evtx file in a folder to JSON with Chainsaw, keeps only the events the rules
       can match, replaces the host name, user names, domain SIDs, IP addresses and email addresses
       with fixed lab values, and writes one JSON file.
check: fails if a file in baseline/ still contains a real host name, domain SID, IP address or email.

Run from the repo root:
  make baseline RAW=~/lab-baseline-raw    (build)
  make test                               (check, then the rule tests)
"""

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

CHAINSAW = Path(".tools/chainsaw")
BASELINE = Path("baseline")

# The events the rules can match (see the preconditions in the Chainsaw mapping). None = every event ID.
KEEP = {
    "Microsoft-Windows-Sysmon/Operational": {1, 10, 13},
    "Microsoft-Windows-PowerShell/Operational": {4104},
    "Security": None,
    "System": None,
}

# Lab values that replace the real ones. The IP ranges and example.com are reserved for documentation.
LAB_HOST = "WS-LAB01"
LAB_USER = "labuser"
LAB_SID = "S-1-5-21-1111111111-2222222222-3333333333"
LAB_NETS = {4: ipaddress.ip_network("192.0.2.0/24"), 6: ipaddress.ip_network("2001:db8::/120")}
LAB_EMAIL = "labuser@example.com"

# Fields that look like an IP address but are not one.
UNTOUCHED = {"FileVersion"}

# Built-in Windows names that are not people and are safe to publish.
NOT_PEOPLE = {"public", "default", "default user", "all users", "defaultuser0", "system",
              "local service", "network service", "anonymous logon", "-", ""}

# Names that also appear in normal Windows paths. Replacing them would corrupt the log.
TOO_COMMON = {"windows", "system", "system32", "microsoft", "users", "user", "program", "admin"}

SID = re.compile(r"S-1-5-21-\d+-\d+-\d+")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PROFILE = re.compile(r"\\Users\\([^\\\"\s]+)", re.IGNORECASE)


def kept(event: dict) -> bool:
    system = event["Event"]["System"]
    if system.get("Channel") not in KEEP:
        return False
    ids = KEEP[system["Channel"]]
    return ids is None or system.get("EventID") in ids


def strings(value):
    """Every string inside a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            if k not in UNTOUCHED:
                yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def find_names(events: list[dict]) -> tuple[set[str], set[str]]:
    """Host names come from the Computer field, user names from profile folders and Sysmon's User field."""
    hosts, users = set(), set()
    for event in events:
        computer = event["Event"]["System"].get("Computer") or ""
        hosts.update(n for n in {computer, computer.split(".")[0]} if n)
    short_hosts = {h.split(".")[0].lower() for h in hosts}
    for event in events:
        for text in strings(event):
            users.update(PROFILE.findall(text))
        user = (event["Event"].get("EventData") or {}).get("User") or ""
        domain, _, name = user.rpartition("\\")
        if domain.lower() in short_hosts | {"microsoftaccount", "azuread"}:
            users.add(name)
    return hosts, {u for u in users if u.lower() not in NOT_PEOPLE and not u.endswith("$")}


def word(name: str) -> re.Pattern:
    """Matches a name only as a whole word, so the user 'ann' does not change 'Channel'."""
    return re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", re.IGNORECASE)


def real_ip(text: str) -> bool:
    """True for an address that could point at a real machine (not loopback, multicast or the lab range)."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False  # not an address, for example 999.1.2.3
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast
                or ip in LAB_NETS[ip.version] or text == "255.255.255.255")


def clean(value, replace):
    if isinstance(value, str):
        return replace(value)
    if isinstance(value, dict):
        return {k: v if k in UNTOUCHED else clean(v, replace) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v, replace) for v in value]
    return value


def build(raw: Path, out: Path) -> int:
    files = sorted(raw.glob("*.evtx"))
    if not files:
        sys.exit(f"no .evtx files in {raw}")
    events = []
    for evtx in files:
        dump = subprocess.run([CHAINSAW, "dump", evtx, "--json", "-q"], check=True, capture_output=True, text=True)
        events += [e for e in json.loads(dump.stdout or "[]") if kept(e)]

    hosts, users = find_names(events)
    for name in hosts | users:
        if name.lower() in TOO_COMMON:
            sys.exit(f"'{name}' is also a common word in Windows paths. Rename the computer or user and collect again.")
    # Longest first, so 'PC01.corp.local' is replaced before 'PC01'.
    names = [(word(h), LAB_HOST) for h in sorted(hosts, key=len, reverse=True)]
    names += [(word(u), LAB_USER) for u in sorted(users, key=len, reverse=True)]
    ips = {}

    def lab_ip(text: str) -> str:
        if not real_ip(text):
            return text
        lab_net = LAB_NETS[ipaddress.ip_address(text).version]
        return ips.setdefault(text, str(lab_net[10 + len(ips) % 240]))

    def replace(text: str) -> str:
        text = EMAIL.sub(LAB_EMAIL, text)
        for pattern, lab in names:
            text = pattern.sub(lab, text)
        text = SID.sub(LAB_SID, text)
        text = IPV4.sub(lambda m: lab_ip(m[0]), text)
        return lab_ip(text)  # an IPv6 address is replaced only when it is the whole value, such as IpAddress

    events = [clean(e, replace) for e in events]
    for e in events:
        e["Event"]["System"]["Computer"] = LAB_HOST
    events.sort(key=lambda e: e["Event"]["System"]["TimeCreated_attributes"]["SystemTime"])

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(events, indent=1, ensure_ascii=False) + "\n")
    counts = {}
    for e in events:
        key = (e["Event"]["System"]["Channel"], e["Event"]["System"]["EventID"])
        counts[key] = counts.get(key, 0) + 1
    print(f"replaced {len(hosts)} host name(s), {len(users)} user name(s), {len(ips)} IP address(es)")
    for (channel, event_id), n in sorted(counts.items()):
        print(f"  {channel:42} {event_id:>5}  {n}")
    print(f"wrote {len(events)} events to {out} ({out.stat().st_size / 1_000_000:.1f} MB)")
    return 0


def check() -> int:
    failures = []
    for path in sorted(BASELINE.glob("*.json")):
        for i, event in enumerate(json.loads(path.read_text())):
            computer = event["Event"]["System"].get("Computer")
            if computer != LAB_HOST:
                failures.append(f"{path.name} event {i}: Computer is '{computer}', not {LAB_HOST}")
            for text in strings(event):
                for sid in SID.findall(text):
                    if sid != LAB_SID:
                        failures.append(f"{path.name} event {i}: domain SID {sid}")
                for ip in IPV4.findall(text) + [text]:
                    if real_ip(ip):
                        failures.append(f"{path.name} event {i}: IP address {ip}")
                for email in EMAIL.findall(text):
                    if email != LAB_EMAIL:
                        failures.append(f"{path.name} event {i}: email address {email}")
    for line in failures[:20]:
        print(f"FAIL {line}")
    if failures:
        print(f"{len(failures)} problem(s). Rebuild it from the raw logs: make baseline RAW=<folder>")
        return 1
    print("baseline is sanitized")
    return 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["build"] and len(sys.argv) == 4:
        sys.exit(build(Path(sys.argv[2]).expanduser(), Path(sys.argv[3])))
    if sys.argv[1:] == ["check"]:
        sys.exit(check())
    sys.exit(__doc__)
