"""Tests every Sigma rule against attack samples (must match) and the lab baseline (must not match).

Attack samples are downloaded at a pinned commit and checked by SHA-256, then converted to JSON
with Chainsaw, so they are tested in the same format as the sanitized lab baseline in baseline/.
Run from the repo root: uv run python scripts/test_rules.py
"""

import hashlib
import json
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

CHAINSAW = Path(".tools/chainsaw")
MAPPING = Path("mappings/chainsaw-sigma-windows.yml")
RULES = Path("rules")
CASES = Path("tests/cases.yml")
DOCS = Path("docs/use-cases")
BASELINE = Path("baseline")
CACHE = Path(".cache")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(repo: str, commit: str, rel: str, digest: str) -> Path:
    """Download one sample once, keyed by its hash, and refuse it if the hash differs."""
    evtx = CACHE / "samples" / f"{digest}.evtx"
    if not evtx.exists() or sha256(evtx) != digest:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.parse.quote(rel)}"
        evtx.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=60) as resp:
            evtx.write_bytes(resp.read())
        if sha256(evtx) != digest:
            evtx.unlink()
            sys.exit(f"checksum mismatch for {rel}: refusing to test with it")
    out = CACHE / "json" / f"{digest}.json"
    if not out.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([CHAINSAW, "dump", evtx, "--json", "-q", "-o", out], check=True)
    return out


def hunt(paths: list[Path]) -> list[dict]:
    result = subprocess.run(
        [CHAINSAW, "hunt", *paths, "-s", RULES, "-m", MAPPING, "--jsonl", "-q"],
        check=True, capture_output=True, text=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    cases = yaml.safe_load(CASES.read_text())
    rules = {yaml.safe_load(p.read_text())["id"]: p.stem for p in sorted(RULES.rglob("*.yml"))}
    failures = []

    # Every rule needs a test and a use case doc, and every test needs a rule.
    for stem in sorted(set(rules.values()) - set(cases["rules"])):
        failures.append(f"{stem}: rule has no entry in {CASES}")
    for stem in sorted(set(cases["rules"]) - set(rules.values())):
        failures.append(f"{stem}: test case has no rule file")
    for stem in sorted(rules.values()):
        if not (DOCS / f"{stem}.md").exists():
            failures.append(f"{stem}: rule has no use case doc in {DOCS}")

    src = cases["samples"]
    expected = {}  # json path -> (rule stem, sample path)
    for stem, case in cases["rules"].items():
        if not case.get("positive"):
            failures.append(f"{stem}: needs at least one positive sample")
        for sample in case.get("positive", []):
            expected[fetch(src["repo"], src["commit"], sample["path"], sample["sha256"])] = (stem, sample["path"])

    baseline = sorted(BASELINE.glob("*.json"))
    hits = hunt([*expected, *baseline]) if expected or baseline else []
    matched = {(Path(h["document"]["path"]).resolve(), rules.get(h["id"])) for h in hits}

    for path, (stem, sample) in expected.items():
        if (path.resolve(), stem) not in matched:
            failures.append(f"{stem}: missed attack sample '{sample}'")
    for h in hits:
        path = Path(h["document"]["path"])
        if path.parent.resolve() == BASELINE.resolve():
            failures.append(f"{rules.get(h['id'], h['id'])}: false positive in baseline {path.name} ({h['timestamp']})")

    print(f"rules: {len(rules)}  attack samples: {len(expected)}  baseline files: {len(baseline)}  detections: {len(hits)}")
    for line in failures:
        print(f"FAIL {line}")
    if failures:
        return 1
    print("all rules caught their attack samples and stayed quiet on the baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
