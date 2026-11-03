.PHONY: tools check test spl all baseline

# Chainsaw (pinned, checksum-verified) and the Python env
tools:
	bash scripts/install-chainsaw.sh
	uv sync

# Sigma syntax and ATT&CK tag validation
check:
	uv run sigma check --fail-on-issues rules

# The baseline must be sanitized, and rules must match their attack samples and stay quiet on it
test:
	uv run python scripts/baseline.py check
	uv run python scripts/test_rules.py

# Regenerate the Splunk queries
spl:
	bash scripts/convert-splunk.sh

# Rebuild the lab baseline from raw .evtx files (kept outside the repo): make baseline RAW=~/lab-baseline-raw
baseline:
	uv run python scripts/baseline.py build $(RAW) baseline/win11-lab.json

all: check test spl
