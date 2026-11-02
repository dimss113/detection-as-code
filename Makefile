.PHONY: tools check test spl all

# Chainsaw (pinned, checksum-verified) and the Python env
tools:
	bash scripts/install-chainsaw.sh
	uv sync

# Sigma syntax and ATT&CK tag validation
check:
	uv run sigma check --fail-on-issues rules

# Rules must match their attack samples and stay quiet on the baseline
test:
	uv run python scripts/test_rules.py

# Regenerate the Splunk queries
spl:
	bash scripts/convert-splunk.sh

all: check test spl
