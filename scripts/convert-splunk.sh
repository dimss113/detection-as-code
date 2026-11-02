#!/usr/bin/env bash
# Regenerates queries/splunk/ from rules/. CI fails when the committed queries are out of date.
set -euo pipefail

rm -rf queries/splunk
uv run sigma convert -t splunk \
  -p sysmon -p splunk_windows -p pipelines/splunk-powershell.yml \
  -od queries/splunk -ot '{stem}.spl' rules/windows
