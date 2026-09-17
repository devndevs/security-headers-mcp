#!/usr/bin/env bash
# Post-deploy smoke test: proves the live Worker answers MCP calls correctly.
# Usage: bash scripts/smoke.sh https://security-headers-mcp.<subdomain>.workers.dev
set -euo pipefail

BASE_URL="${1:?usage: smoke.sh <worker-base-url>}"
ENDPOINT="${BASE_URL%/}/mcp"
failures=0

echo "Smoke testing ${ENDPOINT}"

call() {
  curl --silent --show-error --fail --max-time 20 "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --data "$1"
}

expect() {
  local label="$1" body="$2" needle="$3"
  if grep -qF -- "$needle" <<<"$body"; then
    echo "PASS  ${label}"
  else
    echo "FAIL  ${label} (expected to find: ${needle})"
    failures=$((failures + 1))
  fi
}

# 1. The tool is registered and discoverable.
body=$(call '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
expect "tools/list exposes check_security_headers" "$body" '"name":"check_security_headers"'

# 2. Policy is enforced. The .invalid TLD never resolves, and the request is denied before any fetch.
body=$(call '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_security_headers","arguments":{"url":"https://not-allowed.invalid/"}}}')
expect "off-list host is denied" "$body" 'Denied: host is not on the allowlist.'

# 3. The happy path works end to end. Depends on example.com being reachable.
body=$(call '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_security_headers","arguments":{"url":"https://example.com/"}}}')
expect "allowlisted host returns a report" "$body" '"status":200'

if [ "$failures" -gt 0 ]; then
  echo "${failures} smoke check(s) failed"
  exit 1
fi
echo "All smoke checks passed"
