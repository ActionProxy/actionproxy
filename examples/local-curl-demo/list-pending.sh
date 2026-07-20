#!/usr/bin/env bash
set -euo pipefail

ACTIONPROXY_BASE_URL="${ACTIONPROXY_BASE_URL:-http://127.0.0.1:8787}"

curl -s "${ACTIONPROXY_BASE_URL}/v1/approvals/pending" | jq
