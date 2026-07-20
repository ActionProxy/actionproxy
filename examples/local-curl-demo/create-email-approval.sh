#!/usr/bin/env bash
set -euo pipefail

ACTIONPROXY_BASE_URL="${ACTIONPROXY_BASE_URL:-http://127.0.0.1:8787}"

curl -s -X POST "${ACTIONPROXY_BASE_URL}/v1/tool-calls" \
  -H 'content-type: application/json' \
  -d '{
    "toolName":"gmail.send_email",
    "input":{"to":"customer@example.com","subject":"Update","body":"Thanks for contacting support."},
    "requestedBy":"dev@example.com",
    "agentId":"demo-agent",
    "reason":"Send approved customer response"
  }' | jq
