#!/usr/bin/env bash
set -euo pipefail

ACTIONPROXY_BASE_URL="${ACTIONPROXY_BASE_URL:-http://127.0.0.1:8787}"

APPROVAL_ID=$(curl -s "${ACTIONPROXY_BASE_URL}/v1/approvals/pending" | jq -r '.approvals[0].id')

if [[ "$APPROVAL_ID" == "null" || -z "$APPROVAL_ID" ]]; then
  echo "No pending approval found. Run create-email-approval.sh first."
  exit 1
fi

curl -s -X POST "${ACTIONPROXY_BASE_URL}/v1/approvals/${APPROVAL_ID}/approve" \
  -H 'content-type: application/json' \
  -d '{"approvedBy":"manager@example.com","note":"Approved from local demo"}' | jq
