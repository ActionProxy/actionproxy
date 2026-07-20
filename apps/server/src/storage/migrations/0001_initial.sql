CREATE TABLE IF NOT EXISTS tool_calls (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  tool_name TEXT NOT NULL,
  input_json TEXT NOT NULL,
  input_hash TEXT,
  action_envelope_json TEXT,
  action_envelope_hash TEXT,
  canonical_action_request_hash TEXT,
  canonical_action_request_version TEXT,
  canonical_decision_input_hash TEXT,
  canonical_policy_context_json TEXT,
  requested_by TEXT NOT NULL,
  requested_by_auth_json TEXT,
  agent_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  status TEXT NOT NULL,
  decision TEXT,
  decision_trace_json TEXT,
  governance_state_json TEXT,
  policy_reason TEXT,
  policy_version_id TEXT,
  policy_version_hash TEXT,
  risk TEXT,
  result_json TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_created_at ON tool_calls(created_at);
CREATE INDEX IF NOT EXISTS idx_tool_calls_workspace_id ON tool_calls(workspace_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_status ON tool_calls(status);
CREATE INDEX IF NOT EXISTS idx_tool_calls_decision ON tool_calls(decision);
CREATE INDEX IF NOT EXISTS idx_tool_calls_tool_name ON tool_calls(tool_name);

CREATE TABLE IF NOT EXISTS content_exposure_scopes (
  workspace_id TEXT NOT NULL,
  influence_scope_id TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  PRIMARY KEY (workspace_id, influence_scope_id)
);

CREATE TABLE IF NOT EXISTS content_exposures (
  workspace_id TEXT NOT NULL,
  influence_scope_id TEXT NOT NULL,
  source_tool_call_id TEXT NOT NULL,
  integrity TEXT NOT NULL CHECK (
    integrity IN (
      'organization_managed',
      'verified_publisher',
      'authenticated_external',
      'public_untrusted',
      'unknown'
    )
  ),
  source_id TEXT,
  policy_version_hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, influence_scope_id, source_tool_call_id)
);

CREATE INDEX IF NOT EXISTS idx_content_exposures_scope_observed
  ON content_exposures(workspace_id, influence_scope_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_content_exposures_scope_order_v1
  ON content_exposures(workspace_id, influence_scope_id, observed_at, source_tool_call_id);

INSERT INTO content_exposure_scopes (workspace_id, influence_scope_id, revision)
SELECT workspace_id, influence_scope_id, COUNT(*)
FROM content_exposures
GROUP BY workspace_id, influence_scope_id
ON CONFLICT (workspace_id, influence_scope_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  tool_call_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_by_auth_json TEXT,
  authorization_json TEXT,
  authorization_consumed_at TEXT,
  authorization_consumed_reason TEXT,
  approved_by TEXT,
  cancelled_at TEXT,
  cancelled_by TEXT,
  cancellation_reason TEXT,
  expired_at TEXT,
  finalized_at TEXT,
  rejected_by TEXT,
  note TEXT,
  rejection_reason TEXT,
  original_input_json TEXT NOT NULL,
  original_input_hash TEXT,
  original_envelope_hash TEXT,
  edited_input_json TEXT,
  approved_input_hash TEXT,
  approved_envelope_hash TEXT,
  review_hash TEXT,
  approver_users_json TEXT,
  approver_groups_json TEXT,
  required_approvals INTEGER,
  separation_of_duties INTEGER,
  decisions_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_tool_call_id ON approvals(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_approvals_workspace_id ON approvals(workspace_id);

CREATE TABLE IF NOT EXISTS approval_deliveries (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  approval_id TEXT NOT NULL,
  tool_call_id TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  message_id TEXT,
  destination TEXT,
  error TEXT,
  recipient_user_id TEXT,
  recipient_email TEXT,
  recipient_slack_user_id TEXT,
  recipient_telegram_chat_id TEXT,
  recipient_telegram_user_id TEXT,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_deliveries_approval_id ON approval_deliveries(approval_id);
CREATE INDEX IF NOT EXISTS idx_approval_deliveries_tool_call_id ON approval_deliveries(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_approval_deliveries_workspace_id ON approval_deliveries(workspace_id);

CREATE TABLE IF NOT EXISTS approver_users (
  id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT,
  slack_user_id TEXT,
  telegram_chat_id TEXT,
  telegram_username TEXT,
  telegram_user_id TEXT,
  groups_json TEXT NOT NULL,
  default_approver INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_approver_users_workspace_id ON approver_users(workspace_id);
CREATE INDEX IF NOT EXISTS idx_approver_users_email ON approver_users(email);
CREATE INDEX IF NOT EXISTS idx_approver_users_slack_user_id ON approver_users(slack_user_id);
CREATE INDEX IF NOT EXISTS idx_approver_users_telegram_username ON approver_users(telegram_username);
CREATE INDEX IF NOT EXISTS idx_approver_users_telegram_user_id ON approver_users(telegram_user_id);

CREATE TABLE IF NOT EXISTS approver_groups (
  id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  description TEXT,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_approver_groups_workspace_id ON approver_groups(workspace_id);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  workspace_id TEXT,
  tool_call_id TEXT,
  approval_id TEXT,
  actor TEXT,
  auth_json TEXT,
  input_hash TEXT,
  policy_version_id TEXT,
  policy_version_hash TEXT,
  previous_event_hash TEXT,
  event_hash TEXT,
  timestamp TEXT NOT NULL,
  data_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_workspace_id ON audit_events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tool_call_id ON audit_events(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_approval_id ON audit_events(approval_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_hash ON audit_events(event_hash);

CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  version TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workspace_users (
  id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  email TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_users_principal_id ON workspace_users(workspace_id, principal_id);

CREATE TABLE IF NOT EXISTS service_accounts (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  groups_json TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_service_accounts_workspace_id ON service_accounts(workspace_id);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  service_account_id TEXT NOT NULL,
  key_prefix TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  scopes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_service_account_id ON api_keys(service_account_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS execution_grants (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  tool_call_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  approved_input_hash TEXT,
  approved_envelope_hash TEXT,
  policy_version_hash TEXT,
  receipt_id TEXT,
  receipt_hash TEXT,
  actor TEXT NOT NULL,
  auth_json TEXT,
  expires_at TEXT NOT NULL,
  nonce TEXT NOT NULL,
  signature TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_grants_tool_call_id ON execution_grants(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_execution_grants_workspace_id ON execution_grants(workspace_id);
CREATE INDEX IF NOT EXISTS idx_execution_grants_receipt_id ON execution_grants(receipt_id);

CREATE TABLE IF NOT EXISTS execution_attempts (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  tool_call_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
  version TEXT NOT NULL,
  state TEXT NOT NULL CHECK (
    state IN (
      'reserved',
      'dispatched',
      'succeeded',
      'failed_before_dispatch',
      'failed_after_dispatch',
      'timed_out',
      'cancelled',
      'unknown_outcome'
    )
  ),
  reservation_owner TEXT NOT NULL,
  execution_mode TEXT NOT NULL,
  executor_id TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  provider_idempotency TEXT NOT NULL,
  retry_policy TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  grant_id TEXT UNIQUE,
  outcome_json TEXT,
  reserved_at TEXT NOT NULL,
  dispatched_at TEXT,
  completed_at TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, tool_call_id)
);

CREATE INDEX IF NOT EXISTS idx_execution_attempts_workspace_state
  ON execution_attempts(workspace_id, state);
CREATE INDEX IF NOT EXISTS idx_execution_attempts_tool_call_id
  ON execution_attempts(tool_call_id);

CREATE TABLE IF NOT EXISTS action_receipts (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  tool_call_id TEXT NOT NULL,
  approval_id TEXT,
  decision_kind TEXT NOT NULL,
  decision_actor TEXT NOT NULL,
  decision_auth_json TEXT,
  tool_name TEXT NOT NULL,
  source_json TEXT NOT NULL,
  protocol TEXT NOT NULL,
  operation_json TEXT NOT NULL,
  original_input_hash TEXT NOT NULL,
  approved_input_hash TEXT NOT NULL,
  original_envelope_hash TEXT NOT NULL,
  approved_envelope_hash TEXT NOT NULL,
  review_hash TEXT,
  policy_version_id TEXT,
  policy_version_hash TEXT,
  policy_decision TEXT,
  policy_reason TEXT,
  policy_risk TEXT,
  execution_mode TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT,
  receipt_hash TEXT NOT NULL,
  key_id TEXT NOT NULL,
  signature_alg TEXT NOT NULL,
  signature TEXT NOT NULL,
  outcome_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_action_receipts_tool_call_id ON action_receipts(tool_call_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_approval_id ON action_receipts(approval_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_workspace_id ON action_receipts(workspace_id);
CREATE INDEX IF NOT EXISTS idx_action_receipts_receipt_hash ON action_receipts(receipt_hash);

CREATE TABLE IF NOT EXISTS idempotency_records (
  workspace_id TEXT NOT NULL,
  route TEXT NOT NULL,
  key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  tool_call_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, route, key)
);

CREATE TABLE IF NOT EXISTS observed_tools (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL DEFAULT 'default',
  tool_name TEXT NOT NULL,
  sources_json TEXT NOT NULL,
  source_ids_json TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  call_count INTEGER NOT NULL,
  schema_hash TEXT,
  schema_change_json TEXT,
  coverage_json TEXT NOT NULL,
  status TEXT NOT NULL,
  suggestion_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_observed_tools_workspace_id ON observed_tools(workspace_id);
CREATE INDEX IF NOT EXISTS idx_observed_tools_tool_name ON observed_tools(tool_name);
CREATE INDEX IF NOT EXISTS idx_observed_tools_status ON observed_tools(status);
CREATE INDEX IF NOT EXISTS idx_observed_tools_last_seen_at ON observed_tools(last_seen_at);
