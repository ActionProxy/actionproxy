ALTER TABLE approver_users ADD COLUMN principal_id TEXT;
CREATE INDEX IF NOT EXISTS idx_approver_users_principal_id ON approver_users(workspace_id, principal_id);
