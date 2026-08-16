CREATE UNIQUE INDEX uq_approver_users_workspace_effective_identity
ON approver_users(workspace_id, COALESCE(NULLIF(principal_id, ''), id));
