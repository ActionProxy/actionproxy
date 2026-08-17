CREATE UNIQUE INDEX uq_approver_users_workspace_principal
ON approver_users(workspace_id, principal_id)
WHERE principal_id IS NOT NULL;
