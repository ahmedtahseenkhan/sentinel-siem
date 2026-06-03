-- Dry-run flag for SOAR playbooks. When true the executor logs each action it
-- *would* run but skips execution — a safe way to validate a playbook's trigger
-- and action sequence before arming real active-response (firewall-drop, etc.).
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS dry_run BOOLEAN NOT NULL DEFAULT FALSE;
