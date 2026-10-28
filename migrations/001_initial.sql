CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  label TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'responder', 'observer')),
  digest TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  UNIQUE (workspace_id, id)
);
CREATE INDEX IF NOT EXISTS api_keys_workspace ON api_keys(workspace_id, created_at);

CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  state TEXT NOT NULL CHECK (state IN ('open', 'investigating', 'contained', 'resolved')),
  created_by TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, created_by) REFERENCES api_keys(workspace_id, id)
);
CREATE INDEX IF NOT EXISTS incidents_feed ON incidents(workspace_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS incidents_state ON incidents(workspace_id, state);

-- One revision claim per mutation is the optimistic concurrency fence.
-- An existing claim aborts the entire transactional D1 batch.
CREATE TABLE IF NOT EXISTS incident_revisions (
  workspace_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, incident_id, revision),
  FOREIGN KEY (workspace_id, incident_id) REFERENCES incidents(workspace_id, id)
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  label TEXT NOT NULL,
  uri TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
  media_type TEXT NOT NULL,
  added_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, incident_id, sha256),
  FOREIGN KEY (workspace_id, incident_id) REFERENCES incidents(workspace_id, id),
  FOREIGN KEY (workspace_id, added_by) REFERENCES api_keys(workspace_id, id)
);
CREATE INDEX IF NOT EXISTS evidence_incident ON evidence(workspace_id, incident_id);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  note TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, incident_id, actor_id, manifest_hash),
  FOREIGN KEY (workspace_id, incident_id) REFERENCES incidents(workspace_id, id),
  FOREIGN KEY (workspace_id, actor_id) REFERENCES api_keys(workspace_id, id)
);
CREATE INDEX IF NOT EXISTS approvals_incident ON approvals(workspace_id, incident_id, manifest_hash);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, incident_id, sequence),
  FOREIGN KEY (workspace_id, incident_id) REFERENCES incidents(workspace_id, id)
);

-- Application credentials should not be used for direct SQL writes.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
