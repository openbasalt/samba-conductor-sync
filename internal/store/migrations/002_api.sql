-- P5b: the management API. Sync settings edited through the API are
-- versioned here (who changed what, when); the configuration file stays
-- the bootstrap. Secrets set through the API (the Google service account
-- key) are stored encrypted (AES-256-GCM with a key from systemd
-- credentials); only non-secret metadata is readable.

CREATE TABLE config_versions (
	id            INTEGER PRIMARY KEY,
	created_at    TEXT NOT NULL,
	actor         TEXT NOT NULL,
	origin        TEXT NOT NULL,          -- bootstrap | api | cli
	comment       TEXT NOT NULL DEFAULT '',
	settings_json TEXT NOT NULL,
	changes_json  TEXT NOT NULL DEFAULT '[]',
	sha256        TEXT NOT NULL
);

CREATE TABLE secrets (
	name       TEXT PRIMARY KEY,
	nonce      BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	meta_json  TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL,
	actor      TEXT NOT NULL
);

CREATE INDEX runs_status ON runs (connector, status, id);
