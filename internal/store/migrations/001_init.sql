-- conductor-sync state. AD stays the source of truth; this holds only what
-- the sync must remember: which target object belongs to which AD object,
-- the runs and their plans, the per-operation journal (resume after a
-- crash) and the hash-chained audit log.

CREATE TABLE meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE links (
	connector         TEXT NOT NULL,
	kind              TEXT NOT NULL,
	source_id         TEXT NOT NULL,
	target_id         TEXT NOT NULL,
	key               TEXT NOT NULL,
	source_dn         TEXT NOT NULL DEFAULT '',
	suspended_by_sync INTEGER NOT NULL DEFAULT 0,
	suspended_at      TEXT NOT NULL DEFAULT '',   -- when the sync suspended it
	created_at        TEXT NOT NULL,
	updated_at        TEXT NOT NULL,
	PRIMARY KEY (connector, kind, source_id)
);
CREATE UNIQUE INDEX links_target ON links (connector, kind, target_id);
CREATE INDEX links_key ON links (connector, key);

CREATE TABLE runs (
	id            INTEGER PRIMARY KEY,
	connector     TEXT NOT NULL,
	action        TEXT NOT NULL,            -- plan | apply
	trigger       TEXT NOT NULL,            -- manual | scheduled
	actor         TEXT NOT NULL,
	started_at    TEXT NOT NULL,
	finished_at   TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL,            -- running | planned | applied | partial | blocked | failed | interrupted | dry-run | nothing-to-do
	plan_digest   TEXT NOT NULL DEFAULT '',
	source_users  INTEGER NOT NULL DEFAULT 0,
	source_groups INTEGER NOT NULL DEFAULT 0,
	ops_total     INTEGER NOT NULL DEFAULT 0,
	ops_done      INTEGER NOT NULL DEFAULT 0,
	ops_failed    INTEGER NOT NULL DEFAULT 0,
	summary       TEXT NOT NULL DEFAULT '{}',
	error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX runs_connector ON runs (connector, id);

CREATE TABLE plans (
	run_id    INTEGER PRIMARY KEY REFERENCES runs (id),
	plan_json TEXT NOT NULL
);

CREATE TABLE ops (
	run_id     INTEGER NOT NULL REFERENCES runs (id),
	seq        INTEGER NOT NULL,
	kind       TEXT NOT NULL,
	key        TEXT NOT NULL,
	source_id  TEXT NOT NULL DEFAULT '',
	target_id  TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL,              -- pending | started | done | failed | skipped | superseded
	error      TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (run_id, seq)
);
CREATE INDEX ops_status ON ops (status);

CREATE TABLE audit (
	id        INTEGER PRIMARY KEY,
	ts        TEXT NOT NULL,
	actor     TEXT NOT NULL,
	action    TEXT NOT NULL,
	target    TEXT NOT NULL,
	detail    TEXT NOT NULL,
	result    TEXT NOT NULL,
	prev_hash TEXT NOT NULL,
	hash      TEXT NOT NULL
);
