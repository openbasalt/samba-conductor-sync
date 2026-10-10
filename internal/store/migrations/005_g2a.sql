-- Google-first mode (Google Workspace to AD).
--
-- g2a_links: the link of each Google account (immutable Google user ID) to
-- the AD account the plan created or manages in a scope. The AD object
-- also carries the marker "google-first:<google user id>", so a lost
-- database does not orphan accounts. google_snapshot holds the Google
-- values last applied (by AD attribute), which tells a Google change from
-- an AD-side drift.
CREATE TABLE g2a_links (
	scope            TEXT NOT NULL,
	google_id        TEXT NOT NULL,
	object_guid      TEXT NOT NULL DEFAULT '',
	sid              TEXT NOT NULL DEFAULT '',
	sam              TEXT NOT NULL DEFAULT '',
	disabled_by_sync INTEGER NOT NULL DEFAULT 0,
	google_snapshot  TEXT NOT NULL DEFAULT '{}',
	updated_at       TEXT NOT NULL,
	PRIMARY KEY (scope, google_id)
);

-- g2a_plans: the plan of a run of action "g2a" (the operations conductor
-- may apply, and the accounts with their Google values), and what
-- conductor reported applying (g2a.confirm).
CREATE TABLE g2a_plans (
	run_id       INTEGER PRIMARY KEY REFERENCES runs(id),
	plan_json    TEXT NOT NULL,
	results_json TEXT NOT NULL DEFAULT '[]'
);
