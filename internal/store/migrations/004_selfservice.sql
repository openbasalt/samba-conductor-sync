-- Self-service (conductor's "Connected accounts").
--
-- activations: users who activated their account on a target. With
-- self_service.activation = "self-service" the sync runs create accounts
-- only for them; everyone else is shown as pending activation.
CREATE TABLE activations (
	connector    TEXT NOT NULL,
	source_id    TEXT NOT NULL,
	activated_at TEXT NOT NULL,
	actor        TEXT NOT NULL,
	PRIMARY KEY (connector, source_id)
);

-- selfservice_actions: every self-service action that reached the target
-- (activations and password changes), for the rate limits and for review.
-- No password, hash or length is ever stored here.
CREATE TABLE selfservice_actions (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	connector TEXT NOT NULL,
	actor_sid TEXT NOT NULL,
	source_id TEXT NOT NULL,
	action    TEXT NOT NULL,
	at        TEXT NOT NULL,
	result    TEXT NOT NULL DEFAULT 'started'
);
CREATE INDEX selfservice_actions_actor ON selfservice_actions(connector, actor_sid, at);
CREATE INDEX selfservice_actions_at ON selfservice_actions(connector, at);
