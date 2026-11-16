-- Adoption approvals. Adoption by address is never automatic: an
-- administrator approves one existing target object for one AD object,
-- bound to the target ID and to the address at the time of the approval.
-- A plan adopts only approved pairs whose target ID and address still match
-- (and that pass the privilege, uniqueness and role checks). A link adopted
-- before this migration has no approval: it keeps working, but the
-- self-service password reset of adopted accounts requires one.
CREATE TABLE adoption_approvals (
	connector   TEXT NOT NULL,
	kind        TEXT NOT NULL,
	source_id   TEXT NOT NULL,
	target_id   TEXT NOT NULL,
	address     TEXT NOT NULL,
	approved_by TEXT NOT NULL,
	approved_at TEXT NOT NULL,
	comment     TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (connector, kind, source_id)
);
