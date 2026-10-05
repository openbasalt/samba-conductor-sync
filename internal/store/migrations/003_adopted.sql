-- Adoption: a link records whether the target object existed before the
-- sync and was adopted by address (1) or was created by the sync (0). The
-- policy's adopted rules (keep the org unit, the address, names AD has no
-- value for; add-only group members) apply to adopted objects on every run.
-- Links made before this migration count as created.
ALTER TABLE links ADD COLUMN adopted INTEGER NOT NULL DEFAULT 0;
