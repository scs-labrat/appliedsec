-- Story 15.2: Add rare_important flag to incident memory
-- Flagged incidents retain a minimum recency score (0.1) regardless of age.

ALTER TABLE incident_memory ADD COLUMN IF NOT EXISTS rare_important BOOLEAN DEFAULT FALSE;
