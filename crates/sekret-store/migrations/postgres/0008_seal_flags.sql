-- One-way facts about the seal configuration, covered by its signature.
ALTER TABLE seal_config ADD COLUMN flags BIGINT NOT NULL DEFAULT 0;
