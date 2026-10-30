-- Generation and rotation: a project default, a per-secret override, and whether a version's value was generated.
ALTER TABLE projects ADD COLUMN secret_policy TEXT;
ALTER TABLE secrets ADD COLUMN policy TEXT;
ALTER TABLE secret_versions ADD COLUMN generated INTEGER NOT NULL DEFAULT 0;
