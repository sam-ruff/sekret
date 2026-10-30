ALTER TABLE projects ADD COLUMN logo_updated_at INTEGER;
CREATE TABLE project_logos (
    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    content_type TEXT NOT NULL,
    data BLOB NOT NULL
);
