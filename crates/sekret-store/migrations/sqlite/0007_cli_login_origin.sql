-- Where a CLI login was started from, shown on the approval page.
ALTER TABLE cli_logins ADD COLUMN requested_from_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE cli_logins ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
