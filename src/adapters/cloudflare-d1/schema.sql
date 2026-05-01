-- @authkit/sessions — Cloudflare D1 schema.
-- Apply via `wrangler d1 execute <db> --file=schema.sql`.

CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT,
  meta        TEXT NOT NULL,         -- JSON-serialised SessionMetadata
  data        TEXT NOT NULL,         -- JSON-serialised payload
  expires_at  INTEGER NOT NULL,      -- Unix seconds
  created_at  INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_idx
  ON sessions (user_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS sessions_expires_idx
  ON sessions (expires_at);
