-- @authkit/sessions — Postgres schema.
-- Apply via psql / your migration tool of choice.

CREATE TABLE IF NOT EXISTS sessions (
  id            TEXT PRIMARY KEY,
  user_id       TEXT,
  meta          JSONB NOT NULL,
  data          JSONB NOT NULL,
  expires_at    BIGINT NOT NULL,
  created_at    BIGINT NOT NULL,
  last_seen_at  BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_idx
  ON sessions (user_id, last_seen_at DESC)
  WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS sessions_expires_idx
  ON sessions (expires_at);
