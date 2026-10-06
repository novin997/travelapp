-- Failed login attempts, keyed by "user:<name>" and "ip:<address>". Rows older than the window are pruned.
CREATE TABLE auth_failures (
  key TEXT NOT NULL,
  at INTEGER NOT NULL
);
CREATE INDEX auth_failures_key_at ON auth_failures(key, at);
