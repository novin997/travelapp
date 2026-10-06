CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Stores a SHA-256 of the session cookie value, never the value itself.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);

-- Trips created before accounts existed have no owner.
ALTER TABLE trips ADD COLUMN owner_id INTEGER REFERENCES users(id);
ALTER TABLE trips ADD COLUMN created_at INTEGER;
CREATE INDEX trips_owner ON trips(owner_id);
