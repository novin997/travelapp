-- People the owner has invited to a trip. The owner is in trips.owner_id, not here.
-- Trips are identified by edit_token, which is now just the trip's id (it no longer grants access on its own).
CREATE TABLE trip_members (
  trip_id TEXT NOT NULL REFERENCES trips(edit_token) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  role TEXT NOT NULL CHECK (role IN ('editor', 'viewer')),
  PRIMARY KEY (trip_id, user_id)
);
CREATE INDEX trip_members_user ON trip_members(user_id);
