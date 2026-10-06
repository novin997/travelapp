-- SHA-256 of the user's current recovery code. Codes are long and random, so no salt or slow hash is needed.
ALTER TABLE users ADD COLUMN recovery_hash TEXT;
