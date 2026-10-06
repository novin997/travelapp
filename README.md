# Travel Planner

**Live:** https://travelapp.sg-bus-app.workers.dev (GitHub Pages at https://novin997.github.io/travelapp/ forwards there; the app needs a server, so it can't run on Pages itself.)

Private, shared travel itineraries. Everything requires logging in. Each trip (`/t/<id>`) can be opened only by its owner and the users they invite by username as **Editor** or **Viewer**.

- Days (Day 1…N), each with ordered stops (optional `HH:MM` time + free-text place) and a notes box
- **Pick on map**: a 2D map (MapLibre 6 from unpkg, OpenFreeMap tiles) where clicking drops a pin, the name is filled in from OpenStreetMap Nominatim reverse geocoding, and the stop is saved with its coordinates (`lat`, `lng`). Mapped stops link to exact coordinates in Google Maps
- **Search on the map**: type a place name to search with [Photon](https://photon.komoot.io) (OpenStreetMap data, results near the current view first); picking a result flies there and drops the pin
- Auto-saves ~1s after each edit. If someone else saved first, you're asked to reload (version check in `UPDATE … WHERE version = ?`)
- Accounts: username + password (PBKDF2-SHA256, per-user salt), 30-day HttpOnly session cookie
- Forgot password: a one-time recovery code shown at signup (stored as SHA-256). Resetting logs out all sessions and issues a new code; logged-in users can get a new code by confirming their password
- Deleting: only the owner can delete a trip (from My trips or the trip page)
- Rate limiting: 5 failed login or reset attempts per username, or 20 per IP, in 15 minutes → `429` with `Retry-After`
- Home page lists **My trips** and **Shared with me**
- Sharing: the owner invites, re-roles or removes members; members can leave. Anyone without access gets `404 Trip not found` (old `/v/` links no longer work; for old `/e/` links see Legacy trips below)

Stack: one Cloudflare Worker (`src/worker.js`, JSON API under `/api/trips`) + one vanilla HTML page (`public/index.html`) + D1.

```sh
npm install
npm run db:local   # create/upgrade local D1 tables
npm run dev        # http://localhost:8787
npm test           # Worker tests (vitest-pool-workers, fresh D1 with migrations/ applied)
```

Deploying: run any new migrations with `npx wrangler d1 migrations apply travelapp --remote`, then `npm run deploy`.

Before going public: Nominatim's usage policy only allows light use (≤1 request/second), and the public Photon server is shared and best-effort, so switch both to a paid or self-hosted geocoder.

Legacy trips: trips made before accounts existed have no owner (`owner_id IS NULL`). Opening the trip's old `/e/<id>` edit link while logged in claims it (`POST /api/trips/:id/claim`): the first user to do so becomes its owner, since that link was the original proof of ownership. Plain `/t/<id>` never claims. Follow-up, after a grace period: delete unclaimed trips and make `owner_id` required.

```sql
-- DELETE FROM trips WHERE owner_id IS NULL;
-- then rebuild trips with `owner_id INTEGER NOT NULL REFERENCES users(id)` (SQLite can't add NOT NULL in place)
```

Known limit: the whole trip saves as one blob, so simultaneous edits to different days still conflict.
