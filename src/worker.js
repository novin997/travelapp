const MAX_BYTES = 100_000;
const MAX_TITLE = 200;
const TIME_RE = /^(?:[01]\d|2[0-3]):[0-5]\d$|^$/; // what <input type=time> produces, or empty
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100_000; // the maximum Workers allows
const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const FAILURE_WINDOW_MS = 15 * 60_000;
const MAX_FAILURES_PER_USER = 5; // per (username, IP)
const MAX_FAILURES_PER_IP = 20;
// Per username across all IPs. High enough that a stranger can't cheaply lock someone out (it takes 50
// guesses from 10+ IPs), low enough that a distributed guesser gets only 50 tries per 15 minutes.
const MAX_FAILURES_PER_USER_ALL_IPS = 50;

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      ...headers,
    },
  });

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
const newToken = () => toHex(crypto.getRandomValues(new Uint8Array(16)));
const sha256 = async (text) => toHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromHex(saltHex), iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return toHex(bits);
}

function sameHex(a, b) {
  const x = fromHex(a), y = fromHex(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

// ---------- sessions ----------

function sessionCookie(request, value, maxAge) {
  // Browsers drop Secure cookies on plain-http localhost in some cases, so only add it over https.
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `session=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function readSessionToken(request) {
  const match = (request.headers.get("cookie") || "").match(/(?:^|;\s*)session=([0-9a-f]{32})/);
  return match && match[1];
}

async function currentUser(request, env) {
  const token = readSessionToken(request);
  if (!token) return null;
  return env.DB.prepare(
    "SELECT users.id, users.username FROM sessions JOIN users ON users.id = sessions.user_id WHERE token_hash = ? AND expires_at > ?"
  )
    .bind(await sha256(token), Date.now())
    .first();
}

async function startSession(request, env, user, extra = {}) {
  const token = newToken();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(Date.now()),
    env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)").bind(
      await sha256(token),
      user.id,
      Date.now() + SESSION_DAYS * 86_400_000
    ),
  ]);
  return json({ username: user.username, ...extra }, 200, {
    "set-cookie": sessionCookie(request, token, SESSION_DAYS * 86_400),
  });
}

async function readCredentials(request) {
  const { username, password } = await request.json().catch(() => ({}));
  return {
    username: String(username || "").trim().toLowerCase(),
    password: String(password || ""),
  };
}

// ---------- rate limiting ----------

// Cloudflare always sets cf-connecting-ip. Only local dev may lack it; anywhere else, refuse the request
// rather than put every such client in one shared bucket.
function clientIp(request) {
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) return ip;
  const host = new URL(request.url).hostname;
  return host === "localhost" || host === "127.0.0.1" ? "local" : null;
}

const noClientIp = () => json({ error: "Could not identify client address" }, 400);

// Records the attempt against every [key, max] *before* any password work, in one batch (D1 runs a batch
// as a transaction), so parallel requests see each other's rows and can't all slip under the limit.
// Returns the reserved row ids, plus seconds to wait if any key is now over its limit (the reservation
// is then dropped, so rejected requests don't extend the lockout).
async function reserveAttempt(env, limits) {
  const now = Date.now();
  const since = now - FAILURE_WINDOW_MS;
  const results = await env.DB.batch([
    env.DB.prepare("DELETE FROM auth_failures WHERE at <= ?").bind(since),
    ...limits.map(([key]) =>
      env.DB.prepare("INSERT INTO auth_failures (key, at) VALUES (?, ?) RETURNING rowid AS id").bind(key, now)
    ),
    ...limits.map(([key]) =>
      env.DB.prepare("SELECT COUNT(*) AS n, MIN(at) AS oldest FROM auth_failures WHERE key = ? AND at > ?").bind(
        key,
        since
      )
    ),
  ]);
  const ids = results.slice(1, 1 + limits.length).map((r) => r.results[0].id);
  const counts = results.slice(1 + limits.length).map((r) => r.results[0]);
  const over = counts.filter((row, i) => row.n > limits[i][1]);
  if (!over.length) return { ids, wait: 0 };
  await unreserve(env, ids).run();
  return { ids, wait: Math.max(...over.map((row) => Math.ceil((row.oldest + FAILURE_WINDOW_MS - now) / 1000))) };
}

// A reserved attempt that turned out not to be a failure. A failure simply leaves its rows in place.
const unreserve = (env, ids) =>
  env.DB.prepare(`DELETE FROM auth_failures WHERE rowid IN (${ids.map(() => "?").join()})`).bind(...ids);

function tooManyAttempts(seconds) {
  const minutes = Math.ceil(seconds / 60);
  return json(
    { error: `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.` },
    429,
    { "retry-after": String(seconds) }
  );
}

// ---------- recovery codes ----------

// 20 characters from a 32-letter alphabet (no 0/O/1/I) = 100 random bits, shown as XXXX-XXXX-XXXX-XXXX-XXXX.
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function newRecoveryCode() {
  const chars = [...crypto.getRandomValues(new Uint8Array(20))].map((b) => CODE_ALPHABET[b % 32]);
  return chars.join("").match(/.{4}/g).join("-");
}

// Accepts the code however it was typed: any case, with or without dashes or spaces.
const normalizeCode = (code) => String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");

const passwordError = (password) =>
  password.length < 8 ? "Password must be at least 8 characters"
  : password.length > 200 ? "Password must be at most 200 characters"
  : null;

// ---------- account routes ----------

async function signup(request, env) {
  const { username, password } = await readCredentials(request);
  if (!USERNAME_RE.test(username)) {
    return json({ error: "Username must be 3–32 characters: letters, numbers or _" }, 400);
  }
  if (passwordError(password)) return json({ error: passwordError(password) }, 400);
  const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPassword(password, salt);
  const recoveryCode = newRecoveryCode();
  const row = await env.DB.prepare(
    "INSERT INTO users (username, password_hash, salt, recovery_hash, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(username) DO NOTHING RETURNING id, username"
  )
    .bind(username, hash, salt, await sha256(normalizeCode(recoveryCode)), Date.now())
    .first();
  if (!row) return json({ error: "That username is taken" }, 409);
  return startSession(request, env, row, { recoveryCode });
}

async function login(request, env) {
  const { username, password } = await readCredentials(request);
  const ip = clientIp(request);
  if (!ip) return noClientIp();
  const userKey = "user:" + username;
  const pairKey = userKey + "@" + ip;
  const { ids, wait } = await reserveAttempt(env, [
    [pairKey, MAX_FAILURES_PER_USER],
    [userKey, MAX_FAILURES_PER_USER_ALL_IPS],
    ["ip:" + ip, MAX_FAILURES_PER_IP],
  ]);
  if (wait) return tooManyAttempts(wait);

  const user = await env.DB.prepare("SELECT id, username, password_hash, salt FROM users WHERE username = ?")
    .bind(username)
    .first();
  if (!user || !sameHex(await hashPassword(password, user.salt), user.password_hash)) {
    return json({ error: "Wrong username or password" }, 401);
  }
  await env.DB.batch([
    unreserve(env, ids),
    env.DB.prepare("DELETE FROM auth_failures WHERE key IN (?, ?)").bind(pairKey, userKey),
  ]);
  return startSession(request, env, user);
}

// Forgot password: username + recovery code + new password. Logs out every session and issues a new code.
async function resetPassword(request, env) {
  const { username, code, password } = await request.json().catch(() => ({}));
  const name = String(username || "").trim().toLowerCase();
  const newPassword = String(password || "");
  const ip = clientIp(request);
  if (!ip) return noClientIp();
  const userKey = "reset:" + name;
  const pairKey = userKey + "@" + ip;
  const { ids, wait } = await reserveAttempt(env, [
    [pairKey, MAX_FAILURES_PER_USER],
    [userKey, MAX_FAILURES_PER_USER_ALL_IPS],
    ["ip:" + ip, MAX_FAILURES_PER_IP],
  ]);
  if (wait) return tooManyAttempts(wait);

  const user = await env.DB.prepare("SELECT id, username, recovery_hash FROM users WHERE username = ?")
    .bind(name)
    .first();
  if (!user || !user.recovery_hash || !sameHex(await sha256(normalizeCode(code)), user.recovery_hash)) {
    return json({ error: "Wrong username or recovery code" }, 401);
  }
  if (passwordError(newPassword)) {
    await unreserve(env, ids).run();
    return json({ error: passwordError(newPassword) }, 400);
  }

  const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
  const recoveryCode = newRecoveryCode();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET password_hash = ?, salt = ?, recovery_hash = ? WHERE id = ?").bind(
      await hashPassword(newPassword, salt),
      salt,
      await sha256(normalizeCode(recoveryCode)),
      user.id
    ),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
    unreserve(env, ids),
    env.DB.prepare("DELETE FROM auth_failures WHERE key IN (?, ?, ?, ?)").bind(
      pairKey,
      userKey,
      "user:" + name + "@" + ip,
      "user:" + name
    ),
  ]);
  return startSession(request, env, user, { recoveryCode });
}

// Logged in: confirm the password to replace a lost recovery code.
async function regenerateRecoveryCode(request, env, user) {
  const { password } = await request.json().catch(() => ({}));
  // Only this user's own sessions can reach here, so a per-user key can't be used to lock them out.
  const { ids, wait } = await reserveAttempt(env, [["regen:" + user.username, MAX_FAILURES_PER_USER]]);
  if (wait) return tooManyAttempts(wait);

  const row = await env.DB.prepare("SELECT password_hash, salt FROM users WHERE id = ?").bind(user.id).first();
  if (!sameHex(await hashPassword(String(password || ""), row.salt), row.password_hash)) {
    return json({ error: "Wrong password" }, 401);
  }
  const recoveryCode = newRecoveryCode();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET recovery_hash = ? WHERE id = ?").bind(
      await sha256(normalizeCode(recoveryCode)),
      user.id
    ),
    unreserve(env, ids),
  ]);
  return json({ recoveryCode });
}

async function logout(request, env) {
  const token = readSessionToken(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(request, "", 0) });
}

// ---------- trip routes ----------

const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const inRange = (n, max) => typeof n === "number" && Number.isFinite(n) && Math.abs(n) <= max;

// Map-picked stops carry coordinates; typed-in stops don't.
function cleanStop(s) {
  if (!isObj(s) || typeof s.location !== "string" || typeof s.time !== "string" || !TIME_RE.test(s.time)) return null;
  const stop = { time: s.time, location: s.location };
  if (s.lat === undefined && s.lng === undefined) return stop;
  return inRange(s.lat, 90) && inRange(s.lng, 180) ? { ...stop, lat: s.lat, lng: s.lng } : null;
}

function cleanDay(d) {
  if (!isObj(d) || typeof d.notes !== "string" || !Array.isArray(d.stops)) return null;
  const stops = d.stops.map(cleanStop);
  return stops.includes(null) ? null : { notes: d.notes, stops };
}

// Returns a copy with only the known fields, or null if anything is malformed.
function cleanTrip(data) {
  if (!isObj(data) || typeof data.title !== "string" || data.title.length > MAX_TITLE || !Array.isArray(data.days)) return null;
  const days = data.days.map(cleanDay);
  return days.includes(null) ? null : { title: data.title, days };
}

// Trips the user owns, plus trips they've been invited to.
async function myTrips(user, env) {
  const { results } = await env.DB.prepare(
    `SELECT trips.edit_token AS id, json_extract(trips.data, '$.title') AS title,
            COALESCE(trip_members.role, 'owner') AS role, owners.username AS owner
     FROM trips
     LEFT JOIN trip_members ON trip_members.trip_id = trips.edit_token AND trip_members.user_id = ?1
     LEFT JOIN users AS owners ON owners.id = trips.owner_id
     WHERE trips.owner_id = ?1 OR trip_members.user_id = ?1
     ORDER BY trips.created_at DESC`
  )
    .bind(user.id)
    .all();
  return json(results);
}

async function createTrip(request, env, user) {
  const { title } = await request.json().catch(() => ({}));
  const data = {
    title: String(title || "Untitled trip").slice(0, MAX_TITLE),
    days: [{ notes: "", stops: [] }],
  };
  const id = newToken();
  await env.DB.prepare(
    "INSERT INTO trips (edit_token, view_token, data, owner_id, created_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(id, newToken(), JSON.stringify(data), user.id, Date.now())
    .run();
  return json({ id }, 201);
}

// The user's role on a trip: "owner", "editor", "viewer", or null if they have no access.
async function tripRole(env, tripId, user) {
  const row = await env.DB.prepare(
    `SELECT CASE WHEN trips.owner_id = ?2 THEN 'owner' ELSE trip_members.role END AS role
     FROM trips
     LEFT JOIN trip_members ON trip_members.trip_id = trips.edit_token AND trip_members.user_id = ?2
     WHERE trips.edit_token = ?1`
  )
    .bind(tripId, user.id)
    .first();
  return row ? row.role : null;
}

const canEdit = (role) => role === "owner" || role === "editor";

// No access looks the same as not existing, so trip ids can't be probed.
const tripNotFound = () => json({ error: "Trip not found" }, 404);

async function getTrip(env, tripId, user, role) {
  const trip = await env.DB.prepare(
    "SELECT trips.data, trips.version, users.username AS owner FROM trips LEFT JOIN users ON users.id = trips.owner_id WHERE edit_token = ?"
  )
    .bind(tripId)
    .first();
  const { results: members } = await env.DB.prepare(
    "SELECT users.username, trip_members.role FROM trip_members JOIN users ON users.id = trip_members.user_id WHERE trip_id = ? ORDER BY users.username"
  )
    .bind(tripId)
    .all();
  return json({
    data: JSON.parse(trip.data),
    version: trip.version,
    role,
    canEdit: canEdit(role),
    owner: trip.owner,
    you: user.username,
    members,
  });
}

// Save: only succeeds if nobody else saved since this client loaded `version`.
async function saveTrip(request, env, tripId) {
  const tooLarge = () => json({ error: "Trip too large" }, 413);
  if (Number(request.headers.get("content-length")) > MAX_BYTES) return tooLarge();
  const body = await request.text();
  if (new TextEncoder().encode(body).length > MAX_BYTES) return tooLarge();
  let parsed;
  try { parsed = JSON.parse(body); } catch { return json({ error: "Invalid trip" }, 400); }
  const { data: raw, version } = parsed || {};
  const data = cleanTrip(raw);
  if (!data || !Number.isInteger(version)) return json({ error: "Invalid trip" }, 400);
  const result = await env.DB.prepare(
    "UPDATE trips SET data = ?, version = version + 1 WHERE edit_token = ? AND version = ?"
  )
    .bind(JSON.stringify(data), tripId, version)
    .run();
  if (result.meta.changes === 0) return json({ error: "Someone else changed this trip" }, 409);
  return json({ version: version + 1 });
}

// Trips made before accounts have no owner. The old /e/ link was their proof of ownership,
// so the first logged-in user to present it becomes the owner. Already owned looks like not found.
async function claimTrip(env, tripId, user) {
  const result = await env.DB.prepare(
    "UPDATE trips SET owner_id = ?, created_at = COALESCE(created_at, ?) WHERE edit_token = ? AND owner_id IS NULL"
  )
    .bind(user.id, Date.now(), tripId)
    .run();
  return result.meta.changes ? json({ id: tripId }) : tripNotFound();
}

async function deleteTrip(env, tripId) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM trip_members WHERE trip_id = ?").bind(tripId),
    env.DB.prepare("DELETE FROM trips WHERE edit_token = ?").bind(tripId),
  ]);
  return json({ ok: true });
}

// Owner invites a user by username, or changes an existing member's role.
async function addMember(request, env, tripId, owner) {
  const { username, role } = await request.json().catch(() => ({}));
  if (role !== "editor" && role !== "viewer") return json({ error: "Role must be editor or viewer" }, 400);
  const name = String(username || "").trim().toLowerCase();
  const invitee = await env.DB.prepare("SELECT id, username FROM users WHERE username = ?").bind(name).first();
  if (!invitee) return json({ error: `No user called "${name}"` }, 404);
  if (invitee.id === owner.id) return json({ error: "You already own this trip" }, 400);
  await env.DB.prepare(
    "INSERT INTO trip_members (trip_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT (trip_id, user_id) DO UPDATE SET role = excluded.role"
  )
    .bind(tripId, invitee.id, role)
    .run();
  return json({ username: invitee.username, role }, 201);
}

async function removeMember(env, tripId, username) {
  const result = await env.DB.prepare(
    "DELETE FROM trip_members WHERE trip_id = ? AND user_id = (SELECT id FROM users WHERE username = ?)"
  )
    .bind(tripId, username)
    .run();
  if (result.meta.changes === 0) return json({ error: "Not a member of this trip" }, 404);
  return json({ ok: true });
}

// Every /api/trips/:id route requires login and, except claiming, a role on that trip.
async function tripRoute(request, env, tripId, rest) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: "Log in first" }, 401);
  if (rest === "/claim" && request.method === "POST") return claimTrip(env, tripId, user);
  const role = await tripRole(env, tripId, user);
  if (!role) return tripNotFound();
  const method = request.method;

  if (!rest) {
    if (method === "GET") return getTrip(env, tripId, user, role);
    if (method === "PUT") return canEdit(role) ? saveTrip(request, env, tripId) : json({ error: "You can only view this trip" }, 403);
    if (method === "DELETE") return role === "owner" ? deleteTrip(env, tripId) : json({ error: "Only the owner can delete this trip" }, 403);
  }
  if (rest === "/members" && method === "POST") {
    return role === "owner" ? addMember(request, env, tripId, user) : json({ error: "Only the owner can share this trip" }, 403);
  }
  const member = rest && rest.match(/^\/members\/([a-z0-9_]{3,32})$/);
  if (member && method === "DELETE") {
    // The owner can remove anyone; members can remove themselves (leave).
    if (role !== "owner" && member[1] !== user.username) return json({ error: "Only the owner can remove people" }, 403);
    return removeMember(env, tripId, member[1]);
  }
  return json({ error: "Not found" }, 404);
}

// ---------- router ----------

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const method = request.method;

    if (method === "POST" && pathname === "/api/signup") return signup(request, env);
    if (method === "POST" && pathname === "/api/login") return login(request, env);
    if (method === "POST" && pathname === "/api/logout") return logout(request, env);
    if (method === "POST" && pathname === "/api/reset-password") return resetPassword(request, env);

    if (method === "GET" && pathname === "/api/me") {
      const user = await currentUser(request, env);
      return json({ username: user ? user.username : null });
    }

    const isMyTrips = method === "GET" && pathname === "/api/my-trips";
    const isCreate = method === "POST" && pathname === "/api/trips";
    const isNewCode = method === "POST" && pathname === "/api/recovery-code";
    if (isMyTrips || isCreate || isNewCode) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "Log in first" }, 401);
      if (isNewCode) return regenerateRecoveryCode(request, env, user);
      return isMyTrips ? myTrips(user, env) : createTrip(request, env, user);
    }

    const trip = pathname.match(/^\/api\/trips\/([0-9a-f]{32})(\/.*)?$/);
    if (trip) return tripRoute(request, env, trip[1], trip[2]);

    return json({ error: "Not found" }, 404);
  },
};
