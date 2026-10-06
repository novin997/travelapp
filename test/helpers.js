import { exports } from "cloudflare:workers";

const BASE = "http://travelapp.test";

// Unique per call, so tests never share users or rate-limit buckets.
export const uniq = (prefix = "u") => `${prefix}_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
export const newIp = () => `10.${[0, 0, 0].map(() => Math.floor(Math.random() * 256)).join(".")}`;

export function api(path, { method = "GET", body, cookie, ip, raw } = {}) {
  const headers = { "cf-connecting-ip": ip || newIp() };
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers["content-type"] = "application/json";
  return exports.default.fetch(`${BASE}${path}`, {
    method,
    headers,
    body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body),
  });
}

export const cookieOf = (res) => res.headers.get("set-cookie").split(";")[0];

export async function signup(username = uniq(), password = "password123") {
  const res = await api("/api/signup", { method: "POST", body: { username, password } });
  if (res.status !== 200) throw new Error(`signup ${res.status}`);
  const { recoveryCode } = await res.json();
  return { username, password, recoveryCode, cookie: cookieOf(res) };
}

// Owner plus an editor, a viewer and an unrelated user, all on one fresh trip.
export async function tripWithMembers() {
  const [owner, editor, viewer, stranger] = await Promise.all([signup(), signup(), signup(), signup()]);
  const res = await api("/api/trips", { method: "POST", cookie: owner.cookie, body: { title: "Trip" } });
  const { id } = await res.json();
  for (const [user, role] of [[editor, "editor"], [viewer, "viewer"]]) {
    const r = await api(`/api/trips/${id}/members`, {
      method: "POST",
      cookie: owner.cookie,
      body: { username: user.username, role },
    });
    if (r.status !== 201) throw new Error(`addMember ${r.status}`);
  }
  return { id, owner, editor, viewer, stranger };
}
