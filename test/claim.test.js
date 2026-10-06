import { describe, it, expect } from "vitest";
import { env } from "cloudflare:workers";
import { api, signup } from "./helpers.js";

// Claiming trips made before accounts existed (#3).
const hex = () => crypto.randomUUID().replace(/-/g, "");
const claim = (id, cookie) => api(`/api/trips/${id}/claim`, { method: "POST", cookie });

async function legacyTrip() {
  const id = hex();
  await env.DB.prepare("INSERT INTO trips (edit_token, view_token, data) VALUES (?, ?, ?)")
    .bind(id, hex(), JSON.stringify({ title: "Old", days: [{ notes: "", stops: [] }] }))
    .run();
  return id;
}

describe("claiming legacy trips", () => {
  it("requires login", async () => {
    expect((await claim(await legacyTrip())).status).toBe(401);
  });

  it("the first claimant becomes owner", async () => {
    const id = await legacyTrip();
    const [a, b] = await Promise.all([signup(), signup()]);
    expect((await api(`/api/trips/${id}`, { cookie: a.cookie })).status).toBe(404);

    const res = await claim(id, a.cookie);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id });
    const trip = await (await api(`/api/trips/${id}`, { cookie: a.cookie })).json();
    expect(trip).toMatchObject({ role: "owner", owner: a.username, data: { title: "Old" } });
    expect(await (await api("/api/my-trips", { cookie: a.cookie })).json()).toEqual([
      { id, title: "Old", role: "owner", owner: a.username },
    ]);
    const row = await env.DB.prepare("SELECT created_at FROM trips WHERE edit_token = ?").bind(id).first();
    expect(row.created_at).toBeGreaterThan(0);

    expect((await claim(id, b.cookie)).status).toBe(404);
    expect((await claim(id, a.cookie)).status).toBe(404);
  });

  it("owned and missing trips look the same", async () => {
    const a = await signup();
    const { id } = await (await api("/api/trips", { method: "POST", cookie: a.cookie, body: {} })).json();
    expect((await claim(id, a.cookie)).status).toBe(404);
    expect((await claim(hex(), a.cookie)).status).toBe(404);
  });

  it("only POST claims", async () => {
    const id = await legacyTrip();
    const a = await signup();
    expect((await api(`/api/trips/${id}/claim`, { cookie: a.cookie })).status).toBe(404);
    expect((await claim(id, a.cookie)).status).toBe(200);
  });
});
