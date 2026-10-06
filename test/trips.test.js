import { describe, it, expect } from "vitest";
import { api, signup, tripWithMembers, uniq } from "./helpers.js";

const trip = (id, opts) => api(`/api/trips/${id}`, opts);
const load = async (id, cookie) => (await trip(id, { cookie })).json();
const save = (id, cookie, body) => trip(id, { method: "PUT", cookie, body });
const validData = { title: "Edited", days: [{ notes: "hi", stops: [{ location: "Tokyo", time: "09:00", lat: 35.6, lng: 139.7 }] }] };

describe("trip access", () => {
  it("requires login", async () => {
    const { id } = await tripWithMembers();
    expect((await trip(id)).status).toBe(401);
  });

  it("owner, editor and viewer can read with their role", async () => {
    const t = await tripWithMembers();
    for (const role of ["owner", "editor", "viewer"]) {
      const body = await load(t.id, t[role].cookie);
      expect(body.role).toBe(role);
      expect(body.canEdit).toBe(role !== "viewer");
    }
  });

  it("non-member gets 404 for GET, PUT and DELETE", async () => {
    const t = await tripWithMembers();
    const cookie = t.stranger.cookie;
    expect((await trip(t.id, { cookie })).status).toBe(404);
    expect((await save(t.id, cookie, { data: validData, version: 1 })).status).toBe(404);
    expect((await trip(t.id, { method: "DELETE", cookie })).status).toBe(404);
    expect((await api(`/api/trips/${t.id}/members`, { method: "POST", cookie, body: { username: t.stranger.username, role: "editor" } })).status).toBe(404);
    expect((await load(t.id, t.owner.cookie)).version).toBe(1);
  });

  it("missing trip looks the same as no access", async () => {
    const { cookie } = await signup();
    expect((await trip("0".repeat(32), { cookie })).status).toBe(404);
  });

  it("viewer cannot save", async () => {
    const t = await tripWithMembers();
    expect((await save(t.id, t.viewer.cookie, { data: validData, version: 1 })).status).toBe(403);
    expect((await load(t.id, t.owner.cookie)).version).toBe(1);
  });

  it("editor can save but cannot share or delete", async () => {
    const t = await tripWithMembers();
    expect((await save(t.id, t.editor.cookie, { data: validData, version: 1 })).status).toBe(200);
    const share = await api(`/api/trips/${t.id}/members`, {
      method: "POST",
      cookie: t.editor.cookie,
      body: { username: t.stranger.username, role: "editor" },
    });
    expect(share.status).toBe(403);
    expect((await trip(t.id, { method: "DELETE", cookie: t.editor.cookie })).status).toBe(403);
    expect((await trip(t.id, { cookie: t.stranger.cookie })).status).toBe(404);
  });

  it("member can leave", async () => {
    const t = await tripWithMembers();
    const res = await api(`/api/trips/${t.id}/members/${t.viewer.username}`, { method: "DELETE", cookie: t.viewer.cookie });
    expect(res.status).toBe(200);
    expect((await trip(t.id, { cookie: t.viewer.cookie })).status).toBe(404);
  });

  it("member cannot remove others", async () => {
    const t = await tripWithMembers();
    const res = await api(`/api/trips/${t.id}/members/${t.viewer.username}`, { method: "DELETE", cookie: t.editor.cookie });
    expect(res.status).toBe(403);
    expect((await trip(t.id, { cookie: t.viewer.cookie })).status).toBe(200);
  });

  it("owner can remove a member", async () => {
    const t = await tripWithMembers();
    const res = await api(`/api/trips/${t.id}/members/${t.editor.username}`, { method: "DELETE", cookie: t.owner.cookie });
    expect(res.status).toBe(200);
    expect((await trip(t.id, { cookie: t.editor.cookie })).status).toBe(404);
  });

  it("owner can delete", async () => {
    const t = await tripWithMembers();
    expect((await trip(t.id, { method: "DELETE", cookie: t.owner.cookie })).status).toBe(200);
    expect((await trip(t.id, { cookie: t.owner.cookie })).status).toBe(404);
    expect((await trip(t.id, { cookie: t.editor.cookie })).status).toBe(404);
  });
});

describe("saving", () => {
  it("valid save bumps the version", async () => {
    const t = await tripWithMembers();
    const res = await save(t.id, t.owner.cookie, { data: validData, version: 1 });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ version: 2 });
    const body = await load(t.id, t.editor.cookie);
    expect(body.version).toBe(2);
    expect(body.data).toEqual(validData);
  });

  it("stale version is 409", async () => {
    const t = await tripWithMembers();
    expect((await save(t.id, t.owner.cookie, { data: validData, version: 1 })).status).toBe(200);
    const res = await save(t.id, t.editor.cookie, { data: { title: "Late", days: [] }, version: 1 });
    expect(res.status).toBe(409);
    expect((await load(t.id, t.owner.cookie)).data).toEqual(validData);
  });

  it("invalid JSON is 400", async () => {
    const t = await tripWithMembers();
    const res = await trip(t.id, { method: "PUT", cookie: t.owner.cookie, raw: "{not json" });
    expect(res.status).toBe(400);
  });

  it("wrong shape is 400", async () => {
    const t = await tripWithMembers();
    for (const body of [
      { data: validData },
      { data: { title: 1, days: [] }, version: 1 },
      { data: { title: "x", days: [{ notes: "", stops: [{ location: "x", time: "", lat: 91 }] }] }, version: 1 },
    ]) {
      expect((await save(t.id, t.owner.cookie, body)).status).toBe(400);
    }
  });
});

describe("my trips", () => {
  it("requires login", async () => {
    expect((await api("/api/my-trips")).status).toBe(401);
    expect((await api("/api/trips", { method: "POST", body: {} })).status).toBe(401);
  });

  it("lists owned and shared trips with role and owner", async () => {
    const t = await tripWithMembers();
    const mine = await (await api("/api/my-trips", { cookie: t.owner.cookie })).json();
    expect(mine).toEqual([{ id: t.id, title: "Trip", role: "owner", owner: t.owner.username }]);
    const shared = await (await api("/api/my-trips", { cookie: t.viewer.cookie })).json();
    expect(shared).toEqual([{ id: t.id, title: "Trip", role: "viewer", owner: t.owner.username }]);
    expect(await (await api("/api/my-trips", { cookie: t.stranger.cookie })).json()).toEqual([]);
  });
});

describe("creating", () => {
  const create = async (cookie, body, raw) => {
    const res = await api("/api/trips", { method: "POST", cookie, body, raw });
    expect(res.status).toBe(201);
    return (await load((await res.json()).id, cookie)).data;
  };

  it("defaults the title and starts with one empty day", async () => {
    const { cookie } = await signup();
    expect(await create(cookie, undefined, "not json")).toEqual({ title: "Untitled trip", days: [{ notes: "", stops: [] }] });
  });

  it("truncates long titles to 200 characters", async () => {
    const { cookie } = await signup();
    expect((await create(cookie, { title: "x".repeat(300) })).title).toHaveLength(200);
  });
});

describe("sharing", () => {
  const members = (t, body) => api(`/api/trips/${t.id}/members`, { method: "POST", cookie: t.owner.cookie, body });

  it("validates the invite", async () => {
    const t = await tripWithMembers();
    expect((await members(t, { username: t.stranger.username, role: "admin" })).status).toBe(400);
    expect((await members(t, { username: uniq(), role: "viewer" })).status).toBe(404);
    expect((await members(t, { username: t.owner.username, role: "editor" })).status).toBe(400);
  });

  it("re-inviting changes the role", async () => {
    const t = await tripWithMembers();
    const res = await members(t, { username: " " + t.viewer.username.toUpperCase(), role: "editor" });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ username: t.viewer.username, role: "editor" });
    expect((await load(t.id, t.viewer.cookie)).canEdit).toBe(true);
  });

  it("lists members on the trip", async () => {
    const t = await tripWithMembers();
    const body = await load(t.id, t.editor.cookie);
    expect(body).toMatchObject({ owner: t.owner.username, you: t.editor.username, role: "editor" });
    expect(body.members.map((m) => m.role).sort()).toEqual(["editor", "viewer"]);
  });

  it("removing a non-member is 404", async () => {
    const t = await tripWithMembers();
    const res = await api(`/api/trips/${t.id}/members/${t.stranger.username}`, { method: "DELETE", cookie: t.owner.cookie });
    expect(res.status).toBe(404);
  });

  it("unknown trip sub-routes are 404", async () => {
    const t = await tripWithMembers();
    for (const [method, rest] of [["PATCH", ""], ["GET", "/members"], ["POST", "/nope"], ["DELETE", "/members/A!"]]) {
      expect((await api(`/api/trips/${t.id}${rest}`, { method, cookie: t.owner.cookie })).status).toBe(404);
    }
  });
});
