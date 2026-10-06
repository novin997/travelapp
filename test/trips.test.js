import { describe, it, expect } from "vitest";
import { api, signup, tripWithMembers } from "./helpers.js";

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
