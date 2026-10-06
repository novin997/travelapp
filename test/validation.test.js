import { describe, it, expect } from "vitest";
import { api, tripWithMembers } from "./helpers.js";

// Trip validation and size limits (#4).
const put = (t, body, raw) => api(`/api/trips/${t.id}`, { method: "PUT", cookie: t.owner.cookie, body, raw });
const day = (stops, notes = "") => ({ notes, stops });
const trip = (days, title = "T") => ({ data: { title, days }, version: 1 });

describe("trip validation", () => {
  it("rejects malformed trips with a JSON 400", async () => {
    const t = await tripWithMembers();
    const bad = [
      trip([null]),
      trip(["day"]),
      trip([[]]),
      trip([{ notes: 1, stops: [] }]),
      trip([{ notes: "", stops: "x" }]),
      trip([day([null])]),
      trip([day([{ time: "", location: 5 }])]),
      trip([day([{ time: 9, location: "x" }])]),
      trip([day([{ time: "", location: "x", lat: 1 }])]),
      trip([day([{ time: "", location: "x", lng: 1 }])]),
      trip([day([{ time: "", location: "x", lat: "1", lng: 1 }])]),
      trip([day([{ time: "", location: "x", lat: 1, lng: 181 }])]),
      trip([day([{ time: "24:00", location: "x" }])]),
      trip([day([{ time: "9:00", location: "x" }])]),
      trip([day([{ time: "<b>noon</b>", location: "x" }])]),
      trip([], "x".repeat(201)),
      trip("days"),
      { data: null, version: 1 },
      { data: [], version: 1 },
      { data: { title: "T", days: [] }, version: "1" },
    ];
    for (const body of bad) {
      const res = await put(t, body);
      expect(res.status, JSON.stringify(body).slice(0, 80)).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid trip" });
    }
    expect((await put(t, undefined, "null")).status).toBe(400);
  });

  it("stores only known fields", async () => {
    const t = await tripWithMembers();
    const body = trip([{ notes: "n", x: 1, stops: [{ time: "23:59", location: "A", lat: -90, lng: 180, evil: true }, { time: "", location: "B" }] }], "x".repeat(200));
    body.data.__extra = "y";
    expect((await put(t, body)).status).toBe(200);
    const saved = await (await api(`/api/trips/${t.id}`, { cookie: t.owner.cookie })).json();
    expect(saved.data).toEqual({
      title: "x".repeat(200),
      days: [{ notes: "n", stops: [{ time: "23:59", location: "A", lat: -90, lng: 180 }, { time: "", location: "B" }] }],
    });
  });
});

describe("trip size limit", () => {
  // 3-byte characters: under 100 000 characters but over 100 000 bytes.
  const big = (t) => JSON.stringify(trip([day([], "€".repeat(40_000))]));

  it("rejects a large content-length before reading the body", async () => {
    const t = await tripWithMembers();
    const res = await put(t, undefined, big(t));
    expect(res.status).toBe(413);
  });

  it("measures real bytes when there is no content-length", async () => {
    const t = await tripWithMembers();
    const stream = (text) => new Blob([text]).stream();
    expect((await put(t, undefined, stream(big(t)))).status).toBe(413);
    expect((await put(t, undefined, stream(JSON.stringify(trip([day([], "€".repeat(30_000))]))))).status).toBe(200);
  });
});
