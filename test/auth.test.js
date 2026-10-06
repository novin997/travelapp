import { describe, it, expect } from "vitest";
import { api, cookieOf, signup, uniq, newIp } from "./helpers.js";

const me = async (cookie) => (await (await api("/api/me", { cookie })).json()).username;

describe("accounts", () => {
  it("signup logs in and returns a recovery code", async () => {
    const res = await api("/api/signup", { method: "POST", body: { username: uniq(), password: "password123" } });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.recoveryCode).toMatch(/^([A-Z2-9]{4}-){4}[A-Z2-9]{4}$/);
    expect(await me(cookieOf(res))).toBe(body.username);
  });

  it("rejects a taken username", async () => {
    const { username } = await signup();
    const res = await api("/api/signup", { method: "POST", body: { username, password: "password123" } });
    expect(res.status).toBe(409);
  });

  it("/api/me is null without a session", async () => {
    expect(await me()).toBeNull();
  });

  it("login with the right password starts a session", async () => {
    const { username, password } = await signup();
    const res = await api("/api/login", { method: "POST", body: { username, password } });
    expect(res.status).toBe(200);
    expect(await me(cookieOf(res))).toBe(username);
  });

  it("login with the wrong password is 401", async () => {
    const { username } = await signup();
    const res = await api("/api/login", { method: "POST", body: { username, password: "wrongpassword" } });
    expect(res.status).toBe(401);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("logout ends the session", async () => {
    const { username, cookie } = await signup();
    expect(await me(cookie)).toBe(username);
    const res = await api("/api/logout", { method: "POST", cookie });
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toMatch(/Max-Age=0/);
    expect(await me(cookie)).toBeNull();
  });
});

describe("rate limiting", () => {
  it("locks a username out after 5 failed logins", async () => {
    const { username, password } = await signup();
    const ip = newIp();
    for (let i = 0; i < 5; i++) {
      const res = await api("/api/login", { method: "POST", ip, body: { username, password: "wrongpassword" } });
      expect(res.status).toBe(401);
    }
    // Even the right password is refused while locked out.
    const res = await api("/api/login", { method: "POST", ip, body: { username, password } });
    expect(res.status).toBe(429);
    expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);
  });
});

describe("reset-password", () => {
  it("rotates the recovery code and logs out old sessions", async () => {
    const user = await signup();
    const reset = (code) =>
      api("/api/reset-password", {
        method: "POST",
        body: { username: user.username, code, password: "newpassword456" },
      });

    const res = await reset(user.recoveryCode.toLowerCase().replace(/-/g, ""));
    expect(res.status).toBe(200);
    const { recoveryCode } = await res.json();
    expect(recoveryCode).not.toBe(user.recoveryCode);
    expect(await me(cookieOf(res))).toBe(user.username);

    expect(await me(user.cookie)).toBeNull();
    expect((await reset(user.recoveryCode)).status).toBe(401);
    expect((await api("/api/login", { method: "POST", body: { username: user.username, password: user.password } })).status).toBe(401);
    expect((await api("/api/login", { method: "POST", body: { username: user.username, password: "newpassword456" } })).status).toBe(200);
    expect((await reset(recoveryCode)).status).toBe(200);
  });

  it("rejects a wrong code", async () => {
    const { username } = await signup();
    const res = await api("/api/reset-password", {
      method: "POST",
      body: { username, code: "AAAA-AAAA-AAAA-AAAA-AAAA", password: "newpassword456" },
    });
    expect(res.status).toBe(401);
  });
});

describe("signup validation", () => {
  const post = (body, raw) => api("/api/signup", { method: "POST", body, raw });

  it("rejects bad usernames", async () => {
    for (const username of ["ab", "has space", "x".repeat(33), ""]) {
      expect((await post({ username, password: "password123" })).status).toBe(400);
    }
  });

  it("rejects short and long passwords with the right message", async () => {
    const short = await post({ username: uniq(), password: "1234567" });
    expect(short.status).toBe(400);
    expect((await short.json()).error).toMatch(/at least 8/);
    const long = await post({ username: uniq(), password: "x".repeat(201) });
    expect(long.status).toBe(400);
    expect((await long.json()).error).toMatch(/at most 200/);
  });

  it("treats a non-JSON body as empty credentials", async () => {
    expect((await post(undefined, "not json")).status).toBe(400);
  });

  it("normalises the username to lower case", async () => {
    const name = uniq();
    const res = await post({ username: "  " + name.toUpperCase() + " ", password: "password123" });
    expect((await res.json()).username).toBe(name);
  });
});

describe("session cookie", () => {
  it("is Secure over https only", async () => {
    const https = await api("/api/signup", { method: "POST", base: "https://travelapp.test", body: { username: uniq(), password: "password123" } });
    expect(https.headers.get("set-cookie")).toMatch(/; Secure$/);
    const http = await api("/api/signup", { method: "POST", body: { username: uniq(), password: "password123" } });
    expect(http.headers.get("set-cookie")).not.toMatch(/Secure/);
    expect(http.headers.get("set-cookie")).toMatch(/HttpOnly; SameSite=Lax/);
  });

  it("ignores a malformed session cookie", async () => {
    expect(await me("session=not-a-token")).toBeNull();
  });
});

describe("client address", () => {
  it("refuses login and reset without cf-connecting-ip outside local dev", async () => {
    const { username, password, recoveryCode } = await signup();
    const login = await api("/api/login", { method: "POST", ip: null, body: { username, password } });
    expect(login.status).toBe(400);
    const reset = await api("/api/reset-password", { method: "POST", ip: null, body: { username, code: recoveryCode, password: "newpassword456" } });
    expect(reset.status).toBe(400);
  });

  it("allows a missing address on localhost", async () => {
    const { username, password } = await signup();
    for (const base of ["http://localhost:8787", "http://127.0.0.1:8787"]) {
      expect((await api("/api/login", { method: "POST", ip: null, base, body: { username, password } })).status).toBe(200);
    }
  });
});

describe("rate limiting (fixes from #6)", () => {
  it("parallel bad logins get at most 5 password checks", async () => {
    const { username } = await signup();
    const ip = newIp();
    const results = await Promise.all(
      Array.from({ length: 15 }, (_, i) => api("/api/login", { method: "POST", ip, body: { username, password: "wrong" + i } }))
    );
    const codes = results.map((r) => r.status);
    expect(codes.filter((c) => c === 401).length).toBeLessThanOrEqual(5);
    expect(codes.filter((c) => c === 429).length).toBeGreaterThanOrEqual(10);
  });

  it("locks the username only for the attacking IP", async () => {
    const { username, password } = await signup();
    const attacker = newIp();
    for (let i = 0; i < 5; i++) await api("/api/login", { method: "POST", ip: attacker, body: { username, password: "wrong" } });
    expect((await api("/api/login", { method: "POST", ip: attacker, body: { username, password } })).status).toBe(429);
    expect((await api("/api/login", { method: "POST", ip: newIp(), body: { username, password } })).status).toBe(200);
  });

  it("locks out recovery-code guessing", async () => {
    const { username, recoveryCode } = await signup();
    const ip = newIp();
    const reset = (code) => api("/api/reset-password", { method: "POST", ip, body: { username, code, password: "newpassword456" } });
    for (let i = 0; i < 5; i++) expect((await reset("AAAA-AAAA-AAAA-AAAA-AAAA")).status).toBe(401);
    const locked = await reset(recoveryCode);
    expect(locked.status).toBe(429);
    expect((await locked.json()).error).toMatch(/Try again in \d+ minutes?/);
  });
});

describe("reset-password edge cases", () => {
  it("a bad new password is 400 and doesn't use up the code", async () => {
    const { username, recoveryCode } = await signup();
    const ip = newIp();
    const reset = (password) => api("/api/reset-password", { method: "POST", ip, body: { username, code: recoveryCode, password } });
    for (let i = 0; i < 6; i++) expect((await reset("short")).status).toBe(400);
    expect((await reset("newpassword456")).status).toBe(200);
  });

  it("an empty body is a wrong code", async () => {
    expect((await api("/api/reset-password", { method: "POST", raw: "" })).status).toBe(401);
  });

  it("an unknown user is a wrong code", async () => {
    const res = await api("/api/reset-password", { method: "POST", body: { username: uniq(), code: "AAAA", password: "newpassword456" } });
    expect(res.status).toBe(401);
  });
});

describe("new recovery code", () => {
  const regen = (cookie, body, raw) => api("/api/recovery-code", { method: "POST", cookie, body, raw });

  it("requires login", async () => {
    expect((await regen(undefined, { password: "password123" })).status).toBe(401);
  });

  it("needs the current password", async () => {
    const { cookie } = await signup();
    expect((await regen(cookie, { password: "wrongpassword" })).status).toBe(401);
    expect((await regen(cookie, undefined, "not json")).status).toBe(401);
  });

  it("replaces the old code", async () => {
    const user = await signup();
    const res = await regen(user.cookie, { password: user.password });
    expect(res.status).toBe(200);
    const { recoveryCode } = await res.json();
    expect(recoveryCode).not.toBe(user.recoveryCode);
    const reset = (code) => api("/api/reset-password", { method: "POST", body: { username: user.username, code, password: "newpassword456" } });
    expect((await reset(user.recoveryCode)).status).toBe(401);
    expect((await reset(recoveryCode)).status).toBe(200);
  });

  it("locks out after 5 wrong passwords", async () => {
    const { cookie, password } = await signup();
    for (let i = 0; i < 5; i++) expect((await regen(cookie, { password: "wrongpassword" })).status).toBe(401);
    expect((await regen(cookie, { password })).status).toBe(429);
  });
});

describe("routing", () => {
  it("unknown API paths are 404", async () => {
    for (const [method, path] of [["GET", "/api/nope"], ["GET", "/api/login"], ["GET", "/api/trips/not-hex"], ["DELETE", "/api/my-trips"]]) {
      expect((await api(path, { method })).status).toBe(404);
    }
  });

  it("JSON responses carry content-type", async () => {
    expect((await api("/api/me")).headers.get("content-type")).toBe("application/json");
  });
});
