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
