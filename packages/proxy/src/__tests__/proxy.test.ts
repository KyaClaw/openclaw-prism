import { describe, it, expect, afterAll, vi, beforeEach } from "vitest";
import { createServer } from "../index.js";
import type { Policy } from "../index.js";
import type http from "node:http";

const TEST_POLICY: Policy = {
  host: "127.0.0.1",
  port: 0,
  upstreamUrl: "http://127.0.0.1:19999", // non-existent for testing
  upstreamTokenEnv: "TEST_UPSTREAM_TOKEN",
  defaultDenyTools: ["gateway"],
  clients: [
    {
      id: "test-client",
      token: "test-token-123",
      allowedSessionPrefixes: ["user-a:"],
      allowTools: ["read", "write", "exec", "web_fetch"],
    },
  ],
};

function postInvoke(
  port: number,
  body: Record<string, unknown>,
  token = "test-token-123",
): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}/tools/invoke`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
}

describe("Invoke Guard Proxy", () => {
  let server: http.Server;
  let port: number;

  beforeEach(async () => {
    if (server) server.close();
    const { server: s } = createServer({ ...TEST_POLICY });
    server = s;
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      server.once("error", onError);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", onError);
        port = (server.address() as { port: number }).port;
        resolve();
      });
    });
  });

  afterAll(() => {
    if (server) server.close();
  });

  it("responds to /healthz", async () => {
    const resp = await fetch(`http://127.0.0.1:${port}/healthz`);
    expect(resp.status).toBe(200);
    expect(await resp.json()).toEqual({ ok: true });
  });

  it("returns 404 for unknown routes", async () => {
    const resp = await fetch(`http://127.0.0.1:${port}/unknown`);
    expect(resp.status).toBe(404);
  });

  it("returns 401 for invalid token", async () => {
    const resp = await postInvoke(
      port,
      { tool: "read", sessionKey: "user-a:1", args: {} },
      "invalid-token",
    );
    expect(resp.status).toBe(401);
  });

  it("returns 400 when tool is missing", async () => {
    const resp = await postInvoke(port, { sessionKey: "user-a:1" });
    expect(resp.status).toBe(400);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("tool is required");
  });

  it("returns 400 when sessionKey is missing", async () => {
    const resp = await postInvoke(port, { tool: "read" });
    expect(resp.status).toBe(400);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("sessionKey is required");
  });

  it("returns 403 for session ownership violation", async () => {
    const resp = await postInvoke(port, {
      tool: "read",
      sessionKey: "user-b:1",
      args: {},
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("session ownership");
  });

  it("returns 403 for denied tool", async () => {
    const resp = await postInvoke(port, {
      tool: "gateway",
      sessionKey: "user-a:1",
      args: {},
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("denied by policy");
  });

  it("returns 403 for tool not in client allowTools", async () => {
    const resp = await postInvoke(port, {
      tool: "delete",
      sessionKey: "user-a:1",
      args: {},
    });
    expect(resp.status).toBe(403);
  });

  it("returns 403 for dangerous exec", async () => {
    const resp = await postInvoke(port, {
      tool: "exec",
      sessionKey: "user-a:1",
      args: { command: "rm -rf / --no-preserve" },
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("dangerous exec");
  });

  it("returns 500 when upstream token env is not set", async () => {
    // read is allowed, session prefix matches, but no upstream token
    delete process.env.TEST_UPSTREAM_TOKEN;
    const resp = await postInvoke(port, {
      tool: "read",
      sessionKey: "user-a:1",
      args: { path: "/tmp/test" },
    });
    expect(resp.status).toBe(500);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("missing env");
  });

  it("returns 502 when upstream is unreachable", async () => {
    process.env.TEST_UPSTREAM_TOKEN = "upstream-secret";
    const resp = await postInvoke(port, {
      tool: "read",
      sessionKey: "user-a:1",
      args: { path: "/tmp/test" },
    });
    // upstream at port 19999 is not running
    expect(resp.status).toBe(502);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("upstream unavailable");
    delete process.env.TEST_UPSTREAM_TOKEN;
  });
});
