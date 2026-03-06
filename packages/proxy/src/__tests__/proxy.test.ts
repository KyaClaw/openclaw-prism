import { describe, it, expect, afterAll, afterEach, beforeEach } from "vitest";
import { createServer } from "../index.js";
import type { Policy } from "../index.js";
import { createServer as createHttpServer } from "node:http";
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

async function startHttpServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ server: http.Server; port: number }> {
  const server = createHttpServer(handler);
  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  return { server, port: (server.address() as { port: number }).port };
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

  it("returns 403 for shell trampoline exec", async () => {
    const resp = await postInvoke(port, {
      tool: "exec",
      sessionKey: "user-a:1",
      args: { command: "/bin/bash -c whoami" },
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("shell-trampoline");
  });

  it("returns 403 for git ssh override trampoline", async () => {
    const resp = await postInvoke(port, {
      tool: "exec",
      sessionKey: "user-a:1",
      args: { command: "git -c core.sshCommand=evil push origin main" },
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("git-ssh-override");
  });

  it("returns 403 for inline interpreter trampoline", async () => {
    const resp = await postInvoke(port, {
      tool: "exec",
      sessionKey: "user-a:1",
      args: { command: "node --eval process.exit" },
    });
    expect(resp.status).toBe(403);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("interpreter-inline-code");
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

describe("Invoke Guard Proxy scanner auth contract", () => {
  let upstream: http.Server | null = null;
  let scanner: http.Server | null = null;
  let proxy: http.Server | null = null;
  let proxyPort = 0;

  afterEach(async () => {
    for (const server of [proxy, scanner, upstream]) {
      if (server) {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    }
    proxy = null;
    scanner = null;
    upstream = null;
    delete process.env.TEST_UPSTREAM_TOKEN;
    delete process.env.SCANNER_AUTH_TOKEN;
  });

  async function bootProxyWithScanner(opts: {
    expectedScannerAuth: string;
    scannerStatus?: number;
    scannerBody?: Record<string, unknown>;
  }): Promise<{ scannerAuthSeen: () => string; scannerHits: () => number }> {
    let authHeaderSeen = "";
    let scannerCallCount = 0;

    const upstreamServer = await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/tools/invoke") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true, result: "safe text" }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ ok: false }));
    });
    upstream = upstreamServer.server;

    const scannerServer = await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/scan") {
        scannerCallCount++;
        authHeaderSeen = String(req.headers.authorization ?? "");
        if (authHeaderSeen !== `Bearer ${opts.expectedScannerAuth}`) {
          res.statusCode = 401;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
        res.statusCode = opts.scannerStatus ?? 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(opts.scannerBody ?? { verdict: "benign", reasons: [] }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ ok: false }));
    });
    scanner = scannerServer.server;

    process.env.TEST_UPSTREAM_TOKEN = "upstream-secret";
    const policy: Policy = {
      host: "127.0.0.1",
      port: 0,
      upstreamUrl: `http://127.0.0.1:${upstreamServer.port}`,
      upstreamTokenEnv: "TEST_UPSTREAM_TOKEN",
      defaultDenyTools: ["gateway"],
      scannerUrl: `http://127.0.0.1:${scannerServer.port}/scan`,
      scannerTimeoutMs: 1200,
      blockOnScannerFailure: true,
      clients: [
        {
          id: "scanner-contract-client",
          token: "test-token-123",
          allowedSessionPrefixes: ["user-a:"],
          allowTools: ["web_fetch"],
        },
      ],
    };

    const created = createServer(policy);
    proxy = created.server;
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      created.server.once("error", onError);
      created.server.listen(0, "127.0.0.1", () => {
        created.server.off("error", onError);
        proxyPort = (created.server.address() as { port: number }).port;
        resolve();
      });
    });

    return {
      scannerAuthSeen: () => authHeaderSeen,
      scannerHits: () => scannerCallCount,
    };
  }

  it("forwards scanner bearer token from SCANNER_AUTH_TOKEN", async () => {
    process.env.SCANNER_AUTH_TOKEN = "scanner-good";
    const state = await bootProxyWithScanner({ expectedScannerAuth: "scanner-good" });

    const resp = await postInvoke(proxyPort, {
      tool: "web_fetch",
      sessionKey: "user-a:scan1",
      args: { url: "https://example.com" },
    });
    expect(resp.status).toBe(200);
    expect(state.scannerHits()).toBe(1);
    expect(state.scannerAuthSeen()).toBe("Bearer scanner-good");
  });

  it("fails closed when SCANNER_AUTH_TOKEN is missing", async () => {
    delete process.env.SCANNER_AUTH_TOKEN;
    const state = await bootProxyWithScanner({ expectedScannerAuth: "scanner-good" });

    const resp = await postInvoke(proxyPort, {
      tool: "web_fetch",
      sessionKey: "user-a:scan2",
      args: { url: "https://example.com" },
    });
    expect(resp.status).toBe(503);
    expect(state.scannerHits()).toBe(0);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("SCANNER_AUTH_TOKEN is required");
  });

  it("fails closed on scanner 401 due to invalid token", async () => {
    process.env.SCANNER_AUTH_TOKEN = "scanner-bad";
    const state = await bootProxyWithScanner({ expectedScannerAuth: "scanner-good" });

    const resp = await postInvoke(proxyPort, {
      tool: "web_fetch",
      sessionKey: "user-a:scan3",
      args: { url: "https://example.com" },
    });
    expect(resp.status).toBe(503);
    expect(state.scannerHits()).toBe(1);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("scanner status=401");
  });

  it("fails closed on scanner non-200 responses", async () => {
    process.env.SCANNER_AUTH_TOKEN = "scanner-good";
    const state = await bootProxyWithScanner({
      expectedScannerAuth: "scanner-good",
      scannerStatus: 503,
      scannerBody: { error: "unavailable" },
    });

    const resp = await postInvoke(proxyPort, {
      tool: "web_fetch",
      sessionKey: "user-a:scan4",
      args: { url: "https://example.com" },
    });
    expect(resp.status).toBe(503);
    expect(state.scannerHits()).toBe(1);
    const body = await resp.json() as { error: string };
    expect(body.error).toContain("scanner status=503");
  });
});
