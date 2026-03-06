import { describe, it, expect, afterEach } from "vitest";
import { createServer } from "node:http";
import type http from "node:http";
import { runVerify } from "../verify.js";

type StartedServer = { server: http.Server; port: number };

async function startHttpServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<StartedServer> {
  const server = createServer(handler);
  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (err: Error) => rejectListen(err);
    server.once("error", onError);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", onError);
      resolveListen();
    });
  });
  return { server, port: (server.address() as { port: number }).port };
}

describe("runVerify scanner auth contract", () => {
  let scanner: http.Server | null = null;
  let proxy: http.Server | null = null;

  afterEach(async () => {
    for (const server of [scanner, proxy]) {
      if (server) {
        await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      }
    }
    scanner = null;
    proxy = null;
  });

  it("passes and sends bearer token when auth is valid", async () => {
    const expectedToken = "scanner-good";
    let seenAuth = "";
    scanner = (await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/scan") {
        seenAuth = String(req.headers.authorization ?? "");
        if (seenAuth !== `Bearer ${expectedToken}`) {
          res.statusCode = 401;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ verdict: "suspicious", score: 60 }));
        return;
      }
      res.statusCode = 404;
      res.end();
    })).server;

    const scannerPort = (scanner.address() as { port: number }).port;

    proxy = (await startHttpServer((req, res) => {
      if (req.method === "GET" && req.url === "/healthz") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    })).server;
    const proxyPort = (proxy.address() as { port: number }).port;

    const stdout: string[] = [];
    const stderr: string[] = [];
    const code = await runVerify({
      scannerUrl: `http://127.0.0.1:${scannerPort}/scan`,
      proxyUrl: `http://127.0.0.1:${proxyPort}/healthz`,
      scannerToken: expectedToken,
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line),
    });

    expect(code).toBe(0);
    expect(seenAuth).toBe(`Bearer ${expectedToken}`);
    expect(stderr.join("")).not.toContain("[verify] FAIL");
  });

  it("fails fast when scanner token is missing", async () => {
    let scannerHits = 0;
    const scannerStarted = await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/scan") scannerHits++;
      res.statusCode = 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ verdict: "suspicious", score: 60 }));
    });
    scanner = scannerStarted.server;

    const proxyStarted = await startHttpServer((req, res) => {
      if (req.method === "GET" && req.url === "/healthz") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    proxy = proxyStarted.server;

    const stderr: string[] = [];
    const code = await runVerify({
      scannerUrl: `http://127.0.0.1:${scannerStarted.port}/scan`,
      proxyUrl: `http://127.0.0.1:${proxyStarted.port}/healthz`,
      scannerToken: "",
      stdout: () => {},
      stderr: (line) => stderr.push(line),
    });

    expect(code).toBe(1);
    expect(scannerHits).toBe(0);
    expect(stderr.join("")).toContain("SCANNER_AUTH_TOKEN is not set");
  });

  it("fails on scanner 401 for invalid token", async () => {
    const scannerStarted = await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/scan") {
        res.statusCode = 401;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    scanner = scannerStarted.server;

    const proxyStarted = await startHttpServer((req, res) => {
      if (req.method === "GET" && req.url === "/healthz") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    proxy = proxyStarted.server;

    const stderr: string[] = [];
    const code = await runVerify({
      scannerUrl: `http://127.0.0.1:${scannerStarted.port}/scan`,
      proxyUrl: `http://127.0.0.1:${proxyStarted.port}/healthz`,
      scannerToken: "scanner-bad",
      stdout: () => {},
      stderr: (line) => stderr.push(line),
    });

    expect(code).toBe(1);
    expect(stderr.join("")).toContain("scanner auth rejected (401)");
  });

  it("fails on scanner non-200 responses", async () => {
    const scannerStarted = await startHttpServer((req, res) => {
      if (req.method === "POST" && req.url === "/scan") {
        res.statusCode = 503;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "unavailable" }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    scanner = scannerStarted.server;

    const proxyStarted = await startHttpServer((req, res) => {
      if (req.method === "GET" && req.url === "/healthz") {
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    proxy = proxyStarted.server;

    const stderr: string[] = [];
    const code = await runVerify({
      scannerUrl: `http://127.0.0.1:${scannerStarted.port}/scan`,
      proxyUrl: `http://127.0.0.1:${proxyStarted.port}/healthz`,
      scannerToken: "scanner-good",
      stdout: () => {},
      stderr: (line) => stderr.push(line),
    });

    expect(code).toBe(1);
    expect(stderr.join("")).toContain("scanner returned 503");
  });
});
