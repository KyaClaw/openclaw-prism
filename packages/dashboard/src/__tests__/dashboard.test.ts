import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "../index.js";
import type http from "node:http";
import { createServer as createHttpServer } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readAuditEntries } from "../audit-reader.js";

type StartedServer = { server: http.Server; port: number };

async function startHttpServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<StartedServer> {
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

describe("dashboard HTTP APIs", () => {
  let dashboard: http.Server | null = null;
  let internalAudit: http.Server | null = null;
  const originalEnv = { ...process.env };

  afterEach(async () => {
    for (const s of [dashboard, internalAudit]) {
      if (s) await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    dashboard = null;
    internalAudit = null;
    process.env = { ...originalEnv };
  });

  it("serves healthz and enforces bearer auth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-integration-"));
    const policyPath = join(dir, "security.policy.json");
    const auditPath = join(dir, "audit.jsonl");
    writeFileSync(policyPath, `${JSON.stringify({ execAllowedPrefixes: ["node"] }, null, 2)}\n`);
    writeFileSync(auditPath, `${JSON.stringify({
      ts: "2026-03-06T12:00:00.000Z",
      event: "exec_whitelist_block",
      command: "curl https://example.com",
      session: "sess-a",
    })}\n`);

    const auditEvents: Record<string, unknown>[] = [];
    const internalStarted = await startHttpServer((req, res) => {
      if (req.method !== "POST" || req.url !== "/internal/audit") {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        auditEvents.push(JSON.parse(body || "{}") as Record<string, unknown>);
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
      });
    });
    internalAudit = internalStarted.server;

    process.env.PRISM_DASHBOARD_TOKEN = "dashboard-test-token";
    process.env.PRISM_INTERNAL_TOKEN = "internal-test-token";
    process.env.PRISM_INTERNAL_PORT = String(internalStarted.port);
    process.env.PRISM_SECURITY_POLICY = policyPath;
    process.env.PRISM_AUDIT_LOG = auditPath;

    dashboard = createServer();
    await new Promise<void>((resolve, reject) => {
      dashboard!.once("error", reject);
      dashboard!.listen(0, "127.0.0.1", () => resolve());
    });
    const port = (dashboard.address() as { port: number }).port;

    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true });

    const unauthorized = await fetch(`http://127.0.0.1:${port}/api/config`);
    expect(unauthorized.status).toBe(401);

    const blocks = await fetch(`http://127.0.0.1:${port}/api/blocks?limit=10`, {
      headers: { authorization: "Bearer dashboard-test-token" },
    });
    expect(blocks.status).toBe(200);
    const blocksJson = await blocks.json() as {
      blocks: Array<{ event: string; allowAction: { supported: boolean; type?: string } }>;
    };
    expect(blocksJson.blocks).toHaveLength(1);
    expect(blocksJson.blocks[0]!.event).toBe("exec_whitelist_block");
    expect(blocksJson.blocks[0]!.allowAction.supported).toBe(true);
    expect(blocksJson.blocks[0]!.allowAction.type).toBe("add_exec_prefix");

    // wait for async auth_failed event delegation
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(auditEvents.some((event) => event.event === "dashboard_auth_failed")).toBe(true);
  });

  it("supports config validate/update and allow preview/apply flows", async () => {
    const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-flows-"));
    const policyPath = join(dir, "security.policy.json");
    const auditPath = join(dir, "audit.jsonl");
    writeFileSync(policyPath, `${JSON.stringify({
      execAllowedPrefixes: ["node"],
      protectedPathExceptions: [],
      execBlockedPatterns: ["rm\\s+-rf\\s+/"],
      outboundSecretPatterns: ["AKIA[0-9A-Z]{16}"],
    }, null, 2)}\n`);
    writeFileSync(auditPath, `${[
      JSON.stringify({
        ts: "2026-03-06T12:00:00.000Z",
        event: "exec_whitelist_block",
        command: "curl https://example.com",
        session: "sess-a",
      }),
      JSON.stringify({
        ts: "2026-03-06T12:01:00.000Z",
        event: "path_block",
        rawPath: "../etc/hosts",
        cwd: "/home/user/project",
        session: "sess-path",
      }),
    ].join("\n")}\n`);

    const delegated: Record<string, unknown>[] = [];
    const internal = await startHttpServer((req, res) => {
      if (req.method !== "POST" || req.url !== "/internal/audit") {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }
      let body = "";
      req.setEncoding("utf8");
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        delegated.push(JSON.parse(body || "{}") as Record<string, unknown>);
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ ok: true }));
      });
    });
    internalAudit = internal.server;

    process.env.PRISM_DASHBOARD_TOKEN = "dashboard-test-token";
    process.env.PRISM_INTERNAL_TOKEN = "internal-test-token";
    process.env.PRISM_INTERNAL_PORT = String(internal.port);
    process.env.PRISM_SECURITY_POLICY = policyPath;
    process.env.PRISM_AUDIT_LOG = auditPath;

    dashboard = createServer();
    await new Promise<void>((resolve, reject) => {
      dashboard!.once("error", reject);
      dashboard!.listen(0, "127.0.0.1", () => resolve());
    });
    const port = (dashboard.address() as { port: number }).port;
    const authHeader = { authorization: "Bearer dashboard-test-token", "content-type": "application/json" };

    const validate = await fetch(`http://127.0.0.1:${port}/api/config/validate`, {
      method: "POST",
      headers: authHeader,
      body: JSON.stringify({ config: { execBlockedPatterns: ["(bad"] } }),
    });
    expect(validate.status).toBe(200);
    expect((await validate.json() as { valid: boolean }).valid).toBe(false);

    const getConfig = await fetch(`http://127.0.0.1:${port}/api/config`, {
      headers: { authorization: "Bearer dashboard-test-token" },
    });
    const cfg = await getConfig.json() as { config: Record<string, unknown>; revision: string };
    expect(cfg.revision).toMatch(/^[0-9a-f]{16}$/);

    const putConfig = await fetch(`http://127.0.0.1:${port}/api/config`, {
      method: "PUT",
      headers: authHeader,
      body: JSON.stringify({
        revision: cfg.revision,
        config: { ...cfg.config, execAllowedPrefixes: ["node", "git"] },
      }),
    });
    expect(putConfig.status).toBe(200);
    const putBody = await putConfig.json() as { ok: boolean; revision: string };
    expect(putBody.ok).toBe(true);

    const entries = readAuditEntries({ auditLogPath: auditPath }).entries;
    const sourceCursor = entries.find((entry) => entry.record.event === "path_block")!.cursor;

    const preview = await fetch(`http://127.0.0.1:${port}/api/allow/preview`, {
      method: "POST",
      headers: authHeader,
      body: JSON.stringify({ sourceCursor }),
    });
    expect(preview.status).toBe(200);
    const previewBody = await preview.json() as {
      supported: boolean;
      impact?: { riskLevel: string; requiresConfirmation?: boolean };
    };
    expect(previewBody.supported).toBe(true);
    expect(previewBody.impact?.riskLevel).toBe("medium");
    expect(previewBody.impact?.requiresConfirmation).toBe(true);

    const getConfig2 = await fetch(`http://127.0.0.1:${port}/api/config`, {
      headers: { authorization: "Bearer dashboard-test-token" },
    });
    const cfg2 = await getConfig2.json() as { revision: string };
    const apply = await fetch(`http://127.0.0.1:${port}/api/allow/apply`, {
      method: "POST",
      headers: authHeader,
      body: JSON.stringify({
        sourceCursor,
        revision: cfg2.revision,
        confirmation: "ALLOW",
      }),
    });
    expect(apply.status).toBe(200);
    const applyBody = await apply.json() as { ok: boolean; revision: string };
    expect(applyBody.ok).toBe(true);
    expect(applyBody.revision).toMatch(/^[0-9a-f]{16}$/);

    const refreshedBlocks = await fetch(`http://127.0.0.1:${port}/api/blocks?limit=10`, {
      headers: { authorization: "Bearer dashboard-test-token" },
    });
    expect(refreshedBlocks.status).toBe(200);
    const refreshedBody = await refreshedBlocks.json() as {
      blocks: Array<{
        event: string;
        allowAction: { supported: boolean; alreadyApplied?: boolean };
      }>;
    };
    const pathBlock = refreshedBody.blocks.find((block) => block.event === "path_block");
    expect(pathBlock?.allowAction.supported).toBe(true);
    expect(pathBlock?.allowAction.alreadyApplied).toBe(true);

    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(delegated.some((event) => event.event === "dashboard_config_updated")).toBe(true);
    expect(delegated.some((event) => event.event === "dashboard_allow_applied")).toBe(true);
  });
});
