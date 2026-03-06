#!/usr/bin/env node
import http from "node:http";
import {
  evaluateInvokePolicy,
  extractExecCommand,
  getClientByToken,
  getDefaultPolicyPath,
  isDangerousExec,
  isSessionAllowed,
  loadPolicy,
  normalizeToolName,
  parseExecCommand,
} from "./policy.js";
import type { InvokeBody, Policy } from "./policy.js";

const POLICY_PATH = getDefaultPolicyPath();

function readBearer(req: http.IncomingMessage): string {
  const raw = (req.headers["authorization"] ?? "") as string;
  if (!raw.toLowerCase().startsWith("bearer ")) return "";
  return raw.slice(7).trim();
}

function json(res: http.ServerResponse, status: number, payload: unknown) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
}

async function scanResultText(
  scannerUrl: string,
  text: string,
  timeoutMs: number,
  scannerAuthToken?: string,
): Promise<{ verdict: string; reasons: string[] }> {
  if (!scannerAuthToken) {
    throw new Error("SCANNER_AUTH_TOKEN is required");
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(scannerUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${scannerAuthToken}`,
      },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`scanner status=${resp.status}`);
    const payload = (await resp.json()) as { verdict?: string; reasons?: string[] };
    return {
      verdict: payload.verdict ?? "benign",
      reasons: Array.isArray(payload.reasons) ? payload.reasons.map(String) : [],
    };
  } finally {
    clearTimeout(timeout);
  }
}

function extractTextFromInvokeResult(result: unknown): string {
  try {
    if (typeof result === "string") return result;
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

// ── Server factory ──
export function createServer(policyOverride?: Policy) {
  let policy = policyOverride ?? loadPolicy(POLICY_PATH);

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (req.method !== "POST" || req.url !== "/tools/invoke") {
      return json(res, 404, { ok: false, error: "not found" });
    }

    const callerToken = readBearer(req);

    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 2 * 1024 * 1024) {
        req.destroy(new Error("payload too large"));
      }
    });

    req.on("end", async () => {
      let body: InvokeBody;
      try {
        body = (raw ? JSON.parse(raw) : {}) as InvokeBody;
      } catch (err) {
        return json(res, 400, { ok: false, error: `invalid json: ${String(err)}` });
      }

      const decision = evaluateInvokePolicy(policy, callerToken, body);
      if (!decision.allow || !decision.sanitizedBody) {
        return json(res, decision.status, { ok: false, error: decision.message });
      }

      const sanitizedBody = decision.sanitizedBody;
      const tool = sanitizedBody.tool;

      const upstreamToken = process.env[policy.upstreamTokenEnv] ?? "";
      if (!upstreamToken) {
        return json(res, 500, { ok: false, error: `missing env ${policy.upstreamTokenEnv}` });
      }

      let upstreamResp: Response;
      try {
        upstreamResp = await fetch(`${policy.upstreamUrl}/tools/invoke`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${upstreamToken}`,
            "x-openclaw-message-channel": "api",
          },
          body: JSON.stringify(sanitizedBody),
          signal: AbortSignal.timeout(policy.upstreamTimeoutMs ?? 30_000),
        });
      } catch (err) {
        const msg = err instanceof Error && err.name === "TimeoutError"
          ? "upstream timeout" : `upstream unavailable: ${String(err)}`;
        return json(res, 502, { ok: false, error: msg });
      }

      let payload: unknown;
      try {
        payload = await upstreamResp.json();
      } catch {
        payload = { ok: false, error: { message: "invalid upstream payload" } };
      }

      // Bypass result scan for web_fetch/browser
      if (tool === "web_fetch" || tool === "browser") {
        try {
          const text = extractTextFromInvokeResult(payload).slice(0, 30_000);
          if (policy.scannerUrl) {
            const verdict = await scanResultText(
              policy.scannerUrl,
              text,
              policy.scannerTimeoutMs ?? 1200,
              process.env.SCANNER_AUTH_TOKEN ?? "",
            );
            if (verdict.verdict === "malicious") {
              return json(res, 409, {
                ok: false,
                error: {
                  type: "security_block",
                  message: "tool result blocked by injection scanner",
                  reasons: verdict.reasons,
                },
              });
            }
          }
        } catch (err) {
          if (policy.blockOnScannerFailure) {
            return json(res, 503, { ok: false, error: `scanner unavailable: ${String(err)}` });
          }
        }
      }

      return json(res, upstreamResp.status, payload);
    });
  });

  // SIGHUP policy reload
  const reloadPolicy = () => {
    try {
      policy = loadPolicy(POLICY_PATH);
      process.stdout.write("[invoke-guard] policy reloaded\n");
    } catch (err) {
      process.stderr.write(`[invoke-guard] policy reload failed: ${String(err)}\n`);
    }
  };

  return { server, reloadPolicy };
}

// Start server when run directly
const isMainModule =
  process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ""));
if (isMainModule || process.env.PRISM_PROXY_START) {
  const policy = loadPolicy(POLICY_PATH);
  const { server, reloadPolicy } = createServer(policy);
  server.listen(policy.port, policy.host, () => {
    process.stdout.write(`[invoke-guard] listening on http://${policy.host}:${policy.port}\n`);
  });
  process.on("SIGHUP", reloadPolicy);
}

// Export internals for testing
export {
  normalizeToolName,
  readBearer,
  getClientByToken,
  isSessionAllowed,
  extractExecCommand,
  parseExecCommand,
  isDangerousExec,
  evaluateInvokePolicy,
  extractTextFromInvokeResult,
};
export type { ClientPolicy, Policy, InvokeBody, InvokePolicyDecision } from "./policy.js";
