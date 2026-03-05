#!/usr/bin/env node
import fs from "node:fs";
import http from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";

// ── Policy types ──
type ClientPolicy = {
  id: string;
  token: string;
  allowedSessionPrefixes: string[];
  allowTools: string[];
  denyTools?: string[];
};

type Policy = {
  host: string;
  port: number;
  upstreamUrl: string;
  upstreamTokenEnv: string;
  upstreamTimeoutMs?: number;
  defaultDenyTools: string[];
  scannerUrl?: string;
  scannerTimeoutMs?: number;
  blockOnScannerFailure?: boolean;
  clients: ClientPolicy[];
};

type InvokeBody = {
  tool?: unknown;
  args?: unknown;
  action?: unknown;
  sessionKey?: unknown;
  dryRun?: unknown;
};

// ── Policy loading ──
const POLICY_PATH = process.env.INVOKE_GUARD_POLICY ?? "./config/invoke-guard.policy.json";

export function loadPolicy(path?: string): Policy {
  const raw = fs.readFileSync(path ?? POLICY_PATH, "utf8");
  return JSON.parse(raw) as Policy;
}

// ── Utility functions ──
function normalizeToolName(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function readBearer(req: http.IncomingMessage): string {
  const raw = (req.headers["authorization"] ?? "") as string;
  if (!raw.toLowerCase().startsWith("bearer ")) return "";
  return raw.slice(7).trim();
}

function digestToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function constantTimeTokenEqual(left: string, right: string): boolean {
  const leftDigest = digestToken(left);
  const rightDigest = digestToken(right);
  return timingSafeEqual(leftDigest, rightDigest);
}

function getClientByToken(clients: ClientPolicy[], token: string): ClientPolicy | null {
  let matched: ClientPolicy | null = null;
  for (const c of clients) {
    if (constantTimeTokenEqual(c.token, token) && !matched) {
      matched = c;
    }
  }
  return matched;
}

function isSessionAllowed(sessionKey: string, prefixes: string[]): boolean {
  return prefixes.some((p) => sessionKey.startsWith(p));
}

function extractExecCommand(args: unknown): string {
  if (!args || typeof args !== "object") return "";
  const record = args as Record<string, unknown>;
  for (const key of ["command", "cmd", "script"]) {
    const v = record[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

type ParsedExecCommand = {
  executable: string;
  argv: string[];
  assignments: string[];
};

const SHELL_TRAMPOLINES = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh",
]);
const INLINE_INTERPRETER_FLAGS = new Map<string, Set<string>>([
  ["node", new Set(["-e", "--eval", "-p", "--print"])],
  ["python", new Set(["-c"])],
  ["python3", new Set(["-c"])],
  ["perl", new Set(["-e"])],
  ["ruby", new Set(["-e"])],
  ["php", new Set(["-r"])],
  ["lua", new Set(["-e"])],
]);

function tokenizeCommand(command: string): string[] | null {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | "\"" | null = null;
  let escaping = false;

  for (const ch of command) {
    if (escaping) {
      current += ch;
      escaping = false;
      continue;
    }

    if (quote === "'") {
      if (ch === "'") quote = null;
      else current += ch;
      continue;
    }

    if (quote === "\"") {
      if (ch === "\"") {
        quote = null;
      } else if (ch === "\\") {
        escaping = true;
      } else {
        current += ch;
      }
      continue;
    }

    if (ch === "'" || ch === "\"") {
      quote = ch;
      continue;
    }
    if (ch === "\\") {
      escaping = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }

  if (escaping) current += "\\";
  if (quote) return null;
  if (current) tokens.push(current);
  return tokens;
}

function isEnvAssignment(token: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=.*/.test(token);
}

function parseExecCommand(command: string): ParsedExecCommand | null {
  const tokens = tokenizeCommand(command);
  if (!tokens?.length) return null;

  let idx = 0;
  const assignments: string[] = [];

  while (idx < tokens.length && isEnvAssignment(tokens[idx]!)) {
    assignments.push(tokens[idx]!);
    idx++;
  }

  const maybeEnv = tokens[idx];
  if (maybeEnv && maybeEnv.replace(/^.*[\\/]/, "").toLowerCase() === "env") {
    idx++;
    while (idx < tokens.length) {
      const token = tokens[idx]!;
      if (token === "--") {
        idx++;
        break;
      }
      if (token.startsWith("-")) {
        idx++;
        continue;
      }
      if (isEnvAssignment(token)) {
        assignments.push(token);
        idx++;
        continue;
      }
      break;
    }
  }

  while (idx < tokens.length && isEnvAssignment(tokens[idx]!)) {
    assignments.push(tokens[idx]!);
    idx++;
  }

  if (idx >= tokens.length) return { executable: "", argv: [], assignments };

  return {
    executable: tokens[idx]!.replace(/^.*[\\/]/, "").toLowerCase(),
    argv: tokens.slice(idx + 1),
    assignments,
  };
}

function hasGitSshOverride(parsed: ParsedExecCommand): boolean {
  if (parsed.assignments.some((entry) => entry.split("=")[0]?.toLowerCase() === "git_ssh_command")) {
    return true;
  }
  if (parsed.executable !== "git") return false;

  for (let i = 0; i < parsed.argv.length; i++) {
    const arg = parsed.argv[i]!;
    const lower = arg.toLowerCase();
    if (arg === "-c") {
      const next = parsed.argv[i + 1]?.toLowerCase() ?? "";
      if (next.startsWith("core.sshcommand=")) return true;
      continue;
    }
    if (lower.startsWith("-ccore.sshcommand=") || lower.startsWith("--config-env=core.sshcommand")) {
      return true;
    }
  }

  return false;
}

function isDangerousExec(command: string): string | null {
  if (/[;&|`$()<>]/.test(command)) return "shell-metacharacter";

  const parsed = parseExecCommand(command);
  if (!parsed || !parsed.executable) return "unparseable-command";
  if (SHELL_TRAMPOLINES.has(parsed.executable)) return "shell-trampoline";

  const inlineFlags = INLINE_INTERPRETER_FLAGS.get(parsed.executable);
  if (inlineFlags && parsed.argv.some((arg) => inlineFlags.has(arg.toLowerCase()))) {
    return "interpreter-inline-code";
  }
  if (hasGitSshOverride(parsed)) return "git-ssh-override";

  const patterns: Array<{ reason: string; re: RegExp }> = [
    { reason: "rm-root", re: /rm\s+-rf\s+\/(\s|$)/i },
    { reason: "curl-pipe-shell", re: /curl\s+[^|]*\|\s*(sh|bash|zsh)/i },
    { reason: "wget-pipe-shell", re: /wget\s+[^|]*\|\s*(sh|bash|zsh)/i },
    { reason: "netcat-exec", re: /nc\s+.*\s+-e\s+/i },
  ];
  for (const p of patterns) {
    if (p.re.test(command)) return p.reason;
  }
  return null;
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
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(scannerUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(scannerAuthToken ? { authorization: `Bearer ${scannerAuthToken}` } : {}),
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
  let policy = policyOverride!;

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      return json(res, 200, { ok: true });
    }

    if (req.method !== "POST" || req.url !== "/tools/invoke") {
      return json(res, 404, { ok: false, error: "not found" });
    }

    const callerToken = readBearer(req);
    const caller = getClientByToken(policy.clients, callerToken);
    if (!caller) {
      return json(res, 401, { ok: false, error: "unauthorized caller" });
    }

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

      const tool = normalizeToolName(body.tool);
      if (!tool) {
        return json(res, 400, { ok: false, error: "tool is required" });
      }

      const sessionKey = typeof body.sessionKey === "string" ? body.sessionKey.trim() : "";
      if (!sessionKey) {
        return json(res, 400, { ok: false, error: "sessionKey is required" });
      }
      if (!isSessionAllowed(sessionKey, caller.allowedSessionPrefixes)) {
        return json(res, 403, { ok: false, error: "session ownership check failed" });
      }

      const defaultDeny = new Set(policy.defaultDenyTools.map((x) => x.toLowerCase()));
      const callerAllow = new Set(caller.allowTools.map((x) => x.toLowerCase()));
      const callerDeny = new Set((caller.denyTools ?? []).map((x) => x.toLowerCase()));

      if (!callerAllow.has(tool) || defaultDeny.has(tool) || callerDeny.has(tool)) {
        return json(res, 403, { ok: false, error: `tool denied by policy: ${tool}` });
      }

      if (tool === "exec" || tool === "bash") {
        const cmd = extractExecCommand(body.args);
        const dangerous = isDangerousExec(cmd);
        if (dangerous) {
          return json(res, 403, { ok: false, error: `dangerous exec blocked: ${dangerous}` });
        }
      }

      const upstreamToken = process.env[policy.upstreamTokenEnv] ?? "";
      if (!upstreamToken) {
        return json(res, 500, { ok: false, error: `missing env ${policy.upstreamTokenEnv}` });
      }

      // v4 fix: sanitized body — only forward verified fields
      const sanitizedBody = {
        tool,
        args: body.args,
        sessionKey,
        ...(body.dryRun !== undefined ? { dryRun: body.dryRun } : {}),
      };

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
      policy = loadPolicy();
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
  const policy = loadPolicy();
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
  extractTextFromInvokeResult,
};
export type { ClientPolicy, Policy, InvokeBody };
