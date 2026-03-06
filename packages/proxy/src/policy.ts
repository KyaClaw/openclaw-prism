import fs from "node:fs";
import { createHash, timingSafeEqual } from "node:crypto";

export type ClientPolicy = {
  id: string;
  token: string;
  allowedSessionPrefixes: string[];
  allowTools: string[];
  denyTools?: string[];
};

export type Policy = {
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

export type InvokeBody = {
  tool?: unknown;
  args?: unknown;
  action?: unknown;
  sessionKey?: unknown;
  dryRun?: unknown;
};

export type SanitizedInvokeBody = {
  tool: string;
  args: unknown;
  sessionKey: string;
  dryRun?: unknown;
};

export type InvokePolicyDecision = {
  allow: boolean;
  status: number;
  reasonCode: string;
  message: string;
  matchedRulePath: string;
  clientId: string | null;
  tool: string;
  sessionKey: string;
  sanitizedBody: SanitizedInvokeBody | null;
};

function defaultPolicyPath(): string {
  return process.env.INVOKE_GUARD_POLICY ?? "./config/invoke-guard.policy.json";
}

export function getDefaultPolicyPath(): string {
  return defaultPolicyPath();
}

export function loadPolicy(path?: string): Policy {
  const raw = fs.readFileSync(path ?? defaultPolicyPath(), "utf8");
  return JSON.parse(raw) as Policy;
}

export function normalizeToolName(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function digestToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function constantTimeTokenEqual(left: string, right: string): boolean {
  const leftDigest = digestToken(left);
  const rightDigest = digestToken(right);
  return timingSafeEqual(leftDigest, rightDigest);
}

type ClientMatch = { client: ClientPolicy; index: number };

function findClientByToken(clients: ClientPolicy[], token: string): ClientMatch | null {
  let matched: ClientMatch | null = null;
  for (let i = 0; i < clients.length; i++) {
    const candidate = clients[i]!;
    if (constantTimeTokenEqual(candidate.token, token) && !matched) {
      matched = { client: candidate, index: i };
    }
  }
  return matched;
}

export function getClientByToken(clients: ClientPolicy[], token: string): ClientPolicy | null {
  return findClientByToken(clients, token)?.client ?? null;
}

export function isSessionAllowed(sessionKey: string, prefixes: string[]): boolean {
  return prefixes.some((p) => sessionKey.startsWith(p));
}

function findSessionPrefixIndex(sessionKey: string, prefixes: string[]): number {
  for (let i = 0; i < prefixes.length; i++) {
    if (sessionKey.startsWith(prefixes[i]!)) return i;
  }
  return -1;
}

function findToolIndex(tools: string[], tool: string): number {
  const normalized = tool.toLowerCase();
  for (let i = 0; i < tools.length; i++) {
    if (tools[i]!.trim().toLowerCase() === normalized) return i;
  }
  return -1;
}

export function extractExecCommand(args: unknown): string {
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
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "fish",
  "cmd",
  "powershell",
  "pwsh",
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

export function parseExecCommand(command: string): ParsedExecCommand | null {
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

export function isDangerousExec(command: string): string | null {
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

function decisionBase(
  body: InvokeBody,
  caller: ClientPolicy | null,
  message: string,
  allow: boolean,
  status: number,
  reasonCode: string,
  matchedRulePath: string,
  sanitizedBody: SanitizedInvokeBody | null,
): InvokePolicyDecision {
  const tool = normalizeToolName(body.tool);
  const sessionKey = typeof body.sessionKey === "string" ? body.sessionKey.trim() : "";
  return {
    allow,
    status,
    reasonCode,
    message,
    matchedRulePath,
    clientId: caller?.id ?? null,
    tool,
    sessionKey,
    sanitizedBody,
  };
}

export function evaluateInvokePolicy(
  policy: Policy,
  callerToken: string,
  body: InvokeBody,
): InvokePolicyDecision {
  const callerMatch = findClientByToken(policy.clients, callerToken);
  if (!callerMatch) {
    return decisionBase(
      body,
      null,
      "unauthorized caller",
      false,
      401,
      "unauthorized-caller",
      "clients[*].token",
      null,
    );
  }

  const caller = callerMatch.client;
  const clientPath = `clients[${callerMatch.index}]`;
  const tool = normalizeToolName(body.tool);
  if (!tool) {
    return decisionBase(
      body,
      caller,
      "tool is required",
      false,
      400,
      "missing-tool",
      "request.tool",
      null,
    );
  }

  const sessionKey = typeof body.sessionKey === "string" ? body.sessionKey.trim() : "";
  if (!sessionKey) {
    return decisionBase(
      body,
      caller,
      "sessionKey is required",
      false,
      400,
      "missing-session-key",
      "request.sessionKey",
      null,
    );
  }

  const prefixIndex = findSessionPrefixIndex(sessionKey, caller.allowedSessionPrefixes);
  if (prefixIndex < 0) {
    return decisionBase(
      body,
      caller,
      "session ownership check failed",
      false,
      403,
      "session-prefix-mismatch",
      `${clientPath}.allowedSessionPrefixes`,
      null,
    );
  }

  const allowIndex = findToolIndex(caller.allowTools, tool);
  if (allowIndex < 0) {
    return decisionBase(
      body,
      caller,
      `tool denied by policy: ${tool}`,
      false,
      403,
      "tool-not-allowed",
      `${clientPath}.allowTools`,
      null,
    );
  }

  const defaultDenyIndex = findToolIndex(policy.defaultDenyTools, tool);
  if (defaultDenyIndex >= 0) {
    return decisionBase(
      body,
      caller,
      `tool denied by policy: ${tool}`,
      false,
      403,
      "tool-default-deny",
      `defaultDenyTools[${defaultDenyIndex}]`,
      null,
    );
  }

  const denyIndex = findToolIndex(caller.denyTools ?? [], tool);
  if (denyIndex >= 0) {
    return decisionBase(
      body,
      caller,
      `tool denied by policy: ${tool}`,
      false,
      403,
      "tool-client-deny",
      `${clientPath}.denyTools[${denyIndex}]`,
      null,
    );
  }

  if (tool === "exec" || tool === "bash") {
    const cmd = extractExecCommand(body.args);
    const dangerous = isDangerousExec(cmd);
    if (dangerous) {
      return decisionBase(
        body,
        caller,
        `dangerous exec blocked: ${dangerous}`,
        false,
        403,
        "dangerous-exec",
        `builtin.execDanger.${dangerous}`,
        null,
      );
    }
  }

  const sanitizedBody: SanitizedInvokeBody = {
    tool,
    args: body.args,
    sessionKey,
    ...(body.dryRun !== undefined ? { dryRun: body.dryRun } : {}),
  };
  return decisionBase(
    body,
    caller,
    "allowed",
    true,
    200,
    "allow",
    `${clientPath}.allowTools[${allowIndex}]`,
    sanitizedBody,
  );
}
