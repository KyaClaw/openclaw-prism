import { isAbsolute } from "node:path";
import { canonicalizePath } from "@kyaclaw/shared/paths";
import type { SecurityConfig } from "@kyaclaw/shared/types";
import { findEntryByCursor, parseCursor } from "./audit-reader.js";
import {
  readConfigStore,
  updateConfigStore,
  RevisionConflictError,
  ConfigValidationError,
  type StoredConfig,
} from "./config-store.js";

export type RiskLevel = "low" | "medium" | "high";

export type AllowActionType =
  | "add_exec_prefix"
  | "add_path_exception"
  | "remove_blocked_pattern"
  | "remove_secret_pattern";

export type AllowAction = {
  type: AllowActionType;
  field: keyof SecurityConfig;
  value: string;
  description: string;
};

export type AllowActionDescriptor = {
  supported: boolean;
  type?: AllowActionType;
  value?: string;
  description?: string;
  field?: keyof SecurityConfig;
  riskLevel?: RiskLevel;
  requiresConfirmation?: boolean;
  alreadyApplied?: boolean;
  reason?: string;
};

export type AllowPreview = {
  supported: boolean;
  sourceEvent: Record<string, unknown>;
  action?: AllowAction;
  impact?: {
    description: string;
    riskLevel: RiskLevel;
    requiresConfirmation?: boolean;
    confirmationWord?: "ALLOW";
  };
  currentRevision: string;
  reason?: string;
  legacyRecord?: boolean;
};

export const ACTION_RISK_MAP: Record<AllowActionType, RiskLevel> = {
  add_exec_prefix: "low",
  add_path_exception: "medium",
  remove_blocked_pattern: "medium",
  remove_secret_pattern: "medium",
};

const SOURCE_CURSOR_PATTERN = /^[0-9a-f]{32}:[0-9]+$/;
const MAX_SOURCE_OFFSET = 10_000_000;

export class SourceCursorValidationError extends Error {
  constructor(message = "invalid sourceCursor") {
    super(message);
    this.name = "SourceCursorValidationError";
  }
}

export class SourceCursorNotFoundError extends Error {
  constructor(cursor: string) {
    super(`sourceCursor not found: ${cursor}`);
    this.name = "SourceCursorNotFoundError";
  }
}

export class AllowActionUnsupportedError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = "AllowActionUnsupportedError";
    this.reason = reason;
  }
}

export class ConfirmationRequiredError extends Error {
  constructor() {
    super("confirmation word ALLOW is required");
    this.name = "ConfirmationRequiredError";
  }
}

export class AllowActionMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AllowActionMismatchError";
  }
}

function safeString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function normalizeActionValue(v: string): string {
  return v.trim();
}

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
      if (ch === "\"") quote = null;
      else if (ch === "\\") escaping = true;
      else current += ch;
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

function firstExecutable(command: string): string {
  const tokens = tokenizeCommand(command);
  if (!tokens?.length) return "";

  let idx = 0;
  while (idx < tokens.length && isEnvAssignment(tokens[idx]!)) idx++;
  if (idx >= tokens.length) return "";

  if (tokens[idx]!.replace(/^.*[\\/]/, "").toLowerCase() === "env") {
    idx++;
    while (idx < tokens.length) {
      const token = tokens[idx]!;
      if (token === "--") {
        idx++;
        break;
      }
      if (token.startsWith("-") || isEnvAssignment(token)) {
        idx++;
        continue;
      }
      break;
    }
  }
  while (idx < tokens.length && isEnvAssignment(tokens[idx]!)) idx++;
  if (idx >= tokens.length) return "";
  return tokens[idx]!.replace(/^.*[\\/]/, "").toLowerCase();
}

type ReconstructedAction = {
  supported: true;
  action: AllowAction;
  sourceEvent: Record<string, unknown>;
  legacyRecord?: boolean;
} | {
  supported: false;
  reason: string;
  sourceEvent: Record<string, unknown>;
  legacyRecord?: boolean;
};

function reconstructAllowAction(record: Record<string, unknown>): ReconstructedAction {
  const sourceEvent = { ...record };
  const event = safeString(record.event);

  if (event === "exec_whitelist_block") {
    const command = safeString(record.command);
    const executable = firstExecutable(command);
    if (!executable) {
      return { supported: false, reason: "unable to extract executable from command", sourceEvent };
    }
    return {
      supported: true,
      sourceEvent,
      action: {
        type: "add_exec_prefix",
        field: "execAllowedPrefixes",
        value: executable,
        description: `Add '${executable}' to exec allowed prefixes`,
      },
    };
  }

  if (event === "path_block") {
    const rawPath = safeString(record.rawPath) || safeString(record.path);
    const originalCwd = safeString(record.cwd);
    const cwd = originalCwd && isAbsolute(originalCwd) ? originalCwd : "/";
    const legacyRecord =
      record.legacyRecord === true || safeString(record.rawPath) === "" || originalCwd === "";

    if (!rawPath) {
      return { supported: false, reason: "path_block record missing path", sourceEvent, legacyRecord };
    }
    if (legacyRecord && !isAbsolute(rawPath)) {
      return {
        supported: false,
        reason: "legacy relative path cannot be safely resolved without original cwd",
        sourceEvent,
        legacyRecord: true,
      };
    }

    const canonicalPath = canonicalizePath(rawPath, cwd);
    const nextSource = {
      ...sourceEvent,
      rawPath,
      cwd,
      canonicalPath,
      ...(legacyRecord ? { legacyRecord: true } : {}),
    };

    return {
      supported: true,
      sourceEvent: nextSource,
      legacyRecord,
      action: {
        type: "add_path_exception",
        field: "protectedPathExceptions",
        value: canonicalPath,
        description: `Add '${canonicalPath}' as exception to path protection`,
      },
    };
  }

  if (event === "exec_pattern_block") {
    const pattern = safeString(record.pattern);
    if (!pattern) {
      return { supported: false, reason: "exec_pattern_block record missing pattern", sourceEvent };
    }
    return {
      supported: true,
      sourceEvent,
      action: {
        type: "remove_blocked_pattern",
        field: "execBlockedPatterns",
        value: pattern,
        description: `Remove blocked exec pattern '${pattern}'`,
      },
    };
  }

  if (event === "outbound_secret_blocked") {
    const pattern = safeString(record.pattern);
    if (!pattern) {
      return { supported: false, reason: "outbound_secret_blocked record missing pattern", sourceEvent };
    }
    return {
      supported: true,
      sourceEvent,
      action: {
        type: "remove_secret_pattern",
        field: "outboundSecretPatterns",
        value: pattern,
        description: `Remove outbound secret pattern '${pattern}'`,
      },
    };
  }

  return { supported: false, reason: `event '${event}' is not allow-action supported`, sourceEvent };
}

function riskDescription(action: AllowAction, riskLevel: RiskLevel): string {
  switch (action.type) {
    case "add_exec_prefix":
      return `All commands starting with '${action.value}' will be allowed for exec`;
    case "add_path_exception":
      return `Only '${action.value}' will be exempted; other protected paths remain enforced`;
    case "remove_blocked_pattern":
      return `Dangerous command pattern '${action.value}' will no longer be blocked`;
    case "remove_secret_pattern":
      return `Secret leak pattern '${action.value}' will no longer be blocked`;
    default:
      return `Risk level ${riskLevel}`;
  }
}

export function describeAllowAction(
  record: Record<string, unknown>,
  config?: SecurityConfig,
): AllowActionDescriptor {
  const reconstructed = reconstructAllowAction(record);
  if (!reconstructed.supported) {
    return { supported: false, reason: reconstructed.reason };
  }

  const riskLevel = ACTION_RISK_MAP[reconstructed.action.type];
  const alreadyApplied = config ? isActionAlreadyApplied(config, reconstructed.action) : false;
  return {
    supported: true,
    type: reconstructed.action.type,
    field: reconstructed.action.field,
    value: reconstructed.action.value,
    description: reconstructed.action.description,
    riskLevel,
    requiresConfirmation: riskLevel !== "low",
    alreadyApplied,
  };
}

function ensureSourceCursor(sourceCursor: string): void {
  if (!SOURCE_CURSOR_PATTERN.test(sourceCursor)) {
    throw new SourceCursorValidationError("sourceCursor must match ^[0-9a-f]{32}:[0-9]+$");
  }
  const parsed = parseCursor(sourceCursor);
  if (!parsed || parsed.lineOffset > MAX_SOURCE_OFFSET) {
    throw new SourceCursorValidationError("sourceCursor lineOffset exceeds allowed maximum");
  }
}

function ensureStringArray(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input.filter((item): item is string => typeof item === "string");
}

function applyActionToConfig(config: SecurityConfig, action: AllowAction): SecurityConfig {
  const next: SecurityConfig = { ...config };

  if (action.type === "add_exec_prefix") {
    const existing = ensureStringArray(next.execAllowedPrefixes);
    const normalized = normalizeActionValue(action.value).toLowerCase();
    if (!existing.some((v) => v.toLowerCase() === normalized)) existing.push(normalized);
    next.execAllowedPrefixes = existing;
    return next;
  }

  if (action.type === "add_path_exception") {
    const existing = ensureStringArray(next.protectedPathExceptions);
    const normalized = normalizeActionValue(action.value);
    if (!existing.includes(normalized)) existing.push(normalized);
    next.protectedPathExceptions = existing;
    return next;
  }

  if (action.type === "remove_blocked_pattern") {
    next.execBlockedPatterns = ensureStringArray(next.execBlockedPatterns).filter((v) => v !== action.value);
    return next;
  }

  next.outboundSecretPatterns = ensureStringArray(next.outboundSecretPatterns).filter((v) => v !== action.value);
  return next;
}

function isActionAlreadyApplied(config: SecurityConfig, action: AllowAction): boolean {
  if (action.type === "add_exec_prefix") {
    const normalized = normalizeActionValue(action.value).toLowerCase();
    return ensureStringArray(config.execAllowedPrefixes).some((v) => v.toLowerCase() === normalized);
  }

  if (action.type === "add_path_exception") {
    const normalized = normalizeActionValue(action.value);
    return ensureStringArray(config.protectedPathExceptions).includes(normalized);
  }

  if (action.type === "remove_blocked_pattern") {
    return !ensureStringArray(config.execBlockedPatterns).includes(action.value);
  }

  return !ensureStringArray(config.outboundSecretPatterns).includes(action.value);
}

function assertActionMatches(expected: AllowAction, candidate?: Partial<AllowAction>): void {
  if (!candidate) return;
  const mismatch =
    candidate.type !== expected.type ||
    candidate.field !== expected.field ||
    normalizeActionValue(String(candidate.value ?? "")) !== normalizeActionValue(expected.value);
  if (mismatch) {
    throw new AllowActionMismatchError("request action does not match source event derived action");
  }
}

function ensureConfirmation(actionType: AllowActionType, confirmation?: string): void {
  const riskLevel = ACTION_RISK_MAP[actionType];
  if (riskLevel === "low") return;
  if (confirmation !== "ALLOW") throw new ConfirmationRequiredError();
}

export function previewAllowAction(input: {
  sourceCursor: string;
  auditLogPath?: string;
  policyPath?: string;
}): AllowPreview {
  ensureSourceCursor(input.sourceCursor);
  const entry = findEntryByCursor(input.sourceCursor, { auditLogPath: input.auditLogPath });
  if (!entry) throw new SourceCursorNotFoundError(input.sourceCursor);

  const reconstructed = reconstructAllowAction(entry.record);
  const currentConfig = readConfigStore(input.policyPath);

  if (!reconstructed.supported) {
    return {
      supported: false,
      reason: reconstructed.reason,
      sourceEvent: reconstructed.sourceEvent,
      currentRevision: currentConfig.revision,
      ...(reconstructed.legacyRecord ? { legacyRecord: true } : {}),
    };
  }

  const riskLevel = ACTION_RISK_MAP[reconstructed.action.type];
  return {
    supported: true,
    sourceEvent: reconstructed.sourceEvent,
    action: reconstructed.action,
    impact: {
      description: riskDescription(reconstructed.action, riskLevel),
      riskLevel,
      ...(riskLevel === "low"
        ? {}
        : {
            requiresConfirmation: true,
            confirmationWord: "ALLOW" as const,
          }),
    },
    currentRevision: currentConfig.revision,
    ...(reconstructed.legacyRecord ? { legacyRecord: true } : {}),
  };
}

export function applyAllowAction(input: {
  sourceCursor: string;
  revision: string;
  confirmation?: string;
  action?: Partial<AllowAction>;
  auditLogPath?: string;
  policyPath?: string;
}): StoredConfig & { action: AllowAction; sourceCursor: string; summary: string } {
  ensureSourceCursor(input.sourceCursor);
  const entry = findEntryByCursor(input.sourceCursor, { auditLogPath: input.auditLogPath });
  if (!entry) throw new SourceCursorNotFoundError(input.sourceCursor);

  const reconstructed = reconstructAllowAction(entry.record);
  if (!reconstructed.supported) {
    throw new AllowActionUnsupportedError(reconstructed.reason);
  }
  assertActionMatches(reconstructed.action, input.action);
  ensureConfirmation(reconstructed.action.type, input.confirmation);

  const current = readConfigStore(input.policyPath);
  if (current.revision !== input.revision) {
    throw new RevisionConflictError(current.revision);
  }

  const nextConfig = applyActionToConfig(current.config, reconstructed.action);
  const updated = updateConfigStore({
    config: nextConfig,
    expectedRevision: current.revision,
    customPath: current.path,
  });

  return {
    ...updated,
    action: reconstructed.action,
    sourceCursor: input.sourceCursor,
    summary: reconstructed.action.description,
  };
}

export type DashboardApplyError =
  | SourceCursorValidationError
  | SourceCursorNotFoundError
  | AllowActionUnsupportedError
  | ConfirmationRequiredError
  | AllowActionMismatchError
  | RevisionConflictError
  | ConfigValidationError;
