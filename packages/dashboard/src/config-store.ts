import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import type { SecurityConfig } from "@kyaclaw/shared/types";

export const DEFAULT_POLICY_PATH = join(homedir(), ".openclaw", "security", "security.policy.json");

const KNOWN_KEYS = new Set([
  "riskTtlMs",
  "persistRiskState",
  "riskStateFile",
  "maxScanChars",
  "scanTools",
  "protectedPathPatterns",
  "protectedPathExceptions",
  "execAllowedPrefixes",
  "execBlockedPatterns",
  "scannerUrl",
  "scannerTimeoutMs",
  "blockOnScannerFailure",
  "outboundSecretPatterns",
  "blockedDomains",
  "riskyDomains",
]);

const ARRAY_FIELDS = [
  "scanTools",
  "protectedPathPatterns",
  "protectedPathExceptions",
  "execAllowedPrefixes",
  "execBlockedPatterns",
  "outboundSecretPatterns",
  "blockedDomains",
  "riskyDomains",
] as const;

export type ValidationIssue = { field: string; message: string };
export type ValidationResult = {
  valid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
};

export type StoredConfig = {
  config: SecurityConfig;
  revision: string;
  path: string;
  lastModified: string;
};

export class RevisionConflictError extends Error {
  readonly currentRevision: string;

  constructor(currentRevision: string) {
    super("revision mismatch");
    this.name = "RevisionConflictError";
    this.currentRevision = currentRevision;
  }
}

export class ConfigValidationError extends Error {
  readonly issues: ValidationIssue[];

  constructor(issues: ValidationIssue[]) {
    super("config validation failed");
    this.name = "ConfigValidationError";
    this.issues = issues;
  }
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(",")}}`;
}

function ensureObject(value: unknown): SecurityConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as SecurityConfig;
}

export function resolvePolicyPath(customPath?: string): string {
  const fromEnv = customPath ?? process.env.PRISM_SECURITY_POLICY;
  const raw = fromEnv?.trim();
  if (!raw) return DEFAULT_POLICY_PATH;
  return isAbsolute(raw) ? resolve(raw) : resolve(process.cwd(), raw);
}

export function computeRevision(config: SecurityConfig): string {
  return createHash("sha256").update(stableStringify(config), "utf8").digest("hex").slice(0, 16);
}

export function readConfigStore(customPath?: string): StoredConfig {
  const policyPath = resolvePolicyPath(customPath);
  const config = existsSync(policyPath)
    ? ensureObject(JSON.parse(readFileSync(policyPath, "utf8")))
    : {};
  const lastModified = existsSync(policyPath)
    ? new Date(statSync(policyPath).mtimeMs).toISOString()
    : new Date(0).toISOString();

  return {
    config,
    revision: computeRevision(config),
    path: policyPath,
    lastModified,
  };
}

function pushError(errors: ValidationIssue[], field: string, message: string): void {
  errors.push({ field, message });
}

function validateStringArray(
  errors: ValidationIssue[],
  field: string,
  value: unknown,
): value is string[] {
  if (value === undefined) return false;
  if (!Array.isArray(value)) {
    pushError(errors, field, "must be an array");
    return false;
  }
  let valid = true;
  value.forEach((item, idx) => {
    if (typeof item !== "string") {
      pushError(errors, `${field}[${idx}]`, "must be a string");
      valid = false;
    }
  });
  return valid;
}

export function validateSecurityConfig(config: SecurityConfig): ValidationResult {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];
  const input = ensureObject(config);

  if (input.riskTtlMs !== undefined) {
    if (!Number.isInteger(input.riskTtlMs) || input.riskTtlMs <= 0) {
      pushError(errors, "riskTtlMs", "must be a positive integer");
    }
  }
  if (input.maxScanChars !== undefined) {
    if (!Number.isInteger(input.maxScanChars) || input.maxScanChars <= 0) {
      pushError(errors, "maxScanChars", "must be a positive integer");
    }
  }
  if (input.scannerTimeoutMs !== undefined) {
    if (!Number.isInteger(input.scannerTimeoutMs) || input.scannerTimeoutMs <= 0) {
      pushError(errors, "scannerTimeoutMs", "must be a positive integer");
    }
  }
  if (input.scannerUrl !== undefined && typeof input.scannerUrl !== "string") {
    pushError(errors, "scannerUrl", "must be a string");
  }
  if (input.persistRiskState !== undefined && typeof input.persistRiskState !== "boolean") {
    pushError(errors, "persistRiskState", "must be a boolean");
  }
  if (input.blockOnScannerFailure !== undefined && typeof input.blockOnScannerFailure !== "boolean") {
    pushError(errors, "blockOnScannerFailure", "must be a boolean");
  }

  for (const field of ARRAY_FIELDS) {
    const value = (input as Record<string, unknown>)[field];
    const isValidArray = validateStringArray(errors, field, value);
    if (!isValidArray) continue;
    for (let i = 0; i < (value as string[]).length; i++) {
      const item = (value as string[])[i]!;
      if (!item.trim()) {
        pushError(errors, `${field}[${i}]`, "must be non-empty");
      }
    }
  }

  for (const [field, values] of [
    ["execBlockedPatterns", input.execBlockedPatterns],
    ["outboundSecretPatterns", input.outboundSecretPatterns],
  ] as const) {
    if (!Array.isArray(values)) continue;
    values.forEach((pattern, idx) => {
      if (typeof pattern !== "string") return;
      try {
        // Compile check only, execution remains in plugin runtime.
        // eslint-disable-next-line no-new
        new RegExp(pattern);
      } catch (err) {
        pushError(errors, `${field}[${idx}]`, `invalid regex: ${(err as Error).message}`);
      }
    });
  }

  // Domain list validation: reject URLs, whitespace-only, entries with spaces
  for (const [field, values] of [
    ["blockedDomains", input.blockedDomains],
    ["riskyDomains", input.riskyDomains],
  ] as const) {
    if (!Array.isArray(values)) continue;
    values.forEach((entry, idx) => {
      if (typeof entry !== "string") return;
      const trimmed = entry.trim();
      if (!trimmed) {
        pushError(errors, `${field}[${idx}]`, "must be non-empty");
        return;
      }
      if (/^https?:\/\//i.test(trimmed)) {
        pushError(errors, `${field}[${idx}]`, "must be a domain, not a URL (e.g. \"example.com\" not \"https://example.com\")");
        return;
      }
      if (/\s/.test(trimmed)) {
        pushError(errors, `${field}[${idx}]`, "must not contain whitespace");
      }
    });
  }

  for (const key of Object.keys(input as Record<string, unknown>)) {
    if (!KNOWN_KEYS.has(key)) {
      warnings.push({ field: key, message: "unknown field" });
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}

function diffChangedFields(prev: SecurityConfig, next: SecurityConfig): string[] {
  const keys = new Set([...Object.keys(prev as Record<string, unknown>), ...Object.keys(next as Record<string, unknown>)]);
  const changed: string[] = [];
  for (const key of [...keys].sort()) {
    const left = stableStringify((prev as Record<string, unknown>)[key]);
    const right = stableStringify((next as Record<string, unknown>)[key]);
    if (left !== right) changed.push(key);
  }
  return changed;
}

function writeAtomic(path: string, data: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmpPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  const fd = openSync(tmpPath, "w");
  try {
    writeFileSync(fd, data, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }

  renameSync(tmpPath, path);

  // fsync directory metadata so rename is durable.
  const dirFd = openSync(dirname(path), "r");
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
}

export function updateConfigStore(input: {
  config: SecurityConfig;
  expectedRevision: string;
  customPath?: string;
}): StoredConfig & { changedFields: string[]; previousRevision: string } {
  const current = readConfigStore(input.customPath);
  if (current.revision !== input.expectedRevision) {
    throw new RevisionConflictError(current.revision);
  }

  const nextConfig = ensureObject(input.config);
  const validation = validateSecurityConfig(nextConfig);
  if (!validation.valid) {
    throw new ConfigValidationError(validation.errors);
  }

  const changedFields = diffChangedFields(current.config, nextConfig);
  writeAtomic(current.path, `${JSON.stringify(nextConfig, null, 2)}\n`);
  const next = readConfigStore(current.path);

  return {
    ...next,
    changedFields,
    previousRevision: current.revision,
  };
}
