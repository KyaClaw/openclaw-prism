import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";

const AUDIT_DIR = join(homedir(), ".openclaw", "security");
const AUDIT_LOG = join(AUDIT_DIR, "audit.jsonl");

let _hmacKey: string | undefined;
let _lastHash: string | null | undefined;

function getHmacKey(): string {
  if (!_hmacKey) {
    _hmacKey = process.env.OPENCLAW_AUDIT_HMAC_KEY;
    if (!_hmacKey) {
      throw new Error(
        "OPENCLAW_AUDIT_HMAC_KEY environment variable is required for audit logging",
      );
    }
  }
  return _hmacKey;
}

export function auditLog(entry: Record<string, unknown>): void {
  if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

  const record = {
    ...entry,
    ts: new Date().toISOString(),
    _prev: getLastHash(),
  };
  const hmac = computeHmac(record);
  const hash = computeHash(record, hmac);
  appendFileSync(AUDIT_LOG, JSON.stringify({ ...record, _hmac: hmac, _hash: hash }) + "\n");
  _lastHash = hash;
}

function getLastHash(): string | null {
  if (_lastHash !== undefined) return _lastHash;
  _lastHash = null;
  if (!existsSync(AUDIT_LOG)) return _lastHash;

  const lines = readFileSync(AUDIT_LOG, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(lines[i]!) as Record<string, unknown>;
      if (typeof parsed._hash === "string" && parsed._hash) {
        _lastHash = parsed._hash;
        break;
      }
    } catch {
      // Ignore malformed lines here; verification command will report failures.
    }
  }
  return _lastHash;
}

function stripSignatures(record: Record<string, unknown>): Record<string, unknown> {
  const { _hmac: _ignoreHmac, _hash: _ignoreHash, ...payload } = record;
  return payload;
}

function computeHmac(recordPayload: Record<string, unknown>): string {
  return createHmac("sha256", getHmacKey())
    .update(JSON.stringify(recordPayload))
    .digest("hex");
}

function computeHash(recordPayload: Record<string, unknown>, hmac: string): string {
  return createHash("sha256")
    .update(JSON.stringify(recordPayload))
    .update(hmac)
    .digest("hex");
}

function parseAuditLine(line: string): Record<string, unknown> | null {
  try {
    return JSON.parse(line) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function verifyAuditEntry(line: string, expectedPrevHash?: string | null): boolean {
  try {
    const record = JSON.parse(line) as Record<string, unknown>;
    const hmac = record._hmac as string;
    if (!hmac) return false;

    const payload = stripSignatures(record);
    const expectedHmac = computeHmac(payload);
    if (hmac !== expectedHmac) return false;

    if (typeof record._hash === "string") {
      const expectedHash = computeHash(payload, hmac);
      if (record._hash !== expectedHash) return false;
    }

    if (expectedPrevHash !== undefined && "_prev" in payload) {
      const prev = payload._prev as string | null | undefined;
      if ((prev ?? null) !== (expectedPrevHash ?? null)) return false;
    }

    return true;
  } catch {
    return false;
  }
}

export function verifyAuditChain(lines: string[]): {
  valid: number;
  invalid: number;
  firstInvalidLine: number | null;
} {
  let valid = 0;
  let invalid = 0;
  let firstInvalidLine: number | null = null;
  let prevHash: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line) continue;
    const parsed = parseAuditLine(line);
    if (!parsed) {
      invalid++;
      if (firstInvalidLine === null) firstInvalidLine = i + 1;
      continue;
    }

    const isChained = "_hash" in parsed || "_prev" in parsed;
    const ok = verifyAuditEntry(line, isChained ? prevHash : undefined);
    if (!ok) {
      invalid++;
      if (firstInvalidLine === null) firstInvalidLine = i + 1;
      continue;
    }

    if (typeof parsed._hash === "string" && parsed._hash) {
      prevHash = parsed._hash;
    }
    valid++;
  }

  return { valid, invalid, firstInvalidLine };
}
