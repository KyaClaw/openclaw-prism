import { appendFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { createHash, createHmac } from "node:crypto";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

const AUDIT_DIR = join(homedir(), ".openclaw", "security");
const AUDIT_LOG = join(AUDIT_DIR, "audit.jsonl");
const AUDIT_ANCHOR_LOG = join(AUDIT_DIR, "audit.anchor.jsonl");

type AuditChainResult = {
  valid: number;
  invalid: number;
  firstInvalidLine: number | null;
};

type AuditAnchorPayload = {
  ts: string;
  entry: number;
  hash: string;
};

type AuditAnchorRecord = AuditAnchorPayload & { _hmac: string };

let _hmacKey: string | undefined;
let _lastHash: string | null | undefined;
let _entryCount: number | undefined;

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

function getAuditAnchorPath(): string {
  return process.env.OPENCLAW_AUDIT_ANCHOR_FILE?.trim() || AUDIT_ANCHOR_LOG;
}

function getAuditAnchorEvery(): number {
  const parsed = Number(process.env.OPENCLAW_AUDIT_ANCHOR_EVERY ?? "50");
  if (!Number.isFinite(parsed) || parsed < 1) return 0;
  return Math.floor(parsed);
}

function shouldWriteAnchor(entryCount: number): boolean {
  const every = getAuditAnchorEvery();
  return every > 0 && entryCount % every === 0;
}

function ensureDir(path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function getAuditEntryCount(): number {
  if (_entryCount !== undefined) return _entryCount;
  if (!existsSync(AUDIT_LOG)) {
    _entryCount = 0;
    return _entryCount;
  }
  _entryCount = readFileSync(AUDIT_LOG, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .length;
  return _entryCount;
}

function normalizeAnchorPayload(record: Record<string, unknown>): AuditAnchorPayload | null {
  const ts = record.ts;
  const entry = record.entry;
  const hash = record.hash;
  if (typeof ts !== "string" || !ts) return null;
  if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 1) return null;
  if (typeof hash !== "string" || !hash) return null;
  return { ts, entry, hash };
}

function anchorPayloadToRecord(payload: AuditAnchorPayload): Record<string, unknown> {
  return { ts: payload.ts, entry: payload.entry, hash: payload.hash };
}

function appendAuditAnchor(payload: AuditAnchorPayload): void {
  const anchorPath = getAuditAnchorPath();
  ensureDir(anchorPath);
  const hmac = computeHmac(anchorPayloadToRecord(payload));
  const record: AuditAnchorRecord = { ...payload, _hmac: hmac };
  appendFileSync(anchorPath, JSON.stringify(record) + "\n");
}

export function auditLog(entry: Record<string, unknown>): void {
  if (!existsSync(AUDIT_DIR)) mkdirSync(AUDIT_DIR, { recursive: true });

  const nextEntry = getAuditEntryCount() + 1;
  const record = {
    ...entry,
    ts: new Date().toISOString(),
    _prev: getLastHash(),
  };
  const hmac = computeHmac(record);
  const hash = computeHash(record, hmac);
  appendFileSync(AUDIT_LOG, JSON.stringify({ ...record, _hmac: hmac, _hash: hash }) + "\n");
  _lastHash = hash;
  _entryCount = nextEntry;

  if (shouldWriteAnchor(nextEntry)) {
    try {
      appendAuditAnchor({
        ts: record.ts,
        entry: nextEntry,
        hash,
      });
    } catch {
      // Keep runtime resilient if anchor sink is temporarily unavailable.
    }
  }
}

function getLastHash(): string | null {
  if (_lastHash !== undefined) return _lastHash;
  _lastHash = null;
  if (!existsSync(AUDIT_LOG)) {
    _entryCount = 0;
    return _lastHash;
  }

  const lines = readFileSync(AUDIT_LOG, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  _entryCount = lines.length;
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

function stripAnchorSignature(record: Record<string, unknown>): Record<string, unknown> {
  const { _hmac: _ignoreHmac, ...payload } = record;
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

function parseAnchorLine(line: string): Record<string, unknown> | null {
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

function collectAuditChainState(lines: string[]): AuditChainResult & {
  entryCount: number;
  hashByEntry: Map<number, string>;
} {
  let valid = 0;
  let invalid = 0;
  let firstInvalidLine: number | null = null;
  let prevHash: string | null = null;
  let entryIndex = 0;
  const hashByEntry = new Map<number, string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]?.trim();
    if (!line) continue;
    entryIndex++;
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
      hashByEntry.set(entryIndex, parsed._hash);
    }
    valid++;
  }

  return { valid, invalid, firstInvalidLine, entryCount: entryIndex, hashByEntry };
}

export function verifyAuditChain(lines: string[]): AuditChainResult {
  const { valid, invalid, firstInvalidLine } = collectAuditChainState(lines);
  return { valid, invalid, firstInvalidLine };
}

export function verifyAuditAnchors(
  auditLines: string[],
  anchorLines: string[],
): {
  anchorsChecked: number;
  anchorMismatches: number;
  firstMismatchLine: number | null;
  firstMismatchReason: string | null;
} {
  const auditState = collectAuditChainState(auditLines);
  let anchorsChecked = 0;
  let anchorMismatches = 0;
  let firstMismatchLine: number | null = null;
  let firstMismatchReason: string | null = null;

  for (let i = 0; i < anchorLines.length; i++) {
    const line = anchorLines[i]?.trim();
    if (!line) continue;
    anchorsChecked++;

    let mismatchReason: string | null = null;
    const parsed = parseAnchorLine(line);
    if (!parsed) {
      mismatchReason = "invalid-json";
    } else {
      const hmac = parsed._hmac;
      if (typeof hmac !== "string" || !hmac) {
        mismatchReason = "missing-hmac";
      } else {
        const payloadRaw = stripAnchorSignature(parsed);
        const payload = normalizeAnchorPayload(payloadRaw);
        if (!payload) {
          mismatchReason = "invalid-payload";
        } else {
          const expectedHmac = computeHmac(anchorPayloadToRecord(payload));
          if (hmac !== expectedHmac) {
            mismatchReason = "hmac-mismatch";
          } else {
            const observedHash = auditState.hashByEntry.get(payload.entry);
            if (!observedHash) {
              mismatchReason = payload.entry > auditState.entryCount
                ? "anchor-beyond-audit-end"
                : "missing-audit-hash";
            } else if (observedHash !== payload.hash) {
              mismatchReason = "hash-mismatch";
            }
          }
        }
      }
    }

    if (mismatchReason) {
      anchorMismatches++;
      if (firstMismatchLine === null) {
        firstMismatchLine = i + 1;
        firstMismatchReason = mismatchReason;
      }
    }
  }

  return { anchorsChecked, anchorMismatches, firstMismatchLine, firstMismatchReason };
}
