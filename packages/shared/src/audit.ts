import { appendFileSync, mkdirSync, existsSync } from "node:fs";
import { createHmac } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";

const AUDIT_DIR = join(homedir(), ".openclaw", "security");
const AUDIT_LOG = join(AUDIT_DIR, "audit.jsonl");

let _hmacKey: string | undefined;

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

  const record = { ...entry, ts: new Date().toISOString() };
  const payload = JSON.stringify(record);
  const hmac = createHmac("sha256", getHmacKey()).update(payload).digest("hex");
  appendFileSync(AUDIT_LOG, JSON.stringify({ ...record, _hmac: hmac }) + "\n");
}

export function verifyAuditEntry(line: string): boolean {
  try {
    const record = JSON.parse(line) as Record<string, unknown>;
    const hmac = record._hmac as string;
    if (!hmac) return false;

    const { _hmac: _, ...rest } = record;
    const payload = JSON.stringify(rest);
    const expected = createHmac("sha256", getHmacKey())
      .update(payload)
      .digest("hex");
    return hmac === expected;
  } catch {
    return false;
  }
}
