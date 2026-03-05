import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { createHmac } from "node:crypto";

// ── Types ──
type BootstrapHookEvent = {
  type?: string;
  action?: string;
  context?: {
    bootstrapFiles?: Array<{ path?: string; content?: string }>;
  };
  messages: string[];
};

type HookHandler = (event: BootstrapHookEvent) => Promise<void> | void;

// ── Paths ──
const SECURITY_DIR = join(homedir(), ".openclaw", "security");
const BACKUP_DIR = join(SECURITY_DIR, "backups");
const HASH_FILE = join(SECURITY_DIR, "bootstrap-hashes.json");
const AUDIT_LOG = join(SECURITY_DIR, "audit.jsonl");
const CRITICAL_FILES = ["SOUL.md", "AGENTS.md", "TOOLS.md"];

// ── Inline audit (self-contained, no workspace deps) ──
function inlineAuditLog(entry: Record<string, unknown>): void {
  const hmacKey = process.env.OPENCLAW_AUDIT_HMAC_KEY;
  if (!hmacKey) {
    // Refuse to write unsigned audit records — integrity cannot be silently degraded
    process.stderr.write(
      "[security-bootstrap] WARNING: OPENCLAW_AUDIT_HMAC_KEY not set, audit entry dropped\n",
    );
    return;
  }
  if (!existsSync(SECURITY_DIR)) mkdirSync(SECURITY_DIR, { recursive: true });
  const record = { ...entry, ts: new Date().toISOString() };
  const payload = JSON.stringify(record);
  const hmac = createHmac("sha256", hmacKey).update(payload).digest("hex");
  appendFileSync(AUDIT_LOG, JSON.stringify({ ...record, _hmac: hmac }) + "\n");
}

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

// ── Handler ──
const handler: HookHandler = async (event) => {
  if (event.type !== "agent" || event.action !== "bootstrap") return;

  const files = event.context?.bootstrapFiles;
  if (!files || !Array.isArray(files)) return;

  mkdirSync(BACKUP_DIR, { recursive: true });

  let known: Record<string, string> = {};
  try {
    known = JSON.parse(readFileSync(HASH_FILE, "utf-8"));
  } catch {
    // First run or corrupted file
  }

  let modified = false;
  for (const file of files) {
    const basename = String(file.path ?? "").split("/").pop() || "";
    if (!CRITICAL_FILES.includes(basename)) continue;

    if (typeof file.content !== "string") {
      inlineAuditLog({ event: "bootstrap_content_missing", file: basename });
      continue;
    }

    const content = file.content;
    const hash = sha256(content);

    if (known[basename] && known[basename] !== hash) {
      writeFileSync(join(BACKUP_DIR, `${basename}.tampered.${Date.now()}`), content);
      inlineAuditLog({
        event: "bootstrap_tamper",
        file: basename,
        expected: known[basename]!.slice(0, 12),
        got: hash.slice(0, 12),
      });
      event.messages.push(
        `[security] ${basename} hash changed since last verified. Backup saved. Verify manually.`,
      );
    }

    if (!known[basename]) {
      writeFileSync(join(BACKUP_DIR, `${basename}.baseline`), content);
    }

    known[basename] = hash;
    modified = true;
  }

  if (modified) writeFileSync(HASH_FILE, JSON.stringify(known, null, 2));
};

export default handler;
