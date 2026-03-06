import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe.sequential("audit chain", () => {
  const originalHome = process.env.HOME;
  const originalHmacKey = process.env.OPENCLAW_AUDIT_HMAC_KEY;
  const originalAnchorFile = process.env.OPENCLAW_AUDIT_ANCHOR_FILE;
  const originalAnchorEvery = process.env.OPENCLAW_AUDIT_ANCHOR_EVERY;
  let tempHome = "";

  beforeEach(() => {
    tempHome = mkdtempSync(join(tmpdir(), "kyaclaw-audit-test-"));
    process.env.HOME = tempHome;
    process.env.OPENCLAW_AUDIT_HMAC_KEY = "test-audit-hmac-key";
    vi.resetModules();
  });

  afterEach(() => {
    rmSync(tempHome, { recursive: true, force: true });
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalHmacKey !== undefined) process.env.OPENCLAW_AUDIT_HMAC_KEY = originalHmacKey;
    else delete process.env.OPENCLAW_AUDIT_HMAC_KEY;
    if (originalAnchorFile !== undefined) process.env.OPENCLAW_AUDIT_ANCHOR_FILE = originalAnchorFile;
    else delete process.env.OPENCLAW_AUDIT_ANCHOR_FILE;
    if (originalAnchorEvery !== undefined) process.env.OPENCLAW_AUDIT_ANCHOR_EVERY = originalAnchorEvery;
    else delete process.env.OPENCLAW_AUDIT_ANCHOR_EVERY;
  });

  it("verifies intact chained entries", async () => {
    const { auditLog, verifyAuditChain } = await import("../audit.js");
    auditLog({ event: "one" });
    auditLog({ event: "two" });

    const lines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");

    const result = verifyAuditChain(lines);
    expect(result.valid).toBe(2);
    expect(result.invalid).toBe(0);
    expect(result.firstInvalidLine).toBeNull();
  });

  it("detects chain break after deleting middle entries", async () => {
    const { auditLog, verifyAuditChain } = await import("../audit.js");
    auditLog({ event: "one" });
    auditLog({ event: "two" });
    auditLog({ event: "three" });

    const allLines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");

    const tampered = [allLines[0]!, allLines[2]!];
    const result = verifyAuditChain(tampered);

    expect(result.invalid).toBeGreaterThan(0);
    expect(result.firstInvalidLine).toBe(2);
  });

  it("verifies anchors and detects deleted audit segments", async () => {
    process.env.OPENCLAW_AUDIT_ANCHOR_FILE = join(tempHome, ".openclaw", "security", "audit.anchor.jsonl");
    process.env.OPENCLAW_AUDIT_ANCHOR_EVERY = "1";

    const { auditLog, verifyAuditAnchors } = await import("../audit.js");
    auditLog({ event: "one" });
    auditLog({ event: "two" });
    auditLog({ event: "three" });

    const auditLines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");
    const anchorLines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.anchor.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");

    const intact = verifyAuditAnchors(auditLines, anchorLines);
    expect(intact.anchorsChecked).toBe(3);
    expect(intact.anchorMismatches).toBe(0);

    const tamperedAudit = [auditLines[0]!, auditLines[2]!];
    const tampered = verifyAuditAnchors(tamperedAudit, anchorLines);
    expect(tampered.anchorMismatches).toBeGreaterThan(0);
    expect(tampered.firstMismatchLine).toBe(2);
    expect(tampered.firstMismatchReason).toBe("missing-audit-hash");
  });

  it("detects anchor hmac tampering", async () => {
    process.env.OPENCLAW_AUDIT_ANCHOR_FILE = join(tempHome, ".openclaw", "security", "audit.anchor.jsonl");
    process.env.OPENCLAW_AUDIT_ANCHOR_EVERY = "1";

    const { auditLog, verifyAuditAnchors } = await import("../audit.js");
    auditLog({ event: "one" });
    auditLog({ event: "two" });

    const auditLines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");
    const anchorLines = readFileSync(
      join(tempHome, ".openclaw", "security", "audit.anchor.jsonl"),
      "utf8",
    )
      .trim()
      .split("\n");

    const firstAnchor = JSON.parse(anchorLines[0]!) as Record<string, unknown>;
    firstAnchor._hmac = "tampered";
    anchorLines[0] = JSON.stringify(firstAnchor);

    const result = verifyAuditAnchors(auditLines, anchorLines);
    expect(result.anchorMismatches).toBeGreaterThan(0);
    expect(result.firstMismatchReason).toBe("hmac-mismatch");
  });
});
