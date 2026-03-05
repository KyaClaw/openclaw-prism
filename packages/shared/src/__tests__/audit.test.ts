import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe.sequential("audit chain", () => {
  const originalHome = process.env.HOME;
  const originalHmacKey = process.env.OPENCLAW_AUDIT_HMAC_KEY;
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
});
