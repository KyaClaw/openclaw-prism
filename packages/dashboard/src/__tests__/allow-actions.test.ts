import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import {
  applyAllowAction,
  describeAllowAction,
  previewAllowAction,
  SourceCursorValidationError,
  ConfirmationRequiredError,
  AllowActionUnsupportedError,
} from "../allow-actions.js";
import { readAuditEntries } from "../audit-reader.js";
import { readConfigStore } from "../config-store.js";

function createFixture() {
  const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-allow-"));
  const auditPath = join(dir, "audit.jsonl");
  const policyPath = join(dir, "security.policy.json");

  const records = [
    {
      ts: "2026-03-06T12:00:00.000Z",
      event: "exec_whitelist_block",
      command: "curl https://example.com",
      session: "sess-a",
    },
    {
      ts: "2026-03-06T12:01:00.000Z",
      event: "path_block",
      path: "../legacy/path.txt",
      session: "sess-legacy",
    },
    {
      ts: "2026-03-06T12:02:00.000Z",
      event: "path_block",
      rawPath: "../etc/hosts",
      cwd: "/home/user/project",
      session: "sess-path",
    },
    {
      ts: "2026-03-06T12:03:00.000Z",
      event: "exec_pattern_block",
      pattern: "rm\\s+-rf\\s+/",
      session: "sess-pattern",
    },
    {
      ts: "2026-03-06T12:04:00.000Z",
      event: "outbound_secret_blocked",
      pattern: "AKIA[0-9A-Z]{16}",
      session: "sess-secret",
    },
  ];
  writeFileSync(auditPath, `${records.map((r) => JSON.stringify(r)).join("\n")}\n`, "utf8");
  writeFileSync(policyPath, `${JSON.stringify({
    execAllowedPrefixes: ["node"],
    protectedPathExceptions: [],
    execBlockedPatterns: ["rm\\s+-rf\\s+/"],
    outboundSecretPatterns: ["AKIA[0-9A-Z]{16}"],
  }, null, 2)}\n`);

  return { auditPath, policyPath };
}

describe("allow-actions", () => {
  it("builds exec allow preview from source cursor", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const execCursor = entries.find((entry) => entry.record.event === "exec_whitelist_block")!.cursor;

    const preview = previewAllowAction({
      sourceCursor: execCursor,
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });

    expect(preview.supported).toBe(true);
    expect(preview.action?.type).toBe("add_exec_prefix");
    expect(preview.action?.value).toBe("curl");
    expect(preview.impact?.riskLevel).toBe("low");
  });

  it("blocks legacy relative path records from allow flow", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const legacyCursor = entries.find((entry) =>
      entry.record.event === "path_block" && entry.record.legacyRecord === true
    )!.cursor;

    const preview = previewAllowAction({
      sourceCursor: legacyCursor,
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });
    expect(preview.supported).toBe(false);
    expect(preview.reason).toContain("legacy relative path");
  });

  it("requires ALLOW confirmation for medium risk actions", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const pathCursor = entries.find((entry) =>
      entry.record.event === "path_block" && entry.record.legacyRecord !== true
    )!.cursor;
    const current = readConfigStore(fixture.policyPath);

    expect(() => {
      applyAllowAction({
        sourceCursor: pathCursor,
        revision: current.revision,
        auditLogPath: fixture.auditPath,
        policyPath: fixture.policyPath,
      });
    }).toThrow(ConfirmationRequiredError);
  });

  it("previews and applies exec pattern unblock action", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const cursor = entries.find((entry) => entry.record.event === "exec_pattern_block")!.cursor;

    const preview = previewAllowAction({
      sourceCursor: cursor,
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });
    expect(preview.supported).toBe(true);
    expect(preview.action?.type).toBe("remove_blocked_pattern");
    expect(preview.impact?.riskLevel).toBe("medium");
    expect(preview.impact?.requiresConfirmation).toBe(true);

    const current = readConfigStore(fixture.policyPath);
    applyAllowAction({
      sourceCursor: cursor,
      revision: current.revision,
      confirmation: "ALLOW",
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });

    const updated = readConfigStore(fixture.policyPath);
    expect(updated.config.execBlockedPatterns).not.toContain("rm\\s+-rf\\s+/");
  });

  it("previews and applies outbound secret unblock action", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const cursor = entries.find((entry) => entry.record.event === "outbound_secret_blocked")!.cursor;

    const preview = previewAllowAction({
      sourceCursor: cursor,
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });
    expect(preview.supported).toBe(true);
    expect(preview.action?.type).toBe("remove_secret_pattern");
    expect(preview.impact?.riskLevel).toBe("medium");

    const current = readConfigStore(fixture.policyPath);
    applyAllowAction({
      sourceCursor: cursor,
      revision: current.revision,
      confirmation: "ALLOW",
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });

    const updated = readConfigStore(fixture.policyPath);
    expect(updated.config.outboundSecretPatterns).not.toContain("AKIA[0-9A-Z]{16}");
  });

  it("applies exec allow action and updates config revision", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const execCursor = entries.find((entry) => entry.record.event === "exec_whitelist_block")!.cursor;
    const current = readConfigStore(fixture.policyPath);

    const result = applyAllowAction({
      sourceCursor: execCursor,
      revision: current.revision,
      auditLogPath: fixture.auditPath,
      policyPath: fixture.policyPath,
    });

    expect(result.revision).not.toBe(current.revision);
    expect(result.action.type).toBe("add_exec_prefix");

    const updated = readConfigStore(fixture.policyPath);
    expect(updated.config.execAllowedPrefixes).toContain("curl");
  });

  it("preserves existing exec prefix casing when adding a new prefix", () => {
    const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-allow-prefix-case-"));
    const auditPath = join(dir, "audit.jsonl");
    const policyPath = join(dir, "security.policy.json");
    writeFileSync(auditPath, `${JSON.stringify({
      ts: "2026-03-06T12:00:00.000Z",
      event: "exec_whitelist_block",
      command: "curl https://example.com",
    })}\n`);
    writeFileSync(policyPath, `${JSON.stringify({ execAllowedPrefixes: ["Node"] }, null, 2)}\n`);

    const entry = readAuditEntries({ auditLogPath: auditPath }).entries[0]!;
    const current = readConfigStore(policyPath);
    applyAllowAction({
      sourceCursor: entry.cursor,
      revision: current.revision,
      auditLogPath: auditPath,
      policyPath,
    });

    const updated = readConfigStore(policyPath);
    expect(updated.config.execAllowedPrefixes).toContain("Node");
    expect(updated.config.execAllowedPrefixes).toContain("curl");
  });

  it("validates sourceCursor format", () => {
    const fixture = createFixture();
    expect(() => {
      previewAllowAction({
        sourceCursor: "not-a-cursor",
        auditLogPath: fixture.auditPath,
        policyPath: fixture.policyPath,
      });
    }).toThrow(SourceCursorValidationError);
  });

  it("marks allow action as already applied when config already satisfies it", () => {
    const fixture = createFixture();
    const entries = readAuditEntries({ auditLogPath: fixture.auditPath }).entries;
    const execRecord = entries.find((entry) => entry.record.event === "exec_whitelist_block")!.record;
    const pathRecord = entries.find((entry) =>
      entry.record.event === "path_block" && entry.record.legacyRecord !== true
    )!.record;

    const execDescriptor = describeAllowAction(execRecord, { execAllowedPrefixes: ["curl"] });
    expect(execDescriptor.supported).toBe(true);
    expect(execDescriptor.alreadyApplied).toBe(true);

    const pathDescriptor = describeAllowAction(pathRecord, {
      protectedPathExceptions: ["/home/user/etc/hosts"],
    });
    expect(pathDescriptor.supported).toBe(true);
    expect(pathDescriptor.alreadyApplied).toBe(true);
  });

  it("rejects unsupported event types", () => {
    const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-allow-unsupported-"));
    const auditPath = join(dir, "audit.jsonl");
    const policyPath = join(dir, "security.policy.json");
    writeFileSync(auditPath, `${JSON.stringify({ ts: "2026-03-06T12:00:00.000Z", event: "risk_escalation_block" })}\n`);
    writeFileSync(policyPath, `${JSON.stringify({ execAllowedPrefixes: ["node"] }, null, 2)}\n`);

    const entry = readAuditEntries({ auditLogPath: auditPath }).entries[0]!;
    expect(isAbsolute(policyPath)).toBe(true);
    expect(() => {
      applyAllowAction({
        sourceCursor: entry.cursor,
        revision: readConfigStore(policyPath).revision,
        auditLogPath: auditPath,
        policyPath,
      });
    }).toThrow(AllowActionUnsupportedError);
  });
});
