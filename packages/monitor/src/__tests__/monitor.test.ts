import { describe, it, expect, afterEach, vi } from "vitest";
import { writeFileSync, unlinkSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createMonitor, computeHash } from "../index.js";

vi.mock("@kyaclaw/shared/audit", () => ({
  auditLog: vi.fn(),
}));

const TEST_DIR = join(tmpdir(), "kyaclaw-monitor-test-" + Date.now());
mkdirSync(TEST_DIR, { recursive: true });

describe("computeHash", () => {
  it("returns sha256 hash for existing file", () => {
    const path = join(TEST_DIR, "hash-test.txt");
    writeFileSync(path, "hello world");
    const hash = computeHash(path);
    expect(hash).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  });

  it("returns null for non-existent file", () => {
    expect(computeHash(join(TEST_DIR, "nonexistent.txt"))).toBeNull();
  });
});

describe("createMonitor", () => {
  const auditEntries: Record<string, unknown>[] = [];
  let monitor: Awaited<ReturnType<typeof createMonitor>>;

  afterEach(async () => {
    if (monitor) await monitor.close();
    auditEntries.length = 0;
  });

  it("establishes baseline hashes for existing files", async () => {
    const file = join(TEST_DIR, "soul.md");
    writeFileSync(file, "original content");

    monitor = createMonitor({
      watchPaths: [file],
      reconcileIntervalMs: 60_000,
      auditFn: (entry) => auditEntries.push(entry),
    });

    expect(monitor.hashes.has(file)).toBe(true);
    // Initial creation is logged
    expect(auditEntries.some((e) => e.event === "file_created_or_restored")).toBe(true);
  });

  it("detects file changes on reconcile", async () => {
    const file = join(TEST_DIR, "agents.md");
    writeFileSync(file, "v1");

    monitor = createMonitor({
      watchPaths: [file],
      reconcileIntervalMs: 60_000,
      auditFn: (entry) => auditEntries.push(entry),
    });

    // Clear initial entries
    auditEntries.length = 0;

    // Modify file
    writeFileSync(file, "v2 - modified externally");
    monitor.reconcileAll();

    expect(auditEntries.some((e) => e.event === "file_changed_external")).toBe(true);
  });

  it("detects file deletion on reconcile", async () => {
    const file = join(TEST_DIR, "deleteme.md");
    writeFileSync(file, "temp");

    monitor = createMonitor({
      watchPaths: [file],
      reconcileIntervalMs: 60_000,
      auditFn: (entry) => auditEntries.push(entry),
    });

    auditEntries.length = 0;
    unlinkSync(file);
    monitor.reconcileAll();

    expect(auditEntries.some((e) => e.event === "file_deleted_or_unreadable")).toBe(true);
  });

  it("ignores non-existent files at startup", async () => {
    monitor = createMonitor({
      watchPaths: [join(TEST_DIR, "does-not-exist.md")],
      reconcileIntervalMs: 60_000,
      auditFn: (entry) => auditEntries.push(entry),
    });

    expect(monitor.hashes.size).toBe(0);
    expect(auditEntries.length).toBe(0);
  });
});
