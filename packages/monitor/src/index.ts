#!/usr/bin/env node
import { readFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { watch as chokidarWatch } from "chokidar";
import { auditLog } from "@kyaclaw/shared/audit";

const SECURITY_DIR = join(homedir(), ".openclaw", "security");
const DEFAULT_WATCH_PATHS = [
  join(homedir(), ".openclaw", "workspace", "SOUL.md"),
  join(homedir(), ".openclaw", "workspace", "AGENTS.md"),
  join(homedir(), ".openclaw", "openclaw.json"),
  join(homedir(), ".openclaw", "auth-profiles.json"),
];

export function computeHash(path: string): string | null {
  try {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return null;
  }
}

export function createMonitor(opts?: {
  watchPaths?: string[];
  reconcileIntervalMs?: number;
  auditFn?: (entry: Record<string, unknown>) => void;
}) {
  const watchPaths = opts?.watchPaths ?? DEFAULT_WATCH_PATHS;
  const reconcileMs = opts?.reconcileIntervalMs ?? 30_000;
  const audit = opts?.auditFn ?? auditLog;
  const hashes = new Map<string, string>();

  function reconcilePath(path: string) {
    const oldHash = hashes.get(path);
    const newHash = computeHash(path);

    if (!newHash) {
      if (oldHash) {
        hashes.delete(path);
        audit({ event: "file_deleted_or_unreadable", path, old: oldHash.slice(0, 12) });
        process.stderr.write(`[file-monitor] ${path} deleted or unreadable\n`);
      }
      return;
    }

    if (oldHash && oldHash !== newHash) {
      audit({
        event: "file_changed_external",
        path,
        old: oldHash.slice(0, 12),
        new: newHash.slice(0, 12),
      });
      process.stderr.write(`[file-monitor] ${path} changed externally\n`);
    } else if (!oldHash) {
      audit({ event: "file_created_or_restored", path, new: newHash.slice(0, 12) });
      process.stdout.write(`[file-monitor] ${path} created/restored\n`);
    }

    hashes.set(path, newHash);
  }

  function reconcileAll() {
    for (const p of watchPaths) reconcilePath(p);
  }

  mkdirSync(SECURITY_DIR, { recursive: true });

  // Initial hash baseline
  reconcileAll();

  // Watch with chokidar for reliable cross-platform file watching
  const watchSet = new Set(watchPaths);
  const watcher = chokidarWatch(watchPaths, {
    persistent: true,
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 50 },
  });

  watcher.on("change", (path) => {
    if (watchSet.has(path)) reconcilePath(path);
  });
  watcher.on("unlink", (path) => {
    if (watchSet.has(path)) reconcilePath(path);
  });
  watcher.on("add", (path) => {
    if (watchSet.has(path)) reconcilePath(path);
  });

  process.stdout.write(
    `[file-monitor] monitoring ${watchPaths.length} target files\n`,
  );

  // Periodic full reconciliation (fallback for missed events)
  const interval = setInterval(reconcileAll, reconcileMs);

  return {
    hashes,
    reconcileAll,
    async close() {
      clearInterval(interval);
      await watcher.close();
    },
  };
}

// Start when run directly
const isMainModule =
  process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ""));
if (isMainModule || process.env.KYACLAW_MONITOR_START) {
  createMonitor();
}
