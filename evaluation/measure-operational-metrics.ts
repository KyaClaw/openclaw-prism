import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

type TimingSummary = {
  iterations: number;
  avgMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  minMs: number;
  maxMs: number;
};

type OperationalMetricsReport = {
  generatedAt: string;
  outputDir: string;
  auditVerify: {
    auditEntries: number;
    anchorEvery: number;
    anchorCount: number;
    chainOnly: TimingSummary;
    chainPlusAnchors: TimingSummary;
  };
  policyReload: {
    iterations: number;
    policyPath: string;
    timing: TimingSummary;
  };
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(EVAL_ROOT, "..");
const DEFAULT_OUTPUT_DIR = join(EVAL_ROOT, "results", "tables-operational");
const DEFAULT_ITERATIONS = 15;
const DEFAULT_AUDIT_ENTRIES = 200;
const DEFAULT_ANCHOR_EVERY = 10;

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/measure-operational-metrics.ts [--output-dir <path>] [--iterations <n>] [--audit-entries <n>] [--anchor-every <n>]",
    "",
    "Outputs:",
    "  operational-metrics.json",
    "  operational-metrics.md",
    "  operational-metrics.tex",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  outputDir: string;
  iterations: number;
  auditEntries: number;
  anchorEvery: number;
} {
  let outputDir = DEFAULT_OUTPUT_DIR;
  let iterations = DEFAULT_ITERATIONS;
  let auditEntries = DEFAULT_AUDIT_ENTRIES;
  let anchorEvery = DEFAULT_ANCHOR_EVERY;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--output-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--output-dir requires a value");
      outputDir = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--iterations") {
      const raw = Number(argv[++i] ?? "");
      if (!Number.isInteger(raw) || raw < 1) throw new Error("--iterations must be a positive integer");
      iterations = raw;
      continue;
    }
    if (arg === "--audit-entries") {
      const raw = Number(argv[++i] ?? "");
      if (!Number.isInteger(raw) || raw < 1) throw new Error("--audit-entries must be a positive integer");
      auditEntries = raw;
      continue;
    }
    if (arg === "--anchor-every") {
      const raw = Number(argv[++i] ?? "");
      if (!Number.isInteger(raw) || raw < 1) throw new Error("--anchor-every must be a positive integer");
      anchorEvery = raw;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { outputDir, iterations, auditEntries, anchorEvery };
}

function toRoundedMs(value: number): number {
  return Number(value.toFixed(3));
}

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return toRoundedMs(sorted[idx]!);
}

function summarizeSamples(samples: number[]): TimingSummary {
  if (samples.length === 0) {
    throw new Error("cannot summarize empty sample set");
  }
  const rounded = samples.map((value) => toRoundedMs(value));
  return {
    iterations: rounded.length,
    avgMs: toRoundedMs(rounded.reduce((sum, value) => sum + value, 0) / rounded.length),
    p50Ms: percentile(rounded, 50),
    p95Ms: percentile(rounded, 95),
    p99Ms: percentile(rounded, 99),
    minMs: toRoundedMs(Math.min(...rounded)),
    maxMs: toRoundedMs(Math.max(...rounded)),
  };
}

function writeOutput(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

async function importFresh<T>(absolutePath: string): Promise<T> {
  const href = pathToFileURL(absolutePath).href;
  return (await import(`${href}?t=${Date.now()}-${Math.random().toString(16).slice(2)}`)) as T;
}

function withMutedStdout<T>(fn: () => T): T {
  const originalStdout = process.stdout.write.bind(process.stdout);
  const originalStderr = process.stderr.write.bind(process.stderr);
  const noop = (() => true) as typeof process.stdout.write;
  process.stdout.write = noop;
  process.stderr.write = noop;
  try {
    return fn();
  } finally {
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
  }
}

async function measureAuditVerify(iterations: number, auditEntries: number, anchorEvery: number): Promise<OperationalMetricsReport["auditVerify"]> {
  const tempHome = mkdtempSync(join(tmpdir(), "openclaw-prism-audit-overhead-"));
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalHmac = process.env.OPENCLAW_AUDIT_HMAC_KEY;
  const originalAnchorFile = process.env.OPENCLAW_AUDIT_ANCHOR_FILE;
  const originalAnchorEvery = process.env.OPENCLAW_AUDIT_ANCHOR_EVERY;

  try {
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    process.env.OPENCLAW_AUDIT_HMAC_KEY = "benchmark-audit-hmac-key";
    process.env.OPENCLAW_AUDIT_ANCHOR_FILE = join(tempHome, ".openclaw", "security", "audit.anchor.jsonl");
    process.env.OPENCLAW_AUDIT_ANCHOR_EVERY = String(anchorEvery);

    const auditModule = await importFresh<{
      auditLog: (entry: Record<string, unknown>) => void;
      verifyAuditChain: (lines: string[]) => { invalid: number };
      verifyAuditAnchors: (auditLines: string[], anchorLines: string[]) => { anchorMismatches: number };
    }>(join(REPO_ROOT, "packages", "shared", "src", "audit.ts"));

    for (let i = 0; i < auditEntries; i++) {
      auditModule.auditLog({ event: "bench_audit_entry", index: i, suite: "operational-metrics" });
    }

    const auditLines = readFileSync(join(tempHome, ".openclaw", "security", "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter(Boolean);
    const anchorLines = readFileSync(join(tempHome, ".openclaw", "security", "audit.anchor.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter(Boolean);

    const chainOnlySamples: number[] = [];
    const chainPlusAnchorSamples: number[] = [];
    for (let i = 0; i < iterations; i++) {
      let start = performance.now();
      const chain = auditModule.verifyAuditChain(auditLines);
      chainOnlySamples.push(performance.now() - start);
      if (chain.invalid !== 0) {
        throw new Error("audit verify benchmark generated invalid chain");
      }

      start = performance.now();
      const chainAgain = auditModule.verifyAuditChain(auditLines);
      const anchors = auditModule.verifyAuditAnchors(auditLines, anchorLines);
      chainPlusAnchorSamples.push(performance.now() - start);
      if (chainAgain.invalid !== 0 || anchors.anchorMismatches !== 0) {
        throw new Error("audit anchor verify benchmark generated mismatches");
      }
    }

    return {
      auditEntries,
      anchorEvery,
      anchorCount: anchorLines.length,
      chainOnly: summarizeSamples(chainOnlySamples),
      chainPlusAnchors: summarizeSamples(chainPlusAnchorSamples),
    };
  } finally {
    rmSync(tempHome, { recursive: true, force: true });
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalUserProfile !== undefined) process.env.USERPROFILE = originalUserProfile;
    else delete process.env.USERPROFILE;
    if (originalHmac !== undefined) process.env.OPENCLAW_AUDIT_HMAC_KEY = originalHmac;
    else delete process.env.OPENCLAW_AUDIT_HMAC_KEY;
    if (originalAnchorFile !== undefined) process.env.OPENCLAW_AUDIT_ANCHOR_FILE = originalAnchorFile;
    else delete process.env.OPENCLAW_AUDIT_ANCHOR_FILE;
    if (originalAnchorEvery !== undefined) process.env.OPENCLAW_AUDIT_ANCHOR_EVERY = originalAnchorEvery;
    else delete process.env.OPENCLAW_AUDIT_ANCHOR_EVERY;
  }
}

function buildPolicyVariant(index: number): Record<string, unknown> {
  return {
    host: "127.0.0.1",
    port: 18768 + (index % 2),
    upstreamUrl: "http://127.0.0.1:3000",
    upstreamTokenEnv: "OPENCLAW_UPSTREAM_TOKEN",
    upstreamTimeoutMs: 30000 + index,
    defaultDenyTools: ["dangerous_tool", index % 2 === 0 ? "exec" : "never-match-tool"],
    scannerUrl: "http://127.0.0.1:18766/scan",
    scannerTimeoutMs: 1200 + index,
    blockOnScannerFailure: false,
    clients: [
      {
        id: "benchmark-client",
        token: "benchmark-token",
        allowedSessionPrefixes: ["agent:bench:"],
        allowTools: ["exec", "web_fetch", "read"],
        denyTools: index % 2 === 0 ? ["write"] : ["edit"],
      },
    ],
  };
}

async function measurePolicyReload(iterations: number): Promise<OperationalMetricsReport["policyReload"]> {
  const tempDir = mkdtempSync(join(tmpdir(), "openclaw-prism-policy-overhead-"));
  const policyPath = join(tempDir, "invoke-guard.policy.json");
  const originalPolicyEnv = process.env.INVOKE_GUARD_POLICY;

  try {
    writeFileSync(policyPath, `${JSON.stringify(buildPolicyVariant(0), null, 2)}\n`, "utf8");
    process.env.INVOKE_GUARD_POLICY = policyPath;

    const proxyModule = await importFresh<{
      createServer: () => { server: { close?: () => void }; reloadPolicy: () => void };
    }>(join(REPO_ROOT, "packages", "proxy", "src", "index.ts"));

    const { server, reloadPolicy } = proxyModule.createServer();
    const samples: number[] = [];
    for (let i = 1; i <= iterations; i++) {
      writeFileSync(policyPath, `${JSON.stringify(buildPolicyVariant(i), null, 2)}\n`, "utf8");
      const start = performance.now();
      withMutedStdout(() => reloadPolicy());
      samples.push(performance.now() - start);
    }
    if (typeof server.close === "function") {
      withMutedStdout(() => server.close!());
    }

    return {
      iterations,
      policyPath,
      timing: summarizeSamples(samples),
    };
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalPolicyEnv !== undefined) process.env.INVOKE_GUARD_POLICY = originalPolicyEnv;
    else delete process.env.INVOKE_GUARD_POLICY;
  }
}

function buildMarkdown(report: OperationalMetricsReport): string {
  const lines: string[] = [];
  lines.push("# Operational Metrics");
  lines.push("");
  lines.push(`Generated at: ${report.generatedAt}`);
  lines.push("");
  lines.push("These are component-level operational timings intended to support the paper's recoverability discussion, not full deployment-wide end-to-end overhead numbers.");
  lines.push("");
  lines.push("## Audit Verification");
  lines.push("");
  lines.push(`- Audit entries: ${report.auditVerify.auditEntries}`);
  lines.push(`- Anchor cadence: every ${report.auditVerify.anchorEvery} entries`);
  lines.push(`- Anchors written: ${report.auditVerify.anchorCount}`);
  lines.push("");
  lines.push("| Operation | Avg ms | p50 ms | p95 ms | p99 ms | Min ms | Max ms |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
  lines.push(
    `| Verify chain only | ${report.auditVerify.chainOnly.avgMs.toFixed(3)} | ${report.auditVerify.chainOnly.p50Ms.toFixed(3)} | ${report.auditVerify.chainOnly.p95Ms.toFixed(3)} | ${report.auditVerify.chainOnly.p99Ms.toFixed(3)} | ${report.auditVerify.chainOnly.minMs.toFixed(3)} | ${report.auditVerify.chainOnly.maxMs.toFixed(3)} |`,
  );
  lines.push(
    `| Verify chain + anchors | ${report.auditVerify.chainPlusAnchors.avgMs.toFixed(3)} | ${report.auditVerify.chainPlusAnchors.p50Ms.toFixed(3)} | ${report.auditVerify.chainPlusAnchors.p95Ms.toFixed(3)} | ${report.auditVerify.chainPlusAnchors.p99Ms.toFixed(3)} | ${report.auditVerify.chainPlusAnchors.minMs.toFixed(3)} | ${report.auditVerify.chainPlusAnchors.maxMs.toFixed(3)} |`,
  );
  lines.push("");
  lines.push("## Policy Reload");
  lines.push("");
  lines.push(`- Policy path: \`${report.policyReload.policyPath}\``);
  lines.push(`- Iterations: ${report.policyReload.iterations}`);
  lines.push("");
  lines.push("| Operation | Avg ms | p50 ms | p95 ms | p99 ms | Min ms | Max ms |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
  lines.push(
    `| Proxy reloadPolicy() | ${report.policyReload.timing.avgMs.toFixed(3)} | ${report.policyReload.timing.p50Ms.toFixed(3)} | ${report.policyReload.timing.p95Ms.toFixed(3)} | ${report.policyReload.timing.p99Ms.toFixed(3)} | ${report.policyReload.timing.minMs.toFixed(3)} | ${report.policyReload.timing.maxMs.toFixed(3)} |`,
  );
  lines.push("");
  return lines.join("\n") + "\n";
}

function buildLatex(report: OperationalMetricsReport): string {
  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\footnotesize");
  lines.push("\\begin{tabularx}{\\textwidth}{l c c c c c c}");
  lines.push("\\toprule");
  lines.push("Operation & Avg ms & p50 ms & p95 ms & p99 ms & Min ms & Max ms \\\\");
  lines.push("\\midrule");
  lines.push(
    `Verify chain only & ${report.auditVerify.chainOnly.avgMs.toFixed(3)} & ${report.auditVerify.chainOnly.p50Ms.toFixed(3)} & ${report.auditVerify.chainOnly.p95Ms.toFixed(3)} & ${report.auditVerify.chainOnly.p99Ms.toFixed(3)} & ${report.auditVerify.chainOnly.minMs.toFixed(3)} & ${report.auditVerify.chainOnly.maxMs.toFixed(3)} \\\\`,
  );
  lines.push(
    `Verify chain + anchors & ${report.auditVerify.chainPlusAnchors.avgMs.toFixed(3)} & ${report.auditVerify.chainPlusAnchors.p50Ms.toFixed(3)} & ${report.auditVerify.chainPlusAnchors.p95Ms.toFixed(3)} & ${report.auditVerify.chainPlusAnchors.p99Ms.toFixed(3)} & ${report.auditVerify.chainPlusAnchors.minMs.toFixed(3)} & ${report.auditVerify.chainPlusAnchors.maxMs.toFixed(3)} \\\\`,
  );
  lines.push(
    `Proxy reloadPolicy() & ${report.policyReload.timing.avgMs.toFixed(3)} & ${report.policyReload.timing.p50Ms.toFixed(3)} & ${report.policyReload.timing.p95Ms.toFixed(3)} & ${report.policyReload.timing.p99Ms.toFixed(3)} & ${report.policyReload.timing.minMs.toFixed(3)} & ${report.policyReload.timing.maxMs.toFixed(3)} \\\\`,
  );
  lines.push("\\bottomrule");
  lines.push("\\end{tabularx}");
  lines.push("\\caption{Preliminary operational timings for audit verification and proxy policy reload. These values characterize component-level maintenance operations rather than request-path latency.}");
  lines.push("\\label{tab:prelim-operational-metrics}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  mkdirSync(opts.outputDir, { recursive: true });

  const report: OperationalMetricsReport = {
    generatedAt: new Date().toISOString(),
    outputDir: opts.outputDir,
    auditVerify: await measureAuditVerify(opts.iterations, opts.auditEntries, opts.anchorEvery),
    policyReload: await measurePolicyReload(opts.iterations),
  };

  writeOutput(join(opts.outputDir, "operational-metrics.json"), JSON.stringify(report, null, 2) + "\n");
  writeOutput(join(opts.outputDir, "operational-metrics.md"), buildMarkdown(report));
  writeOutput(join(opts.outputDir, "operational-metrics.tex"), buildLatex(report));

  process.stdout.write(`[measure-operational-metrics] wrote ${join(opts.outputDir, "operational-metrics.json")}\n`);
  process.stdout.write(`[measure-operational-metrics] wrote ${join(opts.outputDir, "operational-metrics.md")}\n`);
  process.stdout.write(`[measure-operational-metrics] wrote ${join(opts.outputDir, "operational-metrics.tex")}\n`);
}

void main().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[measure-operational-metrics] ERROR ${message}\n`);
  process.exitCode = 1;
});
