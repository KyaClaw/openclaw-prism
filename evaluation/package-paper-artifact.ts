import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type BenchmarkReport = {
  generatedAt: string;
  outputPath: string;
  totalLoadedCases: number;
  suiteFilter?: string[] | null;
  scanner?: {
    mode: "default" | "mock" | "live";
    ollamaModel: string;
    ollamaTimeoutMs: number;
    ollamaTemperature?: number | null;
    ollamaSeed?: number | null;
    pluginScannerTimeoutMs?: number;
    modelAssistedCases: number;
  } | null;
  reports: Array<{
    engine: string;
    summary: {
      executed: number;
      passed: number;
      failed: number;
      metrics: {
        accuracy: number | null;
        precision: number | null;
        recall: number | null;
        f1: number | null;
        attackBlockRate: number | null;
        falsePositiveRate: number | null;
      } | null;
    };
  }>;
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const DEFAULT_INPUT = join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-live.json");
const DEFAULT_FINAL_ROOT = join(EVAL_ROOT, "results", "final");
const BASELINE_LADDER_ENGINES = [
  "no-prism",
  "heuristics-only",
  "plugin-only",
  "plugin-scanner",
  "full-prism",
] as const;

type Status = "preliminary" | "candidate" | "final";

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/package-paper-artifact.ts [options]",
    "",
    "Options:",
    "  --input-report <path>       Benchmark report JSON to package",
    "  --tables-dir <path>         Rendered tables directory (defaults from report name)",
    "  --artifact-name <name>      Output subdirectory name under evaluation/results/final/",
    "  --final-root <path>         Root directory for packaged artifacts",
    "  --status <value>            preliminary | candidate | final (default: candidate)",
    "  --help                      Show this message",
    "",
    "Outputs:",
    "  Copies the selected report and rendered table fragments into a stable",
    "  evaluation/results/final/<artifact-name>/ directory and writes artifact-manifest.md.",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  inputReport: string;
  tablesDir: string;
  artifactName: string;
  finalRoot: string;
  status: Status;
} {
  let inputReport = DEFAULT_INPUT;
  let tablesDir = deriveTablesDir(DEFAULT_INPUT);
  let artifactName = deriveArtifactName(DEFAULT_INPUT);
  let finalRoot = DEFAULT_FINAL_ROOT;
  let status: Status = "candidate";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--input-report") {
      const raw = argv[++i];
      if (!raw) throw new Error("--input-report requires a value");
      inputReport = resolve(process.cwd(), raw);
      tablesDir = deriveTablesDir(inputReport);
      artifactName = deriveArtifactName(inputReport);
      continue;
    }
    if (arg === "--tables-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--tables-dir requires a value");
      tablesDir = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--artifact-name") {
      const raw = argv[++i];
      if (!raw) throw new Error("--artifact-name requires a value");
      artifactName = raw.trim();
      if (!artifactName) throw new Error("--artifact-name must not be empty");
      continue;
    }
    if (arg === "--final-root") {
      const raw = argv[++i];
      if (!raw) throw new Error("--final-root requires a value");
      finalRoot = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--status") {
      const raw = argv[++i];
      if (!raw) throw new Error("--status requires a value");
      if (raw !== "preliminary" && raw !== "candidate" && raw !== "final") {
        throw new Error("--status must be preliminary, candidate, or final");
      }
      status = raw;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { inputReport, tablesDir, artifactName, finalRoot, status };
}

function deriveTablesDir(inputReport: string): string {
  const file = basename(inputReport, ".json");
  if (file === "benchmark-report") {
    return join(dirname(inputReport), "tables");
  }
  if (file.startsWith("benchmark-report-")) {
    return join(dirname(inputReport), `tables-${file.replace("benchmark-report-", "")}`);
  }
  return join(dirname(inputReport), "tables");
}

function deriveArtifactName(inputReport: string): string {
  return basename(inputReport, ".json");
}

function parseReport(path: string): BenchmarkReport {
  return JSON.parse(readFileSync(path, "utf8")) as BenchmarkReport;
}

function ensureExists(path: string, label: string): void {
  if (!existsSync(path)) {
    throw new Error(`${label} does not exist: ${path}`);
  }
}

function hasFullBaselineLadder(report: BenchmarkReport): boolean {
  const names = new Set(report.reports.map((item) => item.engine));
  return BASELINE_LADDER_ENGINES.every((engine) => names.has(engine));
}

function formatMetric(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(3);
}

function writeFile(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

function buildManifest(
  report: BenchmarkReport,
  inputReport: string,
  tablesDir: string,
  artifactDir: string,
  status: Status,
): string {
  const lines: string[] = [];
  lines.push("# Artifact Manifest");
  lines.push("");
  lines.push(`Status: \`${status}\``);
  lines.push(`Packaged at: ${new Date().toISOString()}`);
  lines.push(`Source report: \`${inputReport}\``);
  lines.push(`Source tables dir: \`${tablesDir}\``);
  lines.push(`Output dir: \`${artifactDir}\``);
  lines.push(`Generated at: ${report.generatedAt}`);
  lines.push(`Loaded cases: ${report.totalLoadedCases}`);
  lines.push(`Engines: ${report.reports.map((item) => `\`${item.engine}\``).join(", ")}`);
  if (report.suiteFilter?.length) {
    lines.push(`Suites: ${report.suiteFilter.map((item) => `\`${item}\``).join(", ")}`);
  }
  if (report.scanner) {
    lines.push(
      `Scanner: mode=\`${report.scanner.mode}\`, model=\`${report.scanner.ollamaModel}\`, ollama timeout=\`${report.scanner.ollamaTimeoutMs}\` ms, temperature=\`${report.scanner.ollamaTemperature ?? "n/a"}\`, seed=\`${report.scanner.ollamaSeed ?? "n/a"}\`, plugin timeout=\`${report.scanner.pluginScannerTimeoutMs ?? "n/a"}\` ms, assisted=\`${report.scanner.modelAssistedCases}\``,
    );
  }
  lines.push("");
  lines.push("## Engine Summary");
  lines.push("");
  lines.push("| Engine | Executed | Passed | Failed | Accuracy | Precision | Recall | F1 | Attack BR | FPR |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const reportItem of report.reports) {
    const metrics = reportItem.summary.metrics;
    lines.push(
      `| ${reportItem.engine} | ${reportItem.summary.executed} | ${reportItem.summary.passed} | ${reportItem.summary.failed} | ${formatMetric(metrics?.accuracy ?? null)} | ${formatMetric(metrics?.precision ?? null)} | ${formatMetric(metrics?.recall ?? null)} | ${formatMetric(metrics?.f1 ?? null)} | ${formatMetric(metrics?.attackBlockRate ?? null)} | ${formatMetric(metrics?.falsePositiveRate ?? null)} |`,
    );
  }
  lines.push("");
  lines.push("## Notes");
  lines.push("");
  if (status !== "final") {
    lines.push("- This artifact is not yet designated as the canonical publication-ready result set.");
  }
  if (hasFullBaselineLadder(report)) {
    lines.push("- This artifact includes the full five-row baseline ladder and therefore ships `main-results-rows.tex` and `main-results-table.tex`.");
  } else {
    lines.push("- This artifact does not contain the full five-row baseline ladder.");
  }
  if (existsSync(join(tablesDir, "overhead-summary.md"))) {
    lines.push("- This artifact includes `overhead-summary.*` with preliminary harness-level latency / CPU / memory profiling.");
  }
  if (existsSync(join(tablesDir, "operational-metrics.md"))) {
    lines.push("- This artifact includes `operational-metrics.*` with component-level audit verification and policy reload timings.");
  }
  if (existsSync(join(artifactDir, "stability-check", "benchmark-comparison.md"))) {
    lines.push("- This artifact includes `stability-check/benchmark-comparison.*` documenting same-configuration rerun stability.");
  }
  lines.push("- Use `evaluation/promote-paper-results.ts` to promote a publication-ready artifact into `paper/generated/`.");
  return lines.join("\n") + "\n";
}

function copyIfExists(source: string, targetDir: string): void {
  if (existsSync(source)) {
    copyFileSync(source, join(targetDir, basename(source)));
  }
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  ensureExists(opts.inputReport, "input report");
  ensureExists(opts.tablesDir, "tables dir");

  const report = parseReport(opts.inputReport);
  const artifactDir = join(opts.finalRoot, opts.artifactName);
  mkdirSync(artifactDir, { recursive: true });

  copyFileSync(opts.inputReport, join(artifactDir, basename(opts.inputReport)));

  const standardFiles = [
    "benchmark-run-metadata.md",
    "benchmark-run-metadata.tex",
    "seed-engine-summary.md",
    "seed-engine-summary.tex",
    "seed-suite-breakdown.md",
    "seed-suite-breakdown.tex",
    "overhead-summary.md",
    "overhead-summary.tex",
    "operational-metrics.json",
    "operational-metrics.md",
    "operational-metrics.tex",
    "scanner-path-summary.md",
    "scanner-path-summary.tex",
  ];
  for (const file of standardFiles) {
    copyIfExists(join(opts.tablesDir, file), artifactDir);
  }

  if (hasFullBaselineLadder(report)) {
    copyIfExists(join(opts.tablesDir, "main-results-rows.tex"), artifactDir);
    copyIfExists(join(opts.tablesDir, "main-results-table.tex"), artifactDir);
  }

  writeFile(join(artifactDir, "artifact-manifest.md"), buildManifest(report, opts.inputReport, opts.tablesDir, artifactDir, opts.status));

  process.stdout.write(`[package-paper-artifact] wrote ${artifactDir}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[package-paper-artifact] ERROR ${message}\n`);
  process.exitCode = 1;
}
