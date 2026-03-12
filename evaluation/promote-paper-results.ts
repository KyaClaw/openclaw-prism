import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
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
  reports: Array<{ engine: string }>;
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(EVAL_ROOT, "..");
const DEFAULT_INPUT = join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-live.json");
const DEFAULT_TABLES_DIR = join(EVAL_ROOT, "results", "tables-baseline-ladder-live");
const DEFAULT_PAPER_GENERATED_DIR = join(REPO_ROOT, "paper", "generated");

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/promote-paper-results.ts [--input-report <path>] [--tables-dir <path>] [--paper-generated-dir <path>] [--promote-prefix <prefix>] [--allow-preliminary]",
    "",
    "Behavior:",
    "  Copies main-results-rows.tex and main-results-table.tex into paper/generated/",
    "  and writes a provenance note alongside them.",
    "",
    "Safety:",
    "  Promoting to the default manuscript filenames requires either a report under",
    "  evaluation/results/final/ or the explicit --allow-preliminary flag.",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  inputReport: string;
  tablesDir: string;
  paperGeneratedDir: string;
  promotePrefix: string;
  allowPreliminary: boolean;
} {
  let inputReport = DEFAULT_INPUT;
  let tablesDir = DEFAULT_TABLES_DIR;
  let paperGeneratedDir = DEFAULT_PAPER_GENERATED_DIR;
  let promotePrefix = "main-results";
  let allowPreliminary = false;

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
      continue;
    }
    if (arg === "--tables-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--tables-dir requires a value");
      tablesDir = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--paper-generated-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--paper-generated-dir requires a value");
      paperGeneratedDir = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--promote-prefix") {
      const raw = argv[++i];
      if (!raw) throw new Error("--promote-prefix requires a value");
      promotePrefix = raw.trim();
      if (!promotePrefix) throw new Error("--promote-prefix must not be empty");
      continue;
    }
    if (arg === "--allow-preliminary") {
      allowPreliminary = true;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return {
    inputReport,
    tablesDir,
    paperGeneratedDir,
    promotePrefix,
    allowPreliminary,
  };
}

function parseReport(path: string): BenchmarkReport {
  return JSON.parse(readFileSync(path, "utf8")) as BenchmarkReport;
}

function ensureExists(path: string, label: string): void {
  if (!existsSync(path)) {
    throw new Error(`${label} does not exist: ${path}`);
  }
}

function normalizeForCheck(path: string): string {
  return normalize(path).replace(/\\/g, "/").toLowerCase();
}

function isFinalArtifact(path: string): boolean {
  return normalizeForCheck(path).includes("/evaluation/results/final/");
}

function writeFile(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

function buildProvenance(
  reportPath: string,
  report: BenchmarkReport,
  promotePrefix: string,
  allowPreliminary: boolean,
): string {
  const lines: string[] = [];
  lines.push("# Promoted Paper Results");
  lines.push("");
  lines.push(`Prefix: \`${promotePrefix}\``);
  lines.push(`Source report: \`${reportPath}\``);
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
  lines.push(`Preliminary override used: \`${allowPreliminary}\``);
  lines.push("");
  lines.push("This file was created by `evaluation/promote-paper-results.ts`.");
  return lines.join("\n") + "\n";
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const report = parseReport(opts.inputReport);

  const sourceRows = join(opts.tablesDir, "main-results-rows.tex");
  const sourceTable = join(opts.tablesDir, "main-results-table.tex");
  ensureExists(opts.inputReport, "input report");
  ensureExists(sourceRows, "generated rows fragment");
  ensureExists(sourceTable, "generated table fragment");

  const wantsCanonicalTarget = opts.promotePrefix === "main-results";
  if (wantsCanonicalTarget && !opts.allowPreliminary && !isFinalArtifact(opts.inputReport)) {
    throw new Error(
      "refusing to promote a non-final artifact into paper/generated/main-results-*. Use --allow-preliminary or write the final report under evaluation/results/final/.",
    );
  }

  mkdirSync(opts.paperGeneratedDir, { recursive: true });

  const targetRows = join(opts.paperGeneratedDir, `${opts.promotePrefix}-rows.tex`);
  const targetTable = join(opts.paperGeneratedDir, `${opts.promotePrefix}-table.tex`);
  const targetSource = join(opts.paperGeneratedDir, `${opts.promotePrefix}-source.md`);

  copyFileSync(sourceRows, targetRows);
  copyFileSync(sourceTable, targetTable);
  writeFile(targetSource, buildProvenance(opts.inputReport, report, opts.promotePrefix, opts.allowPreliminary));

  process.stdout.write(`[promote-paper-results] wrote ${targetRows}\n`);
  process.stdout.write(`[promote-paper-results] wrote ${targetTable}\n`);
  process.stdout.write(`[promote-paper-results] wrote ${targetSource}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[promote-paper-results] ERROR ${message}\n`);
  process.exitCode = 1;
}
