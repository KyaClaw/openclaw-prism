import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type BinaryMetrics = {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  attackBlockRate: number | null;
  falsePositiveRate: number | null;
};

type CaseResult = {
  caseId: string;
  caseName: string;
  suite: string;
  engine: string;
  supported: boolean;
  passed: boolean | null;
  expectedClass: "attack" | "benign" | null;
  predictedClass: "attack" | "benign" | null;
  sourceFile: string;
  raw?: Record<string, unknown>;
};

type SuiteSummary = {
  suite: string;
  executed: number;
  passed: number;
  failed: number;
  skipped: number;
  metrics: BinaryMetrics | null;
};

type EngineReport = {
  engine: string;
  summary: {
    totalCases: number;
    executed: number;
    passed: number;
    failed: number;
    skipped: number;
    metrics: BinaryMetrics | null;
    profiling?: {
      wallTimeMs: number;
      avgCaseMs: number | null;
      p50CaseMs: number | null;
      p95CaseMs: number | null;
      p99CaseMs: number | null;
      cpuUserMs: number;
      cpuSystemMs: number;
      cpuTotalMs: number;
      avgCpuMsPerCase: number | null;
      peakRssDeltaMiB: number;
      endRssDeltaMiB: number;
    };
  };
  suites: SuiteSummary[];
  results: CaseResult[];
};

type BenchmarkReport = {
  generatedAt: string;
  outputPath: string;
  totalLoadedCases: number;
  suiteFilter?: string[] | null;
  scanner?: {
    mode: "default" | "mock" | "live";
    requireAssistedPath: boolean;
    ollamaUrl: string;
    ollamaModel: string;
    ollamaTimeoutMs: number;
    ollamaTemperature?: number | null;
    ollamaSeed?: number | null;
    pluginScannerTimeoutMs?: number;
    mockAnnotatedCases: number;
    modelAssistedCases: number;
  } | null;
  reports: EngineReport[];
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const DEFAULT_INPUT = join(EVAL_ROOT, "results", "benchmark-report.json");
const DEFAULT_OUTPUT_DIR = join(EVAL_ROOT, "results", "tables");
const BASELINE_LADDER_ENGINES = [
  "no-prism",
  "heuristics-only",
  "plugin-only",
  "plugin-scanner",
  "full-prism",
] as const;
const BASELINE_LADDER_LABELS: Record<(typeof BASELINE_LADDER_ENGINES)[number], string> = {
  "no-prism": "No PRISM",
  "heuristics-only": "Heuristics only",
  "plugin-only": "Plugin only",
  "plugin-scanner": "Plugin + scanner",
  "full-prism": "Full PRISM",
};

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/results-to-table.ts [--input <path>] [--output-dir <path>]",
    "",
    "Outputs:",
    "  benchmark-run-metadata.md",
    "  benchmark-run-metadata.tex",
    "  seed-engine-summary.md",
    "  seed-engine-summary.tex",
    "  seed-suite-breakdown.md",
    "  seed-suite-breakdown.tex",
    "  overhead-summary.md",
    "  overhead-summary.tex",
    "  main-results-rows.tex (when all baseline-ladder engines are present)",
    "  main-results-table.tex (when all baseline-ladder engines are present)",
  ].join("\n");
}

function parseArgs(argv: string[]): { inputPath: string; outputDir: string } {
  let inputPath = DEFAULT_INPUT;
  let outputDir = DEFAULT_OUTPUT_DIR;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--input") {
      const raw = argv[++i];
      if (!raw) throw new Error("--input requires a value");
      inputPath = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--output-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--output-dir requires a value");
      outputDir = resolve(process.cwd(), raw);
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { inputPath, outputDir };
}

function parseReport(path: string): BenchmarkReport {
  const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`expected JSON object in ${path}`);
  }
  return raw as BenchmarkReport;
}

function formatMetric(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(3);
}

function latexMetric(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(3);
}

function latexEscape(input: string): string {
  return input
    .replace(/\\/g, "\\textbackslash{}")
    .replace(/&/g, "\\&")
    .replace(/%/g, "\\%")
    .replace(/\$/g, "\\$")
    .replace(/#/g, "\\#")
    .replace(/_/g, "\\_")
    .replace(/{/g, "\\{")
    .replace(/}/g, "\\}")
    .replace(/~/g, "\\textasciitilde{}")
    .replace(/\^/g, "\\textasciicircum{}");
}

function collectFailures(report: BenchmarkReport): EngineFailureGroup[] {
  return report.reports.map((engineReport) => ({
    engine: engineReport.engine,
    failures: engineReport.results.filter((result) => result.supported && result.passed === false),
  }));
}

type EngineFailureGroup = {
  engine: string;
  failures: CaseResult[];
};

function buildEngineSummaryMarkdown(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("# Seed Engine Summary");
  lines.push("");
  lines.push(`Generated from \`${report.outputPath}\` on ${report.generatedAt}.`);
  if (report.suiteFilter?.length) {
    lines.push("");
    lines.push(`Suites: \`${report.suiteFilter.join(", ")}\``);
  }
  if (report.scanner) {
    lines.push("");
    lines.push(
      `Scanner mode: \`${report.scanner.mode}\` | model: \`${report.scanner.ollamaModel}\` | ollama timeout: \`${report.scanner.ollamaTimeoutMs}\` ms | plugin scanner timeout: \`${report.scanner.pluginScannerTimeoutMs ?? "n/a"}\` ms | assisted cases: \`${report.scanner.modelAssistedCases}\``,
    );
    if (report.scanner.ollamaTemperature !== null && report.scanner.ollamaTemperature !== undefined) {
      lines[lines.length - 1] += ` | temperature: \`${report.scanner.ollamaTemperature}\``;
    }
    if (report.scanner.ollamaSeed !== null && report.scanner.ollamaSeed !== undefined) {
      lines[lines.length - 1] += ` | seed: \`${report.scanner.ollamaSeed}\``;
    }
  }
  lines.push("");
  lines.push("| Engine | Executed | Passed | Failed | Skipped | Accuracy | Precision | Recall | F1 | Attack BR | FPR |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");

  for (const engine of report.reports) {
    const metrics = engine.summary.metrics;
    lines.push(
      `| ${engine.engine} | ${engine.summary.executed} | ${engine.summary.passed} | ${engine.summary.failed} | ${engine.summary.skipped} | ${formatMetric(metrics?.accuracy ?? null)} | ${formatMetric(metrics?.precision ?? null)} | ${formatMetric(metrics?.recall ?? null)} | ${formatMetric(metrics?.f1 ?? null)} | ${formatMetric(metrics?.attackBlockRate ?? null)} | ${formatMetric(metrics?.falsePositiveRate ?? null)} |`,
    );
  }

  const failures = collectFailures(report);
  if (failures.some((group) => group.failures.length > 0)) {
    lines.push("");
    lines.push("## Failing Cases");
    lines.push("");
    for (const group of failures) {
      if (group.failures.length === 0) continue;
      lines.push(`### ${group.engine}`);
      lines.push("");
      for (const failure of group.failures) {
        lines.push(
          `- \`${failure.suite}\` / \`${failure.caseName}\`: expected \`${failure.expectedClass}\`, predicted \`${failure.predictedClass}\``,
        );
      }
      lines.push("");
    }
  }

  return lines.join("\n") + "\n";
}

function buildSuiteBreakdownMarkdown(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("# Seed Suite Breakdown");
  lines.push("");
  lines.push(`Generated from \`${report.outputPath}\` on ${report.generatedAt}.`);
  if (report.suiteFilter?.length) {
    lines.push("");
    lines.push(`Suites: \`${report.suiteFilter.join(", ")}\``);
  }
  if (report.scanner) {
    lines.push("");
    lines.push(
      `Scanner mode: \`${report.scanner.mode}\` | assisted cases: \`${report.scanner.modelAssistedCases}\` | mock-annotated cases: \`${report.scanner.mockAnnotatedCases}\` | plugin scanner timeout: \`${report.scanner.pluginScannerTimeoutMs ?? "n/a"}\` ms`,
    );
    if (report.scanner.ollamaTemperature !== null && report.scanner.ollamaTemperature !== undefined) {
      lines[lines.length - 1] += ` | temperature: \`${report.scanner.ollamaTemperature}\``;
    }
    if (report.scanner.ollamaSeed !== null && report.scanner.ollamaSeed !== undefined) {
      lines[lines.length - 1] += ` | seed: \`${report.scanner.ollamaSeed}\``;
    }
  }
  lines.push("");

  for (const engine of report.reports) {
    lines.push(`## ${engine.engine}`);
    lines.push("");
    lines.push("| Suite | Executed | Passed | Failed | Skipped | Accuracy | FPR |");
    lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (const suite of engine.suites) {
      lines.push(
        `| ${suite.suite} | ${suite.executed} | ${suite.passed} | ${suite.failed} | ${suite.skipped} | ${formatMetric(suite.metrics?.accuracy ?? null)} | ${formatMetric(suite.metrics?.falsePositiveRate ?? null)} |`,
      );
    }
    lines.push("");
  }

  return lines.join("\n") + "\n";
}

function buildEngineSummaryLatex(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\footnotesize");
  lines.push("\\begin{tabular}{lrrrrrrrrrr}");
  lines.push("\\toprule");
  lines.push("Engine & Exec. & Pass & Fail & Skip & Acc. & Prec. & Rec. & F1 & Atk. BR & FPR \\\\");
  lines.push("\\midrule");

  for (const engine of report.reports) {
    const metrics = engine.summary.metrics;
    lines.push(
      `${latexEscape(engine.engine)} & ${engine.summary.executed} & ${engine.summary.passed} & ${engine.summary.failed} & ${engine.summary.skipped} & ${latexMetric(metrics?.accuracy ?? null)} & ${latexMetric(metrics?.precision ?? null)} & ${latexMetric(metrics?.recall ?? null)} & ${latexMetric(metrics?.f1 ?? null)} & ${latexMetric(metrics?.attackBlockRate ?? null)} & ${latexMetric(metrics?.falsePositiveRate ?? null)} \\\\`,
    );
  }

  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\caption{Seeded artifact-validation results by engine. This table is suitable for the current preliminary evaluation stage and should not be presented as the final end-to-end PRISM comparison.}");
  lines.push("\\label{tab:seed-engine-summary}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

function buildSuiteBreakdownLatex(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("\\begin{longtable}{llrrrrrr}");
  lines.push("\\caption{Per-suite seeded results by engine. Unsupported suites remain visible through the skipped column, making partial engine coverage explicit during the artifact-validation stage.}\\\\");
  lines.push("\\toprule");
  lines.push("Engine & Suite & Exec. & Pass & Fail & Skip & Acc. & FPR \\\\");
  lines.push("\\midrule");
  lines.push("\\endfirsthead");
  lines.push("\\toprule");
  lines.push("Engine & Suite & Exec. & Pass & Fail & Skip & Acc. & FPR \\\\");
  lines.push("\\midrule");
  lines.push("\\endhead");

  for (const engine of report.reports) {
    for (const suite of engine.suites) {
      lines.push(
        `${latexEscape(engine.engine)} & ${latexEscape(suite.suite)} & ${suite.executed} & ${suite.passed} & ${suite.failed} & ${suite.skipped} & ${latexMetric(suite.metrics?.accuracy ?? null)} & ${latexMetric(suite.metrics?.falsePositiveRate ?? null)} \\\\`,
      );
    }
  }

  lines.push("\\bottomrule");
  lines.push("\\end{longtable}");
  lines.push("");
  return lines.join("\n");
}

function buildScannerPathMarkdown(report: BenchmarkReport): string {
  const scanner = report.reports.find((item) => item.engine === "scanner");
  const lines: string[] = [];
  lines.push("# Scanner Path Summary");
  lines.push("");
  lines.push(`Generated from \`${report.outputPath}\` on ${report.generatedAt}.`);
  if (report.scanner) {
    lines.push("");
    lines.push(
      `Scanner mode: \`${report.scanner.mode}\` | model: \`${report.scanner.ollamaModel}\` | ollama timeout: \`${report.scanner.ollamaTimeoutMs}\` ms | plugin scanner timeout: \`${report.scanner.pluginScannerTimeoutMs ?? "n/a"}\` ms | require-assisted-path: \`${report.scanner.requireAssistedPath}\``,
    );
    if (report.scanner.ollamaTemperature !== null && report.scanner.ollamaTemperature !== undefined) {
      lines[lines.length - 1] += ` | temperature: \`${report.scanner.ollamaTemperature}\``;
    }
    if (report.scanner.ollamaSeed !== null && report.scanner.ollamaSeed !== undefined) {
      lines[lines.length - 1] += ` | seed: \`${report.scanner.ollamaSeed}\``;
    }
  }
  lines.push("");

  if (!scanner) {
    lines.push("No standalone scanner engine report found.");
    if (report.scanner) {
      lines.push("");
      lines.push(
        `Run-level metadata still records \`${report.scanner.modelAssistedCases}\` model-assisted cases, which may come from plugin-scanner or full-prism paths even when the standalone \`scanner\` engine was not part of this report.`,
      );
    }
    return lines.join("\n") + "\n";
  }

  const supported = scanner.results.filter((result) => result.supported);
  const counts = new Map<string, number>();
  for (const result of supported) {
    const path = typeof result.raw?.path === "string" ? result.raw.path : "unknown";
    counts.set(path, (counts.get(path) ?? 0) + 1);
  }

  lines.push("| Scanner path | Cases |");
  lines.push("| --- | ---: |");
  for (const [path, count] of [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    lines.push(`| ${path} | ${count} |`);
  }

  const modelUsedCases = supported.filter((result) => result.raw?.modelUsed === true);
  lines.push("");
  lines.push(`Model-assisted cases: ${modelUsedCases.length}`);

  return lines.join("\n") + "\n";
}

function buildScannerPathLatex(report: BenchmarkReport): string {
  const scanner = report.reports.find((item) => item.engine === "scanner");
  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\footnotesize");
  lines.push("\\begin{tabular}{lr}");
  lines.push("\\toprule");
  lines.push("Scanner path & Cases \\\\");
  lines.push("\\midrule");

    if (scanner) {
      const supported = scanner.results.filter((result) => result.supported);
      const counts = new Map<string, number>();
      for (const result of supported) {
        const path = typeof result.raw?.path === "string" ? result.raw.path : "unknown";
        counts.set(path, (counts.get(path) ?? 0) + 1);
      }
      for (const [path, count] of [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))) {
        lines.push(`${latexEscape(path)} & ${count} \\\\`);
      }
    } else {
      lines.push("standalone scanner report missing & 0 \\\\");
    }

  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\caption{Execution-path breakdown for the scanner engine. This makes it explicit whether seeded cases were resolved by heuristic short-circuiting, model-assisted classification, or heuristic fallback.}");
  lines.push("\\label{tab:scanner-path-summary}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

function buildRunMetadataMarkdown(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("# Benchmark Run Metadata");
  lines.push("");
  lines.push(`Generated from \`${report.outputPath}\` on ${report.generatedAt}.`);
  lines.push("");
  lines.push(`Total loaded cases: ${report.totalLoadedCases}`);
  lines.push("");
  if (!report.scanner) {
    lines.push("Scanner engine not enabled in this report.");
    return lines.join("\n") + "\n";
  }

  lines.push("| Field | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Scanner mode | \`${report.scanner.mode}\` |`);
  lines.push(`| Ollama model | \`${report.scanner.ollamaModel}\` |`);
  lines.push(`| Ollama URL | \`${report.scanner.ollamaUrl}\` |`);
  lines.push(`| Ollama timeout (ms) | ${report.scanner.ollamaTimeoutMs} |`);
  lines.push(`| Ollama temperature | ${report.scanner.ollamaTemperature ?? "n/a"} |`);
  lines.push(`| Ollama seed | ${report.scanner.ollamaSeed ?? "n/a"} |`);
  lines.push(`| Plugin scanner timeout (ms) | ${report.scanner.pluginScannerTimeoutMs ?? "n/a"} |`);
  lines.push(`| Require assisted path | \`${report.scanner.requireAssistedPath}\` |`);
  lines.push(`| Cases with embedded scannerMock | ${report.scanner.mockAnnotatedCases} |`);
  lines.push(`| Cases that actually used model-assisted path | ${report.scanner.modelAssistedCases} |`);
  return lines.join("\n") + "\n";
}

function buildRunMetadataLatex(report: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\footnotesize");
  lines.push("\\begin{tabular}{ll}");
  lines.push("\\toprule");
  lines.push("Field & Value \\\\");
  lines.push("\\midrule");
  lines.push(`Total loaded cases & ${report.totalLoadedCases} \\\\`);
    if (report.scanner) {
      lines.push(`Scanner mode & ${latexEscape(report.scanner.mode)} \\\\`);
      lines.push(`Ollama model & ${latexEscape(report.scanner.ollamaModel)} \\\\`);
      lines.push(`Ollama timeout (ms) & ${report.scanner.ollamaTimeoutMs} \\\\`);
      lines.push(`Ollama temperature & ${report.scanner.ollamaTemperature ?? "n/a"} \\\\`);
      lines.push(`Ollama seed & ${report.scanner.ollamaSeed ?? "n/a"} \\\\`);
      lines.push(`Plugin scanner timeout (ms) & ${report.scanner.pluginScannerTimeoutMs ?? "n/a"} \\\\`);
      lines.push(`Require assisted path & ${report.scanner.requireAssistedPath ? "true" : "false"} \\\\`);
    lines.push(`Embedded scannerMock cases & ${report.scanner.mockAnnotatedCases} \\\\`);
    lines.push(`Model-assisted cases & ${report.scanner.modelAssistedCases} \\\\`);
  } else {
    lines.push("Scanner engine & not enabled \\\\");
  }
  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\caption{Run-level metadata for one benchmark report. This is useful for distinguishing default, mock-assisted, and live-model scanner runs.}");
  lines.push("\\label{tab:benchmark-run-metadata}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

function buildOverheadSummaryMarkdown(report: BenchmarkReport): string {
  const ladder = getBaselineLadderReports(report) ?? report.reports;
  const lines: string[] = [];
  lines.push("# Preliminary Overhead Summary");
  lines.push("");
  lines.push(`Generated from \`${report.outputPath}\` on ${report.generatedAt}.`);
  lines.push("");
  lines.push("These measurements are harness-level profiling signals, not final deployment-grade overhead numbers.");
  lines.push("");
  lines.push("| Engine | p50 ms | p95 ms | p99 ms | CPU ms / case | Peak RSS delta MiB | Wall ms total |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const engine of ladder) {
    const profiling = engine.summary.profiling;
    lines.push(
      `| ${engine.engine} | ${formatMetric(profiling?.p50CaseMs ?? null)} | ${formatMetric(profiling?.p95CaseMs ?? null)} | ${formatMetric(profiling?.p99CaseMs ?? null)} | ${formatMetric(profiling?.avgCpuMsPerCase ?? null)} | ${profiling ? profiling.peakRssDeltaMiB.toFixed(3) : "n/a"} | ${profiling ? profiling.wallTimeMs.toFixed(3) : "n/a"} |`,
    );
  }
  lines.push("");
  return lines.join("\n") + "\n";
}

function buildOverheadSummaryLatex(report: BenchmarkReport): string {
  const ladder = getBaselineLadderReports(report) ?? report.reports;
  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\footnotesize");
  lines.push("\\begin{tabularx}{\\textwidth}{l c c c c c c}");
  lines.push("\\toprule");
  lines.push("Engine & p50 ms & p95 ms & p99 ms & CPU ms / case & Peak RSS $\\Delta$ MiB & Wall ms total \\\\");
  lines.push("\\midrule");
  for (const engine of ladder) {
    const profiling = engine.summary.profiling;
    lines.push(
      `${latexEscape(engine.engine)} & ${latexMetric(profiling?.p50CaseMs ?? null)} & ${latexMetric(profiling?.p95CaseMs ?? null)} & ${latexMetric(profiling?.p99CaseMs ?? null)} & ${latexMetric(profiling?.avgCpuMsPerCase ?? null)} & ${profiling ? profiling.peakRssDeltaMiB.toFixed(3) : "n/a"} & ${profiling ? profiling.wallTimeMs.toFixed(3) : "n/a"} \\\\`,
    );
  }
  lines.push("\\bottomrule");
  lines.push("\\end{tabularx}");
  lines.push("\\caption{Preliminary harness-level overhead profile derived from benchmark execution. These measurements quantify benchmark-path latency and resource cost, but they are not yet substitutes for deployment-level end-to-end overhead measurements.}");
  lines.push("\\label{tab:prelim-overhead-summary}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

function getBaselineLadderReports(
  report: BenchmarkReport,
): EngineReport[] | null {
  const byEngine = new Map(report.reports.map((item) => [item.engine, item] as const));
  const ladder = BASELINE_LADDER_ENGINES.map((engine) => byEngine.get(engine) ?? null);
  return ladder.every((item) => item !== null) ? (ladder as EngineReport[]) : null;
}

function buildMainResultsRowsLatex(report: BenchmarkReport): string {
  const ladder = getBaselineLadderReports(report);
  if (!ladder) {
    return "";
  }

  const lines: string[] = [];
  for (const engine of ladder) {
    const metrics = engine.summary.metrics;
    const label = BASELINE_LADDER_LABELS[engine.engine as keyof typeof BASELINE_LADDER_LABELS];
    lines.push(
      `${label} & ${latexMetric(metrics?.attackBlockRate ?? null)} & ${latexMetric(metrics?.falsePositiveRate ?? null)} & ${latexMetric(metrics?.precision ?? null)} & ${latexMetric(metrics?.recall ?? null)} & ${latexMetric(metrics?.f1 ?? null)} \\\\`,
    );
  }
  return lines.join("\n") + "\n";
}

function buildMainResultsTableLatex(report: BenchmarkReport): string {
  const ladder = getBaselineLadderReports(report);
  if (!ladder) {
    return "";
  }

  const suiteText = report.suiteFilter?.length ? report.suiteFilter.map(latexEscape).join(", ") : "all loaded suites";
  const scannerMode = report.scanner?.mode ?? "unspecified";
  const liveNote =
    report.scanner?.mode === "live" && report.scanner?.ollamaModel
      ? ` using \\texttt{${latexEscape(report.scanner.ollamaModel)}}`
      : "";

  const lines: string[] = [];
  lines.push("\\begin{table}[t]");
  lines.push("\\centering");
  lines.push("\\small");
  lines.push("\\begin{tabularx}{\\textwidth}{l c c c c c}");
  lines.push("\\toprule");
  lines.push("Configuration & Attack block rate & False positive rate & Precision & Recall & F1 \\\\");
  lines.push("\\midrule");
  lines.push(buildMainResultsRowsLatex(report).trimEnd());
  lines.push("\\bottomrule");
  lines.push("\\end{tabularx}");
  lines.push(
    `\\caption{Generated baseline-ladder results for the suites ${suiteText} under scanner mode \\texttt{${latexEscape(scannerMode)}}${liveNote}. This fragment is intended to replace paper-side placeholders once the underlying artifact is judged publication-ready.}`,
  );
  lines.push("\\label{tab:generated-main-results}");
  lines.push("\\end{table}");
  lines.push("");
  return lines.join("\n");
}

function writeOutput(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const report = parseReport(opts.inputPath);
  mkdirSync(opts.outputDir, { recursive: true });

  const outputs = [
    {
      path: join(opts.outputDir, "benchmark-run-metadata.md"),
      contents: buildRunMetadataMarkdown(report),
    },
    {
      path: join(opts.outputDir, "benchmark-run-metadata.tex"),
      contents: buildRunMetadataLatex(report),
    },
    {
      path: join(opts.outputDir, "seed-engine-summary.md"),
      contents: buildEngineSummaryMarkdown(report),
    },
    {
      path: join(opts.outputDir, "seed-engine-summary.tex"),
      contents: buildEngineSummaryLatex(report),
    },
    {
      path: join(opts.outputDir, "seed-suite-breakdown.md"),
      contents: buildSuiteBreakdownMarkdown(report),
    },
    {
      path: join(opts.outputDir, "seed-suite-breakdown.tex"),
      contents: buildSuiteBreakdownLatex(report),
    },
    {
      path: join(opts.outputDir, "overhead-summary.md"),
      contents: buildOverheadSummaryMarkdown(report),
    },
    {
      path: join(opts.outputDir, "overhead-summary.tex"),
      contents: buildOverheadSummaryLatex(report),
    },
    {
      path: join(opts.outputDir, "scanner-path-summary.md"),
      contents: buildScannerPathMarkdown(report),
    },
    {
      path: join(opts.outputDir, "scanner-path-summary.tex"),
      contents: buildScannerPathLatex(report),
    },
  ];

  const mainRows = buildMainResultsRowsLatex(report);
  if (mainRows) {
    outputs.push(
      {
        path: join(opts.outputDir, "main-results-rows.tex"),
        contents: mainRows,
      },
      {
        path: join(opts.outputDir, "main-results-table.tex"),
        contents: buildMainResultsTableLatex(report),
      },
    );
  }

  for (const output of outputs) {
    writeOutput(output.path, output.contents);
    process.stdout.write(`[results-to-table] wrote ${output.path}\n`);
  }
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[results-to-table] ERROR ${message}\n`);
  process.exitCode = 1;
}
