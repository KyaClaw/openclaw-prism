import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type BinaryMetrics = {
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
};

type EngineReport = {
  engine: string;
  summary: {
    executed: number;
    passed: number;
    failed: number;
    skipped: number;
    metrics: BinaryMetrics | null;
  };
  results: CaseResult[];
};

type BenchmarkReport = {
  generatedAt: string;
  outputPath: string;
  totalLoadedCases: number;
  suiteFilter?: string[] | null;
  scanner?: {
    mode: "default" | "mock" | "live";
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

type EngineMetricDelta = {
  engine: string;
  base: EngineReport["summary"];
  candidate: EngineReport["summary"];
  deltas: {
    executed: number;
    passed: number;
    failed: number;
    skipped: number;
    accuracy: number | null;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    attackBlockRate: number | null;
    falsePositiveRate: number | null;
  };
};

type CaseDelta = {
  engine: string;
  caseId: string;
  caseName: string;
  suite: string;
  basePassed: boolean | null;
  candidatePassed: boolean | null;
  basePredicted: "attack" | "benign" | null;
  candidatePredicted: "attack" | "benign" | null;
};

type ComparisonSummary = {
  basePath: string;
  candidatePath: string;
  generatedAt: string;
  topLevel: {
    totalLoadedCasesChanged: boolean;
    suiteFilterChanged: boolean;
    scannerChanged: boolean;
  };
  engineMetricDeltas: EngineMetricDelta[];
  caseDeltas: CaseDelta[];
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const DEFAULT_BASE = join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-live.json");
const DEFAULT_CANDIDATE = join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-live-rerun.json");
const DEFAULT_OUTPUT_DIR = join(EVAL_ROOT, "results", "comparisons", "baseline-ladder-live");

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/compare-benchmark-reports.ts [--base <path>] [--candidate <path>] [--output-dir <path>]",
    "",
    "Outputs:",
    "  benchmark-comparison.md",
    "  benchmark-comparison.json",
  ].join("\n");
}

function parseArgs(argv: string[]): { basePath: string; candidatePath: string; outputDir: string } {
  let basePath = DEFAULT_BASE;
  let candidatePath = DEFAULT_CANDIDATE;
  let outputDir = DEFAULT_OUTPUT_DIR;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--base") {
      const raw = argv[++i];
      if (!raw) throw new Error("--base requires a value");
      basePath = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--candidate") {
      const raw = argv[++i];
      if (!raw) throw new Error("--candidate requires a value");
      candidatePath = resolve(process.cwd(), raw);
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

  return { basePath, candidatePath, outputDir };
}

function parseReport(path: string): BenchmarkReport {
  return JSON.parse(readFileSync(path, "utf8")) as BenchmarkReport;
}

function metricDelta(base: number | null, candidate: number | null): number | null {
  if (base === null || candidate === null) return null;
  return Number((candidate - base).toFixed(6));
}

function compareReports(base: BenchmarkReport, candidate: BenchmarkReport, basePath: string, candidatePath: string): ComparisonSummary {
  const baseByEngine = new Map(base.reports.map((item) => [item.engine, item] as const));
  const candidateByEngine = new Map(candidate.reports.map((item) => [item.engine, item] as const));
  const allEngines = [...new Set([...baseByEngine.keys(), ...candidateByEngine.keys()])].sort();

  const engineMetricDeltas: EngineMetricDelta[] = [];
  const caseDeltas: CaseDelta[] = [];

  for (const engine of allEngines) {
    const baseEngine = baseByEngine.get(engine);
    const candidateEngine = candidateByEngine.get(engine);
    if (!baseEngine || !candidateEngine) continue;

    engineMetricDeltas.push({
      engine,
      base: baseEngine.summary,
      candidate: candidateEngine.summary,
      deltas: {
        executed: candidateEngine.summary.executed - baseEngine.summary.executed,
        passed: candidateEngine.summary.passed - baseEngine.summary.passed,
        failed: candidateEngine.summary.failed - baseEngine.summary.failed,
        skipped: candidateEngine.summary.skipped - baseEngine.summary.skipped,
        accuracy: metricDelta(baseEngine.summary.metrics?.accuracy ?? null, candidateEngine.summary.metrics?.accuracy ?? null),
        precision: metricDelta(baseEngine.summary.metrics?.precision ?? null, candidateEngine.summary.metrics?.precision ?? null),
        recall: metricDelta(baseEngine.summary.metrics?.recall ?? null, candidateEngine.summary.metrics?.recall ?? null),
        f1: metricDelta(baseEngine.summary.metrics?.f1 ?? null, candidateEngine.summary.metrics?.f1 ?? null),
        attackBlockRate: metricDelta(baseEngine.summary.metrics?.attackBlockRate ?? null, candidateEngine.summary.metrics?.attackBlockRate ?? null),
        falsePositiveRate: metricDelta(baseEngine.summary.metrics?.falsePositiveRate ?? null, candidateEngine.summary.metrics?.falsePositiveRate ?? null),
      },
    });

    const baseCases = new Map(baseEngine.results.map((item) => [item.caseId, item] as const));
    const candidateCases = new Map(candidateEngine.results.map((item) => [item.caseId, item] as const));
    const caseIds = [...new Set([...baseCases.keys(), ...candidateCases.keys()])].sort();
    for (const caseId of caseIds) {
      const left = baseCases.get(caseId);
      const right = candidateCases.get(caseId);
      if (!left || !right) continue;
      if (left.passed !== right.passed || left.predictedClass !== right.predictedClass) {
        caseDeltas.push({
          engine,
          caseId,
          caseName: right.caseName,
          suite: right.suite,
          basePassed: left.passed,
          candidatePassed: right.passed,
          basePredicted: left.predictedClass,
          candidatePredicted: right.predictedClass,
        });
      }
    }
  }

  const suiteFilterBase = JSON.stringify(base.suiteFilter ?? null);
  const suiteFilterCandidate = JSON.stringify(candidate.suiteFilter ?? null);
  const scannerBase = JSON.stringify(base.scanner ?? null);
  const scannerCandidate = JSON.stringify(candidate.scanner ?? null);

  return {
    basePath,
    candidatePath,
    generatedAt: new Date().toISOString(),
    topLevel: {
      totalLoadedCasesChanged: base.totalLoadedCases !== candidate.totalLoadedCases,
      suiteFilterChanged: suiteFilterBase !== suiteFilterCandidate,
      scannerChanged: scannerBase !== scannerCandidate,
    },
    engineMetricDeltas,
    caseDeltas,
  };
}

function formatMetric(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(3);
}

function formatDelta(value: number | null): string {
  if (value === null) return "n/a";
  if (value === 0) return "0.000";
  return `${value > 0 ? "+" : ""}${value.toFixed(3)}`;
}

function buildMarkdown(summary: ComparisonSummary, base: BenchmarkReport, candidate: BenchmarkReport): string {
  const lines: string[] = [];
  lines.push("# Benchmark Comparison");
  lines.push("");
  lines.push(`Generated at: ${summary.generatedAt}`);
  lines.push(`Base: \`${summary.basePath}\``);
  lines.push(`Candidate: \`${summary.candidatePath}\``);
  lines.push("");
  lines.push("## Top-Level Checks");
  lines.push("");
  lines.push(`- Total loaded cases changed: \`${summary.topLevel.totalLoadedCasesChanged}\``);
  lines.push(`- Suite filter changed: \`${summary.topLevel.suiteFilterChanged}\``);
  lines.push(`- Scanner metadata changed: \`${summary.topLevel.scannerChanged}\``);
  lines.push("");
  if (base.scanner || candidate.scanner) {
    lines.push("### Scanner Metadata");
    lines.push("");
    lines.push(`- Base: \`${JSON.stringify(base.scanner ?? null)}\``);
    lines.push(`- Candidate: \`${JSON.stringify(candidate.scanner ?? null)}\``);
    lines.push("");
  }

  lines.push("## Engine Metric Deltas");
  lines.push("");
  lines.push("| Engine | Passed | Failed | Accuracy | Precision | Recall | F1 | Attack BR | FPR |");
  lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
  for (const delta of summary.engineMetricDeltas) {
    lines.push(
      `| ${delta.engine} | ${delta.base.passed} -> ${delta.candidate.passed} (${delta.deltas.passed >= 0 ? "+" : ""}${delta.deltas.passed}) | ${delta.base.failed} -> ${delta.candidate.failed} (${delta.deltas.failed >= 0 ? "+" : ""}${delta.deltas.failed}) | ${formatMetric(delta.base.metrics?.accuracy ?? null)} -> ${formatMetric(delta.candidate.metrics?.accuracy ?? null)} (${formatDelta(delta.deltas.accuracy)}) | ${formatMetric(delta.base.metrics?.precision ?? null)} -> ${formatMetric(delta.candidate.metrics?.precision ?? null)} (${formatDelta(delta.deltas.precision)}) | ${formatMetric(delta.base.metrics?.recall ?? null)} -> ${formatMetric(delta.candidate.metrics?.recall ?? null)} (${formatDelta(delta.deltas.recall)}) | ${formatMetric(delta.base.metrics?.f1 ?? null)} -> ${formatMetric(delta.candidate.metrics?.f1 ?? null)} (${formatDelta(delta.deltas.f1)}) | ${formatMetric(delta.base.metrics?.attackBlockRate ?? null)} -> ${formatMetric(delta.candidate.metrics?.attackBlockRate ?? null)} (${formatDelta(delta.deltas.attackBlockRate)}) | ${formatMetric(delta.base.metrics?.falsePositiveRate ?? null)} -> ${formatMetric(delta.candidate.metrics?.falsePositiveRate ?? null)} (${formatDelta(delta.deltas.falsePositiveRate)}) |`,
    );
  }

  lines.push("");
  lines.push("## Per-Case Prediction Deltas");
  lines.push("");
  if (summary.caseDeltas.length === 0) {
    lines.push("No per-case prediction changes detected.");
  } else {
    lines.push("| Engine | Suite | Case | Base | Candidate |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const delta of summary.caseDeltas) {
      lines.push(
        `| ${delta.engine} | ${delta.suite} | \`${delta.caseName}\` | ${String(delta.basePredicted)} / ${String(delta.basePassed)} | ${String(delta.candidatePredicted)} / ${String(delta.candidatePassed)} |`,
      );
    }
  }
  lines.push("");
  return lines.join("\n") + "\n";
}

function writeOutput(path: string, contents: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents, "utf8");
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const base = parseReport(opts.basePath);
  const candidate = parseReport(opts.candidatePath);
  const summary = compareReports(base, candidate, opts.basePath, opts.candidatePath);

  mkdirSync(opts.outputDir, { recursive: true });
  writeOutput(join(opts.outputDir, "benchmark-comparison.json"), JSON.stringify(summary, null, 2) + "\n");
  writeOutput(join(opts.outputDir, "benchmark-comparison.md"), buildMarkdown(summary, base, candidate));

  process.stdout.write(`[compare-benchmark-reports] wrote ${join(opts.outputDir, "benchmark-comparison.json")}\n`);
  process.stdout.write(`[compare-benchmark-reports] wrote ${join(opts.outputDir, "benchmark-comparison.md")}\n`);
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[compare-benchmark-reports] ERROR ${message}\n`);
  process.exitCode = 1;
}
