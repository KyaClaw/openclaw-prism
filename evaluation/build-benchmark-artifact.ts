import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type Preset = "baseline-ladder-default" | "baseline-ladder-mock" | "baseline-ladder-live";
type Status = "preliminary" | "candidate" | "final";

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(EVAL_ROOT, "..");
const CLI_CWD = join(REPO_ROOT, "packages", "cli");
const SUITE_FILTER = "plugin-flow,tool-abuse,tool-use";
const ENGINES = "no-prism,heuristics-only,plugin-only,plugin-scanner,full-prism";
const DEFAULT_LIVE_OLLAMA_URL = "http://127.0.0.1:11434/api/generate";
const DEFAULT_LIVE_OLLAMA_MODEL = "qwen3:8b";
const DEFAULT_LIVE_OLLAMA_TIMEOUT_MS = "20000";
const DEFAULT_LIVE_OLLAMA_TEMPERATURE = "0";
const DEFAULT_LIVE_OLLAMA_SEED = "7";

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/build-benchmark-artifact.ts [options]",
    "",
    "Options:",
    "  --preset <name>               baseline-ladder-default | baseline-ladder-mock | baseline-ladder-live",
    "  --artifact-name <name>        Packaged artifact directory name",
    "  --status <value>              preliminary | candidate | final (default: candidate)",
    "  --ollama-url <url>            Live preset Ollama URL (default: http://127.0.0.1:11434/api/generate)",
    "  --ollama-model <name>         Live preset Ollama model (default: qwen3:8b)",
    "  --ollama-timeout-ms <ms>      Live preset Ollama timeout in ms (default: 20000)",
    "  --ollama-temperature <value>  Live preset Ollama temperature (default: 0)",
    "  --ollama-seed <int>           Live preset Ollama seed (default: 7)",
    "  --plugin-scanner-timeout-ms <ms>  Optional override for plugin-side scanner timeout",
    "  --promote-prefix <prefix>     Also promote rows/table into paper/generated/ under this prefix",
    "  --allow-preliminary-promote   Allow canonical promotion from a non-final artifact",
    "  --skip-benchmark              Reuse an existing report instead of rerunning the benchmark",
    "  --help                        Show this message",
    "",
    "Examples:",
    "  tsx evaluation/build-benchmark-artifact.ts --preset baseline-ladder-live --artifact-name baseline-ladder-live-candidate --status candidate",
    "  tsx evaluation/build-benchmark-artifact.ts --preset baseline-ladder-live --artifact-name e2e-main-results-final --status final --promote-prefix main-results",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  preset: Preset;
  artifactName: string | null;
  status: Status;
  ollamaUrl: string;
  ollamaModel: string;
  ollamaTimeoutMs: string;
  ollamaTemperature: string;
  ollamaSeed: string;
  pluginScannerTimeoutMs: string | null;
  promotePrefix: string | null;
  allowPreliminaryPromote: boolean;
  skipBenchmark: boolean;
} {
  let preset: Preset = "baseline-ladder-live";
  let artifactName: string | null = null;
  let status: Status = "candidate";
  let ollamaUrl = process.env.OLLAMA_URL || DEFAULT_LIVE_OLLAMA_URL;
  let ollamaModel = process.env.OLLAMA_MODEL || DEFAULT_LIVE_OLLAMA_MODEL;
  let ollamaTimeoutMs = process.env.OLLAMA_TIMEOUT_MS || DEFAULT_LIVE_OLLAMA_TIMEOUT_MS;
  let ollamaTemperature = process.env.OLLAMA_TEMPERATURE || DEFAULT_LIVE_OLLAMA_TEMPERATURE;
  let ollamaSeed = process.env.OLLAMA_SEED || DEFAULT_LIVE_OLLAMA_SEED;
  let pluginScannerTimeoutMs = process.env.PRISM_BENCH_PLUGIN_SCANNER_TIMEOUT_MS || null;
  let promotePrefix: string | null = null;
  let allowPreliminaryPromote = false;
  let skipBenchmark = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--preset") {
      const raw = argv[++i];
      if (!raw) throw new Error("--preset requires a value");
      if (raw !== "baseline-ladder-default" && raw !== "baseline-ladder-mock" && raw !== "baseline-ladder-live") {
        throw new Error("--preset must be baseline-ladder-default, baseline-ladder-mock, or baseline-ladder-live");
      }
      preset = raw;
      continue;
    }
    if (arg === "--artifact-name") {
      const raw = argv[++i];
      if (!raw) throw new Error("--artifact-name requires a value");
      artifactName = raw.trim();
      if (!artifactName) throw new Error("--artifact-name must not be empty");
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
    if (arg === "--ollama-url") {
      const raw = argv[++i];
      if (!raw) throw new Error("--ollama-url requires a value");
      ollamaUrl = raw;
      continue;
    }
    if (arg === "--ollama-model") {
      const raw = argv[++i];
      if (!raw) throw new Error("--ollama-model requires a value");
      ollamaModel = raw;
      continue;
    }
    if (arg === "--ollama-timeout-ms") {
      const raw = argv[++i];
      if (!raw) throw new Error("--ollama-timeout-ms requires a value");
      ollamaTimeoutMs = raw;
      continue;
    }
    if (arg === "--ollama-temperature") {
      const raw = argv[++i];
      if (!raw) throw new Error("--ollama-temperature requires a value");
      ollamaTemperature = raw;
      continue;
    }
    if (arg === "--ollama-seed") {
      const raw = argv[++i];
      if (!raw) throw new Error("--ollama-seed requires a value");
      ollamaSeed = raw;
      continue;
    }
    if (arg === "--plugin-scanner-timeout-ms") {
      const raw = argv[++i];
      if (!raw) throw new Error("--plugin-scanner-timeout-ms requires a value");
      pluginScannerTimeoutMs = raw;
      continue;
    }
    if (arg === "--promote-prefix") {
      const raw = argv[++i];
      if (!raw) throw new Error("--promote-prefix requires a value");
      promotePrefix = raw.trim();
      if (!promotePrefix) throw new Error("--promote-prefix must not be empty");
      continue;
    }
    if (arg === "--allow-preliminary-promote") {
      allowPreliminaryPromote = true;
      continue;
    }
    if (arg === "--skip-benchmark") {
      skipBenchmark = true;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return {
    preset,
    artifactName,
    status,
    ollamaUrl,
    ollamaModel,
    ollamaTimeoutMs,
    ollamaTemperature,
    ollamaSeed,
    pluginScannerTimeoutMs,
    promotePrefix,
    allowPreliminaryPromote,
    skipBenchmark,
  };
}

function defaultArtifactName(preset: Preset, status: Status): string {
  return `${preset}-${status}`;
}

function presetConfig(preset: Preset): {
  reportPath: string;
  tablesDir: string;
  benchmarkArgs: string[];
} {
  switch (preset) {
    case "baseline-ladder-default":
      return {
        reportPath: join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-default.json"),
        tablesDir: join(EVAL_ROOT, "results", "tables-baseline-ladder-default"),
        benchmarkArgs: [],
      };
    case "baseline-ladder-mock":
      return {
        reportPath: join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder.json"),
        tablesDir: join(EVAL_ROOT, "results", "tables-baseline-ladder"),
        benchmarkArgs: ["--scanner-ollama-mock", "--require-scanner-assisted-path"],
      };
    case "baseline-ladder-live":
      return {
        reportPath: join(EVAL_ROOT, "results", "benchmark-report-baseline-ladder-live.json"),
        tablesDir: join(EVAL_ROOT, "results", "tables-baseline-ladder-live"),
        benchmarkArgs: ["--scanner-ollama-live", "--require-scanner-assisted-path"],
      };
  }
}

function runStep(command: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): void {
  const display = [command, ...args].join(" ");
  process.stdout.write(`[build-benchmark-artifact] running ${display}\n`);
  const result = spawnSync(command, args, {
    cwd,
    env: env ?? process.env,
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0) {
    throw new Error(`command failed with exit code ${result.status}: ${display}`);
  }
}

function runTsxScript(scriptPath: string, args: string[], env?: NodeJS.ProcessEnv): void {
  runStep(process.execPath, ["--import", "tsx", scriptPath, ...args], CLI_CWD, env);
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const config = presetConfig(opts.preset);
  const artifactName = opts.artifactName ?? defaultArtifactName(opts.preset, opts.status);
  const benchmarkEnv = { ...process.env };

  if (opts.preset === "baseline-ladder-live") {
    benchmarkEnv.OLLAMA_URL = opts.ollamaUrl;
    benchmarkEnv.OLLAMA_MODEL = opts.ollamaModel;
    benchmarkEnv.OLLAMA_TIMEOUT_MS = opts.ollamaTimeoutMs;
    benchmarkEnv.OLLAMA_TEMPERATURE = opts.ollamaTemperature;
    benchmarkEnv.OLLAMA_SEED = opts.ollamaSeed;
    if (opts.pluginScannerTimeoutMs) {
      benchmarkEnv.PRISM_BENCH_PLUGIN_SCANNER_TIMEOUT_MS = opts.pluginScannerTimeoutMs;
    }
  }

  if (!opts.skipBenchmark) {
    runTsxScript(
      resolve(EVAL_ROOT, "run-benchmark.ts"),
      [
        "--suite-filter",
        SUITE_FILTER,
        "--engines",
        ENGINES,
        ...config.benchmarkArgs,
        "--output",
        config.reportPath,
      ],
      benchmarkEnv,
    );
  }

  runTsxScript(
    resolve(EVAL_ROOT, "results-to-table.ts"),
    [
      "--input",
      config.reportPath,
      "--output-dir",
      config.tablesDir,
    ],
  );

  runTsxScript(
    resolve(EVAL_ROOT, "package-paper-artifact.ts"),
    [
      "--input-report",
      config.reportPath,
      "--tables-dir",
      config.tablesDir,
      "--artifact-name",
      artifactName,
      "--status",
      opts.status,
    ],
  );

  if (opts.promotePrefix) {
    const promoteArgs = [
      "--input-report",
      join(EVAL_ROOT, "results", "final", artifactName, resolve(config.reportPath).split(/[/\\]/).pop()!),
      "--tables-dir",
      join(EVAL_ROOT, "results", "final", artifactName),
      "--promote-prefix",
      opts.promotePrefix,
    ];
    if (opts.allowPreliminaryPromote) {
      promoteArgs.push("--allow-preliminary");
    }
    runTsxScript(resolve(EVAL_ROOT, "promote-paper-results.ts"), promoteArgs);
  }

  process.stdout.write(
    `[build-benchmark-artifact] completed preset=${opts.preset} artifact=${artifactName} status=${opts.status}\n`,
  );
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[build-benchmark-artifact] ERROR ${message}\n`);
  process.exitCode = 1;
}
