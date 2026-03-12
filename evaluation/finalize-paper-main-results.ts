import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

type ArtifactStatus = "preliminary" | "candidate" | "final";

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(EVAL_ROOT, "..");
const DEFAULT_ARTIFACT_DIR = join(EVAL_ROOT, "results", "final", "e2e-main-results-final");
const PAPER_DIR = join(REPO_ROOT, "paper");
const CLI_CWD = join(REPO_ROOT, "packages", "cli");

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/finalize-paper-main-results.ts [options]",
    "",
    "Options:",
    "  --artifact-dir <path>     Packaged artifact directory under evaluation/results/final/",
    "  --allow-candidate         Allow status=candidate instead of requiring status=final",
    "  --skip-compile            Promote into paper/generated/ but skip pdflatex compilation",
    "  --help                    Show this message",
    "",
    "Behavior:",
    "  1. verifies the packaged artifact contains main-results fragments",
    "  2. promotes them into paper/generated/main-results-*.tex",
    "  3. recompiles paper/main.tex (unless --skip-compile is used)",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  artifactDir: string;
  allowCandidate: boolean;
  skipCompile: boolean;
} {
  let artifactDir = DEFAULT_ARTIFACT_DIR;
  let allowCandidate = false;
  let skipCompile = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--artifact-dir") {
      const raw = argv[++i];
      if (!raw) throw new Error("--artifact-dir requires a value");
      artifactDir = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--allow-candidate") {
      allowCandidate = true;
      continue;
    }
    if (arg === "--skip-compile") {
      skipCompile = true;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { artifactDir, allowCandidate, skipCompile };
}

function ensureExists(path: string, label: string): void {
  if (!existsSync(path)) {
    throw new Error(`${label} does not exist: ${path}`);
  }
}

function parseStatus(manifestPath: string): ArtifactStatus {
  const text = readFileSync(manifestPath, "utf8");
  const match = text.match(/^Status:\s+`(preliminary|candidate|final)`/m);
  if (!match) {
    throw new Error(`could not determine artifact status from ${manifestPath}`);
  }
  return match[1] as ArtifactStatus;
}

function runStep(command: string, args: string[], cwd: string): void {
  const display = [command, ...args].join(" ");
  process.stdout.write(`[finalize-paper-main-results] running ${display}\n`);
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
    shell: false,
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(`command failed with exit code ${result.status}: ${display}`);
  }
}

function findReportPath(artifactDir: string): string {
  const entries = readdirSync(artifactDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.startsWith("benchmark-report") && entry.name.endsWith(".json"))
    .map((entry) => join(artifactDir, entry.name));
  if (entries.length === 0) {
    throw new Error(`no benchmark-report*.json file found in ${artifactDir}`);
  }
  if (entries.length > 1) {
    const preferred = entries.find((item) => item.endsWith("benchmark-report-baseline-ladder-live.json"));
    if (preferred) return preferred;
  }
  return entries[0]!;
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2));
  const manifestPath = join(opts.artifactDir, "artifact-manifest.md");
  const rowsPath = join(opts.artifactDir, "main-results-rows.tex");
  const tablePath = join(opts.artifactDir, "main-results-table.tex");

  ensureExists(opts.artifactDir, "artifact dir");
  ensureExists(manifestPath, "artifact manifest");
  ensureExists(rowsPath, "main-results rows fragment");
  ensureExists(tablePath, "main-results table fragment");
  const reportPath = findReportPath(opts.artifactDir);

  const status = parseStatus(manifestPath);
  if (status !== "final" && !(status === "candidate" && opts.allowCandidate)) {
    throw new Error(
      `artifact status is ${status}; use a final artifact or pass --allow-candidate for a staging preview.`,
    );
  }

  const promoteArgs = [
    "--import",
    "tsx",
    resolve(EVAL_ROOT, "promote-paper-results.ts"),
    "--input-report",
    reportPath,
    "--tables-dir",
    opts.artifactDir,
    "--promote-prefix",
    "main-results",
  ];
  if (status !== "final") {
    promoteArgs.push("--allow-preliminary");
  }
  runStep(process.execPath, promoteArgs, CLI_CWD);

  if (!opts.skipCompile) {
    runStep("pdflatex", ["-interaction=nonstopmode", "-halt-on-error", "main.tex"], PAPER_DIR);
    runStep("pdflatex", ["-interaction=nonstopmode", "-halt-on-error", "main.tex"], PAPER_DIR);
  }

  process.stdout.write(
    `[finalize-paper-main-results] complete artifact=${opts.artifactDir} status=${status} compiled=${!opts.skipCompile}\n`,
  );
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[finalize-paper-main-results] ERROR ${message}\n`);
  process.exitCode = 1;
}
