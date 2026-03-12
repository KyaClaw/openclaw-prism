import http from "node:http";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { performance } from "node:perf_hooks";
import { heuristicScan } from "../packages/shared/src/heuristics.ts";
import { classify } from "../packages/scanner/src/index.ts";
import { evaluateInvokePolicy, loadPolicy } from "../packages/proxy/src/policy.ts";
import registerPlugin, { cleanupAll, getSessionRisk, riskBySession } from "../packages/plugin/src/index.ts";
import type { InvokeBody, InvokePolicyDecision, Policy } from "../packages/proxy/src/policy.ts";

type EngineName =
  | "no-prism"
  | "heuristics-only"
  | "heuristic"
  | "scanner"
  | "proxy-policy"
  | "plugin-only"
  | "plugin-scanner"
  | "full-prism";
type ExpectedClass = "attack" | "benign";
type ScannerRunMode = "default" | "mock" | "live";

type ScanTextCase = {
  kind: "scan-text";
  name: string;
  suite?: string;
  text: string;
  expectedClass: ExpectedClass;
  scannerMock?: {
    verdict: "benign" | "suspicious" | "malicious";
    score?: number;
    reasons?: string[];
  };
  notes?: string;
};

type ScannerMockSpec = {
  verdict: "benign" | "suspicious" | "malicious";
  score?: number;
  reasons?: string[];
};

type PluginFlowStep =
  | {
      type: "message_received";
      content: string;
    }
  | {
      type: "before_prompt_build";
      prompt: string;
    }
  | {
      type: "before_tool_call";
      toolName: string;
      params?: Record<string, unknown>;
    }
  | {
      type: "after_tool_call";
      toolName: string;
      resultText: string;
      scannerMock?: ScannerMockSpec;
    }
  | {
      type: "tool_result_persist";
      toolName: string;
      content: string;
      role?: string;
    }
  | {
      type: "before_message_write";
      content: string;
      role?: string;
    }
  | {
      type: "message_sending";
      content: string;
    }
  | {
      type: "subagent_spawning";
      childSessionKey?: string;
      agentId?: string;
    };

type PluginFlowCase = {
  kind: "plugin-flow";
  name: string;
  suite?: string;
  sessionKey?: string;
  conversationId?: string;
  expectedClass: ExpectedClass;
  heuristicProbe?: string;
  steps: PluginFlowStep[];
  notes?: string;
};

type InvokePolicyCase = {
  kind: "invoke-policy";
  name: string;
  suite?: string;
  token: string;
  request: InvokeBody;
  expectedAllow: boolean;
  policyPath?: string;
  heuristicProbe?: string;
  notes?: string;
};

type BenchmarkCase = ScanTextCase | InvokePolicyCase | PluginFlowCase;

type LoadedCase = {
  id: string;
  suite: string;
  sourceFile: string;
  caseData: BenchmarkCase;
};

type CaseResult = {
  caseId: string;
  caseName: string;
  suite: string;
  engine: EngineName;
  supported: boolean;
  passed: boolean | null;
  expectedClass: ExpectedClass | null;
  predictedClass: ExpectedClass | null;
  sourceFile: string;
  raw: Record<string, unknown>;
};

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

type EngineProfiling = {
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

type SuiteSummary = {
  suite: string;
  executed: number;
  passed: number;
  failed: number;
  skipped: number;
  metrics: BinaryMetrics | null;
};

type EngineReport = {
  engine: EngineName;
  summary: {
    totalCases: number;
    executed: number;
    passed: number;
    failed: number;
    skipped: number;
    metrics: BinaryMetrics | null;
    profiling: EngineProfiling;
  };
  suites: SuiteSummary[];
  results: CaseResult[];
};

type BenchmarkReport = {
  generatedAt: string;
  repoRoot: string;
  caseRoots: string[];
  suiteFilter: string[] | null;
  outputPath: string;
  engines: EngineName[];
  totalLoadedCases: number;
  scanner: {
    mode: ScannerRunMode;
    requireAssistedPath: boolean;
    ollamaUrl: string;
    ollamaModel: string;
    ollamaTimeoutMs: number;
    ollamaTemperature?: number;
    ollamaSeed?: number | null;
    pluginScannerTimeoutMs: number;
    mockAnnotatedCases: number;
    modelAssistedCases: number;
  } | null;
  reports: EngineReport[];
};

const EVAL_ROOT = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(EVAL_ROOT, "..");
const DEFAULT_CASE_ROOTS = [
  join(EVAL_ROOT, "attack-corpus"),
  join(EVAL_ROOT, "benign-corpus"),
];
const DEFAULT_OUTPUT = join(EVAL_ROOT, "results", "benchmark-report.json");
const DEFAULT_POLICY_PATH = join(REPO_ROOT, "config", "invoke-guard.policy.json");
const DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434/api/generate";
const DEFAULT_OLLAMA_MODEL = "qwen3:30b";
const DEFAULT_OLLAMA_TIMEOUT_MS = 3_000;
const BYTES_PER_MEBIBYTE = 1024 * 1024;
const BENCHMARK_OUTBOUND_SECRET_PATTERNS = [
  "ghpbench_[0-9A-Za-z]{16,}",
  "skbench-[A-Za-z0-9]{16,}",
  "xoxbench-[0-9A-Za-z-]{12,}",
];

function usage(): string {
  return [
    "Usage:",
    "  tsx evaluation/run-benchmark.ts [--cases-root <path[,path...]>] [--suite-filter <suite[,suite...]>] [--engines <list>] [--output <path>] [--scanner-ollama-mock|--scanner-ollama-live] [--require-scanner-assisted-path]",
    "",
    "Options:",
    "  --cases-root   Comma-separated case roots. Defaults to evaluation/attack-corpus,evaluation/benign-corpus",
    "  --suite-filter Comma-separated suite names. When set, only matching suites are loaded",
    "  --engines      Comma-separated engines: no-prism,heuristics-only,heuristic,scanner,proxy-policy,plugin-only,plugin-scanner,full-prism",
    "  --output       JSON report path. Defaults to evaluation/results/benchmark-report.json",
    "  --scanner-ollama-mock  Start a local mock Ollama endpoint using case-embedded scannerMock verdicts",
    "  --scanner-ollama-live  Declare this run as a live Ollama-backed scanner experiment",
    "  --require-scanner-assisted-path  Exit non-zero unless at least one scanner case used the assisted path",
    "  --help         Show this message",
  ].join("\n");
}

function parseArgs(argv: string[]): {
  caseRoots: string[];
  engines: EngineName[];
  outputPath: string;
  scannerMode: ScannerRunMode;
  requireScannerAssistedPath: boolean;
  suiteFilter: string[] | null;
} {
  let caseRoots = [...DEFAULT_CASE_ROOTS];
  let engines: EngineName[] = ["heuristic", "scanner", "proxy-policy"];
  let outputPath = DEFAULT_OUTPUT;
  let scannerMode: ScannerRunMode = "default";
  let requireScannerAssistedPath = false;
  let suiteFilter: string[] | null = null;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (arg === "--cases-root") {
      const raw = argv[++i];
      if (!raw) throw new Error("--cases-root requires a value");
      caseRoots = raw.split(",").map((part) => resolve(process.cwd(), part.trim())).filter(Boolean);
      continue;
    }
    if (arg === "--engines") {
      const raw = argv[++i];
      if (!raw) throw new Error("--engines requires a value");
      const parsed = raw.split(",").map((part) => part.trim()).filter(Boolean);
      if (parsed.length === 0) throw new Error("--engines must not be empty");
      engines = parsed.map(parseEngineName);
      continue;
    }
    if (arg === "--suite-filter") {
      const raw = argv[++i];
      if (!raw) throw new Error("--suite-filter requires a value");
      const parsed = raw.split(",").map((part) => part.trim()).filter(Boolean);
      if (parsed.length === 0) throw new Error("--suite-filter must not be empty");
      suiteFilter = parsed;
      continue;
    }
    if (arg === "--output") {
      const raw = argv[++i];
      if (!raw) throw new Error("--output requires a value");
      outputPath = resolve(process.cwd(), raw);
      continue;
    }
    if (arg === "--scanner-ollama-mock") {
      if (scannerMode === "live") {
        throw new Error("--scanner-ollama-mock cannot be combined with --scanner-ollama-live");
      }
      scannerMode = "mock";
      continue;
    }
    if (arg === "--scanner-ollama-live") {
      if (scannerMode === "mock") {
        throw new Error("--scanner-ollama-live cannot be combined with --scanner-ollama-mock");
      }
      scannerMode = "live";
      continue;
    }
    if (arg === "--require-scanner-assisted-path") {
      requireScannerAssistedPath = true;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  if ((scannerMode !== "default" || requireScannerAssistedPath) && !scannerEngineEnabled(engines)) {
    throw new Error("scanner run options require a scanner-capable engine to be enabled");
  }

  return { caseRoots, engines, outputPath, scannerMode, requireScannerAssistedPath, suiteFilter };
}

function parseEngineName(raw: string): EngineName {
  if (
    raw === "no-prism" ||
    raw === "heuristics-only" ||
    raw === "heuristic" ||
    raw === "scanner" ||
    raw === "proxy-policy" ||
    raw === "plugin-only" ||
    raw === "plugin-scanner" ||
    raw === "full-prism"
  ) {
    return raw;
  }
  throw new Error(`unsupported engine: ${raw}`);
}

function executeNoPrismCase(
  entry: LoadedCase,
  base: Pick<CaseResult, "caseId" | "caseName" | "suite" | "engine" | "sourceFile">,
): CaseResult {
  if (entry.caseData.kind === "invoke-policy") {
    const expectedClass = classifyExpectedAllow(entry.caseData.expectedAllow);
    const predictedClass: ExpectedClass = "benign";
    return {
      ...base,
      supported: true,
      passed: entry.caseData.expectedAllow === true,
      expectedClass,
      predictedClass,
      raw: {
        mode: "pass-through",
        allow: true,
        enforcedBy: "none",
      },
    };
  }

  const expectedClass = entry.caseData.expectedClass;
  const predictedClass: ExpectedClass = "benign";
  return {
    ...base,
    supported: true,
    passed: predictedClass === expectedClass,
    expectedClass,
    predictedClass,
    raw: {
      mode: "pass-through",
      enforcedBy: "none",
    },
  };
}

function getHeuristicProbe(caseData: BenchmarkCase): string | null {
  if (caseData.kind === "scan-text") return caseData.text;
  if (caseData.kind === "plugin-flow") return caseData.heuristicProbe?.trim() || null;
  if (caseData.kind === "invoke-policy") return caseData.heuristicProbe?.trim() || null;
  return null;
}

function executeHeuristicsOnlyCase(
  entry: LoadedCase,
  base: Pick<CaseResult, "caseId" | "caseName" | "suite" | "engine" | "sourceFile">,
): CaseResult {
  const probe = getHeuristicProbe(entry.caseData);
  const expectedClass =
    entry.caseData.kind === "invoke-policy"
      ? classifyExpectedAllow(entry.caseData.expectedAllow)
      : entry.caseData.expectedClass;

  if (!probe) {
    const predictedClass: ExpectedClass = "benign";
    return {
      ...base,
      supported: true,
      passed: predictedClass === expectedClass,
      expectedClass,
      predictedClass,
      raw: {
        mode: "pass-through",
        probeUsed: false,
      },
    };
  }

  const verdict = heuristicScan(probe);
  const predictedClass: ExpectedClass = verdict.suspicious ? "attack" : "benign";
  return {
    ...base,
    supported: true,
    passed: predictedClass === expectedClass,
    expectedClass,
    predictedClass,
    raw: {
      mode: "heuristic-probe",
      probeUsed: true,
      suspicious: verdict.suspicious,
      score: verdict.score,
      reasons: verdict.reasons,
      probe,
    },
  };
}

function ensureObject(input: unknown, source: string): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`expected JSON object in ${source}`);
  }
  return input as Record<string, unknown>;
}

function parseScannerMockSpec(input: unknown): ScannerMockSpec | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input)) return undefined;
  const record = input as Record<string, unknown>;
  if (
    record.verdict !== "benign" &&
    record.verdict !== "suspicious" &&
    record.verdict !== "malicious"
  ) {
    return undefined;
  }
  return {
    verdict: record.verdict,
    ...(typeof record.score === "number" ? { score: record.score } : {}),
    ...(Array.isArray(record.reasons) ? { reasons: record.reasons.map(String).slice(0, 8) } : {}),
  };
}

function parsePluginFlowStep(input: unknown, source: string): PluginFlowStep {
  const record = ensureObject(input, source);
  const type = record.type;

  if (type === "message_received") {
    const content = typeof record.content === "string" ? record.content : "";
    if (!content) throw new Error(`${source}.content must be a non-empty string`);
    return { type, content };
  }

  if (type === "before_prompt_build") {
    const prompt = typeof record.prompt === "string" ? record.prompt : "";
    if (!prompt) throw new Error(`${source}.prompt must be a non-empty string`);
    return { type, prompt };
  }

  if (type === "before_tool_call") {
    const toolName = typeof record.toolName === "string" ? record.toolName.trim() : "";
    if (!toolName) throw new Error(`${source}.toolName must be a non-empty string`);
    const params =
      record.params && typeof record.params === "object" && !Array.isArray(record.params)
        ? (record.params as Record<string, unknown>)
        : {};
    return { type, toolName, ...(Object.keys(params).length > 0 ? { params } : {}) };
  }

  if (type === "after_tool_call") {
    const toolName = typeof record.toolName === "string" ? record.toolName.trim() : "";
    const resultText = typeof record.resultText === "string" ? record.resultText : "";
    if (!toolName) throw new Error(`${source}.toolName must be a non-empty string`);
    if (!resultText) throw new Error(`${source}.resultText must be a non-empty string`);
    const scannerMock = parseScannerMockSpec(record.scannerMock);
    return { type, toolName, resultText, ...(scannerMock ? { scannerMock } : {}) };
  }

  if (type === "tool_result_persist") {
    const toolName = typeof record.toolName === "string" ? record.toolName.trim() : "";
    const content = typeof record.content === "string" ? record.content : "";
    const role = typeof record.role === "string" && record.role.trim() ? record.role.trim() : undefined;
    if (!toolName) throw new Error(`${source}.toolName must be a non-empty string`);
    if (!content) throw new Error(`${source}.content must be a non-empty string`);
    return { type, toolName, content, ...(role ? { role } : {}) };
  }

  if (type === "before_message_write") {
    const content = typeof record.content === "string" ? record.content : "";
    const role = typeof record.role === "string" && record.role.trim() ? record.role.trim() : undefined;
    if (!content) throw new Error(`${source}.content must be a non-empty string`);
    return { type, content, ...(role ? { role } : {}) };
  }

  if (type === "message_sending") {
    const content = typeof record.content === "string" ? record.content : "";
    if (!content) throw new Error(`${source}.content must be a non-empty string`);
    return { type, content };
  }

  if (type === "subagent_spawning") {
    const childSessionKey =
      typeof record.childSessionKey === "string" && record.childSessionKey.trim()
        ? record.childSessionKey.trim()
        : undefined;
    const agentId =
      typeof record.agentId === "string" && record.agentId.trim()
        ? record.agentId.trim()
        : undefined;
    return { type, ...(childSessionKey ? { childSessionKey } : {}), ...(agentId ? { agentId } : {}) };
  }

  throw new Error(`${source}.type is not a supported plugin-flow step`);
}

function collectJsonFiles(root: string): string[] {
  if (!existsSync(root) || !statSync(root).isDirectory()) return [];
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectJsonFiles(path));
      continue;
    }
    if (entry.isFile() && extname(entry.name).toLowerCase() === ".json") {
      files.push(path);
    }
  }
  return files;
}

function normalizeSuite(sourceFile: string, caseSuite: string | undefined, caseRoot: string): string {
  if (caseSuite?.trim()) return caseSuite.trim();
  const rel = relative(caseRoot, sourceFile);
  const segments = rel.split(/[\\/]/).filter(Boolean);
  if (segments.length > 1) return segments[0]!;
  return "unsorted";
}

function parseBenchmarkCase(input: unknown, source: string): BenchmarkCase {
  const record = ensureObject(input, source);
  const kind = record.kind;
  const name = typeof record.name === "string" && record.name.trim() ? record.name.trim() : "";
  if (!name) throw new Error(`${source}.name must be a non-empty string`);
  const suite = typeof record.suite === "string" && record.suite.trim() ? record.suite.trim() : undefined;
  const notes = typeof record.notes === "string" ? record.notes : undefined;

  if (kind === "scan-text") {
    const text = typeof record.text === "string" ? record.text : "";
    const expectedClass = record.expectedClass;
    const scannerMock = parseScannerMockSpec(record.scannerMock);
    if (!text) throw new Error(`${source}.text must be a non-empty string`);
    if (expectedClass !== "attack" && expectedClass !== "benign") {
      throw new Error(`${source}.expectedClass must be "attack" or "benign"`);
    }
    return { kind, name, suite, text, expectedClass, ...(scannerMock ? { scannerMock } : {}), ...(notes ? { notes } : {}) };
  }

  if (kind === "plugin-flow") {
    const expectedClass = record.expectedClass;
    if (expectedClass !== "attack" && expectedClass !== "benign") {
      throw new Error(`${source}.expectedClass must be "attack" or "benign"`);
    }
    const sessionKey =
      typeof record.sessionKey === "string" && record.sessionKey.trim() ? record.sessionKey.trim() : undefined;
    const conversationId =
      typeof record.conversationId === "string" && record.conversationId.trim()
        ? record.conversationId.trim()
        : undefined;
    const heuristicProbe =
      typeof record.heuristicProbe === "string" && record.heuristicProbe.trim()
        ? record.heuristicProbe.trim()
        : undefined;
    const rawSteps = Array.isArray(record.steps) ? record.steps : [];
    if (rawSteps.length === 0) throw new Error(`${source}.steps must be a non-empty array`);
    const steps = rawSteps.map((step, index) => parsePluginFlowStep(step, `${source}.steps[${index}]`));
    return {
      kind,
      name,
      suite,
      expectedClass,
      steps,
      ...(sessionKey ? { sessionKey } : {}),
      ...(conversationId ? { conversationId } : {}),
      ...(heuristicProbe ? { heuristicProbe } : {}),
      ...(notes ? { notes } : {}),
    };
  }

  if (kind === "invoke-policy") {
    const token = typeof record.token === "string" ? record.token : "";
    const request = ensureObject(record.request, `${source}.request`) as InvokeBody;
    const expectedAllow = record.expectedAllow;
    const policyPath = typeof record.policyPath === "string" && record.policyPath.trim()
      ? record.policyPath.trim()
      : undefined;
    const heuristicProbe =
      typeof record.heuristicProbe === "string" && record.heuristicProbe.trim()
        ? record.heuristicProbe.trim()
        : undefined;
    if (!token) throw new Error(`${source}.token must be a non-empty string`);
    if (typeof expectedAllow !== "boolean") {
      throw new Error(`${source}.expectedAllow must be boolean`);
    }
    return {
      kind,
      name,
      suite,
      token,
      request,
      expectedAllow,
      ...(policyPath ? { policyPath } : {}),
      ...(heuristicProbe ? { heuristicProbe } : {}),
      ...(notes ? { notes } : {}),
    };
  }

  throw new Error(`${source}.kind must be "scan-text", "plugin-flow", or "invoke-policy"`);
}

function loadCases(caseRoots: string[], suiteFilter: string[] | null): LoadedCase[] {
  const allowedSuites = suiteFilter ? new Set(suiteFilter.map((suite) => suite.trim()).filter(Boolean)) : null;
  const loaded: LoadedCase[] = [];
  for (const caseRoot of caseRoots) {
    for (const filePath of collectJsonFiles(caseRoot)) {
      const raw = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
      const entries = Array.isArray(raw)
        ? raw
        : (() => {
            const record = ensureObject(raw, filePath);
            return Array.isArray(record.cases) ? record.cases : [record];
          })();

      entries.forEach((entry, index) => {
        const parsed = parseBenchmarkCase(entry, `${filePath}[${index}]`);
        const suite = normalizeSuite(filePath, parsed.suite, caseRoot);
        if (allowedSuites && !allowedSuites.has(suite)) return;
        loaded.push({
          id: `${relative(REPO_ROOT, filePath).replace(/[\\/]/g, ":")}:${index}`,
          suite,
          sourceFile: relative(REPO_ROOT, filePath),
          caseData: parsed,
        });
      });
    }
  }
  return loaded;
}

function getOllamaUrl(): string {
  return process.env.OLLAMA_URL ?? DEFAULT_OLLAMA_URL;
}

function getOllamaModel(): string {
  return process.env.OLLAMA_MODEL ?? DEFAULT_OLLAMA_MODEL;
}

function getOllamaTimeoutMs(): number {
  const parsed = Number(process.env.OLLAMA_TIMEOUT_MS ?? `${DEFAULT_OLLAMA_TIMEOUT_MS}`);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_OLLAMA_TIMEOUT_MS;
}

function getOllamaTemperature(): number | null {
  const raw = process.env.OLLAMA_TEMPERATURE;
  if (raw === undefined || raw === "") return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function getOllamaSeed(): number | null {
  const raw = process.env.OLLAMA_SEED;
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

function getPluginScannerTimeoutMs(scannerMode: ScannerRunMode): number {
  const explicit = Number(process.env.PRISM_BENCH_PLUGIN_SCANNER_TIMEOUT_MS ?? "");
  if (Number.isFinite(explicit) && explicit > 0) return explicit;
  if (scannerMode === "live") return Math.max(getOllamaTimeoutMs() + 1_000, 5_000);
  return 900;
}

function classifyExpectedAllow(expectedAllow: boolean): ExpectedClass {
  return expectedAllow ? "benign" : "attack";
}

function classifyDecision(decision: InvokePolicyDecision): ExpectedClass {
  return decision.allow ? "benign" : "attack";
}

const policyCache = new Map<string, Policy>();

function loadPolicyCached(policyPath: string): Policy {
  const resolvedPath = resolve(policyPath);
  let cached = policyCache.get(resolvedPath);
  if (!cached) {
    cached = loadPolicy(resolvedPath);
    policyCache.set(resolvedPath, cached);
  }
  return cached;
}

type BenchmarkRuntime = {
  scannerService: ScannerServiceHandle | null;
  scannerMode: ScannerRunMode;
  pluginScannerTimeoutMs: number;
};

async function executePluginFlowCase(
  engine: "plugin-only" | "plugin-scanner" | "full-prism",
  entry: LoadedCase & { caseData: PluginFlowCase },
  runtime: BenchmarkRuntime,
): Promise<CaseResult> {
  const base = {
    caseId: entry.id,
    caseName: entry.caseData.name,
    suite: entry.suite,
    engine,
    sourceFile: entry.sourceFile,
  };

  const useRemoteScanner = engine === "plugin-scanner" || engine === "full-prism";
  const sessionKey = entry.caseData.sessionKey ?? `bench:${entry.caseData.name}`;
  const conversationId = entry.caseData.conversationId ?? `${sessionKey}:conversation`;
    const pluginConfig: Record<string, unknown> = {
      persistRiskState: false,
      outboundSecretPatterns: BENCHMARK_OUTBOUND_SECRET_PATTERNS,
      ...(useRemoteScanner && runtime.scannerService
        ? {
            scannerUrl: runtime.scannerService.url,
            scannerTimeoutMs: runtime.pluginScannerTimeoutMs,
          }
        : { scannerUrl: "http://127.0.0.1:1/scan" }),
    };
  const { api, hooks } = createPluginMockApi(pluginConfig);
  const originalScannerAuthToken = process.env.SCANNER_AUTH_TOKEN;
  const stepResults: Array<Record<string, unknown>> = [];
  const actions: string[] = [];

  riskBySession.clear();
  cleanupAll();

  if (useRemoteScanner && runtime.scannerService) {
    process.env.SCANNER_AUTH_TOKEN = runtime.scannerService.authToken;
  } else {
    delete process.env.SCANNER_AUTH_TOKEN;
  }

  try {
    registerPlugin(api);
    for (const step of entry.caseData.steps) {
      if (step.type === "message_received") {
        getPluginHook(hooks, "message_received")(
          { from: "user", content: step.content },
          { channelId: "benchmark", conversationId },
        );
        stepResults.push({ type: step.type, conversationRisk: getSessionRisk(conversationId)?.score ?? 0 });
        continue;
      }

      if (step.type === "before_prompt_build") {
        const result = getPluginHook(hooks, "before_prompt_build")(
          { prompt: step.prompt, messages: [] },
          { sessionKey, channelId: "benchmark" },
        );
        stepResults.push({
          type: step.type,
          prependContext: typeof result?.prependContext === "string",
          sessionRisk: getSessionRisk(sessionKey)?.score ?? 0,
        });
        continue;
      }

      if (step.type === "before_tool_call") {
        const result = getPluginHook(hooks, "before_tool_call")(
          { toolName: step.toolName, params: step.params ?? {} },
          { sessionKey, toolName: step.toolName },
        );
        if (result?.block) actions.push("tool-block");
        stepResults.push({ type: step.type, result });
        continue;
      }

      if (step.type === "after_tool_call") {
        await getPluginHook(hooks, "after_tool_call")(
          { toolName: step.toolName, result: { content: step.resultText } },
          { sessionKey, toolName: step.toolName },
        );
        stepResults.push({
          type: step.type,
          sessionRisk: getSessionRisk(sessionKey)?.score ?? 0,
        });
        continue;
      }

      if (step.type === "tool_result_persist") {
        const originalMessage = { role: step.role ?? "tool", content: step.content };
        const result = getPluginHook(hooks, "tool_result_persist")(
          { toolName: step.toolName, message: originalMessage },
          { toolName: step.toolName },
        );
        const changed = JSON.stringify(result?.message ?? originalMessage) !== JSON.stringify(originalMessage);
        if (changed) actions.push("persist-redaction");
        stepResults.push({ type: step.type, changed });
        continue;
      }

      if (step.type === "before_message_write") {
        const originalMessage = { role: step.role ?? "tool", content: step.content };
        const result = getPluginHook(hooks, "before_message_write")(
          { message: originalMessage },
          { sessionKey },
        );
        const changed = JSON.stringify(result?.message ?? originalMessage) !== JSON.stringify(originalMessage);
        if (changed) actions.push("write-redaction");
        stepResults.push({ type: step.type, changed });
        continue;
      }

      if (step.type === "message_sending") {
        const result = getPluginHook(hooks, "message_sending")(
          { to: "user", content: step.content },
          { channelId: "benchmark", conversationId },
        );
        if (result?.cancel) actions.push("outbound-block");
        stepResults.push({ type: step.type, result });
        continue;
      }

      if (step.type === "subagent_spawning") {
        const result = getPluginHook(hooks, "subagent_spawning")(
          {
            childSessionKey: step.childSessionKey ?? `${sessionKey}:child`,
            agentId: step.agentId ?? "bench-subagent",
            mode: "run",
            threadRequested: false,
          },
          { requesterSessionKey: sessionKey },
        );
        if (result?.status === "error") actions.push("spawn-block");
        stepResults.push({ type: step.type, result });
        continue;
      }
    }

    const predictedClass: ExpectedClass = actions.length > 0 ? "attack" : "benign";
    return {
      ...base,
      supported: true,
      passed: predictedClass === entry.caseData.expectedClass,
      expectedClass: entry.caseData.expectedClass,
      predictedClass,
      raw: {
        actions,
        stepResults,
        sessionRisk: getSessionRisk(sessionKey),
        conversationRisk: getSessionRisk(conversationId),
      },
    };
  } finally {
    getPluginHook(hooks, "session_end")(
      { sessionId: `${sessionKey}:end`, sessionKey, messageCount: entry.caseData.steps.length },
      { sessionId: `${sessionKey}:end`, sessionKey },
    );
    cleanupAll();
    riskBySession.clear();
    if (originalScannerAuthToken === undefined) delete process.env.SCANNER_AUTH_TOKEN;
    else process.env.SCANNER_AUTH_TOKEN = originalScannerAuthToken;
  }
}

async function executeCase(engine: EngineName, entry: LoadedCase, runtime: BenchmarkRuntime): Promise<CaseResult> {
  const base = {
    caseId: entry.id,
    caseName: entry.caseData.name,
    suite: entry.suite,
    engine,
    sourceFile: entry.sourceFile,
  };

  if (engine === "no-prism") {
    return executeNoPrismCase(entry, base);
  }

  if (engine === "heuristics-only") {
    return executeHeuristicsOnlyCase(entry, base);
  }

  if (engine === "heuristic") {
    if (entry.caseData.kind !== "scan-text") {
      return { ...base, supported: false, passed: null, expectedClass: null, predictedClass: null, raw: { reason: "unsupported-kind" } };
    }
    const verdict = heuristicScan(entry.caseData.text);
    const predictedClass: ExpectedClass = verdict.suspicious ? "attack" : "benign";
    return {
      ...base,
      supported: true,
      passed: predictedClass === entry.caseData.expectedClass,
      expectedClass: entry.caseData.expectedClass,
      predictedClass,
      raw: {
        suspicious: verdict.suspicious,
        score: verdict.score,
        reasons: verdict.reasons,
      },
    };
  }

  if (engine === "scanner") {
    if (entry.caseData.kind !== "scan-text") {
      return { ...base, supported: false, passed: null, expectedClass: null, predictedClass: null, raw: { reason: "unsupported-kind" } };
    }
    const verdict = await classify(entry.caseData.text);
    const predictedClass: ExpectedClass = verdict.verdict === "benign" ? "benign" : "attack";
    return {
      ...base,
      supported: true,
      passed: predictedClass === entry.caseData.expectedClass,
      expectedClass: entry.caseData.expectedClass,
      predictedClass,
      raw: {
        verdict: verdict.verdict,
        score: verdict.score,
        reasons: verdict.reasons,
        path: verdict.path,
        heuristicScore: verdict.heuristicScore,
        heuristicSuspicious: verdict.heuristicSuspicious,
        modelVerdict: verdict.modelVerdict,
        modelScore: verdict.modelScore,
        modelUsed: verdict.modelUsed,
      },
    };
  }

  if (engine === "plugin-only" || engine === "plugin-scanner") {
    if (entry.caseData.kind === "plugin-flow") {
      return executePluginFlowCase(engine, entry as LoadedCase & { caseData: PluginFlowCase }, runtime);
    }
    if (entry.caseData.kind !== "invoke-policy") {
      return { ...base, supported: false, passed: null, expectedClass: null, predictedClass: null, raw: { reason: "unsupported-kind" } };
    }
    const expectedClass = classifyExpectedAllow(entry.caseData.expectedAllow);
    const predictedClass: ExpectedClass = "benign";
    return {
      ...base,
      supported: true,
      passed: entry.caseData.expectedAllow === true,
      expectedClass,
      predictedClass,
      raw: {
        mode: "pass-through",
        policyLayer: "disabled",
      },
    };
  }

  if (engine === "full-prism") {
    if (entry.caseData.kind === "plugin-flow") {
      return executePluginFlowCase("full-prism", entry as LoadedCase & { caseData: PluginFlowCase }, runtime);
    }
    if (entry.caseData.kind !== "invoke-policy") {
      return { ...base, supported: false, passed: null, expectedClass: null, predictedClass: null, raw: { reason: "unsupported-kind" } };
    }
    const policyPath = entry.caseData.policyPath
      ? resolve(dirname(resolve(REPO_ROOT, entry.sourceFile)), entry.caseData.policyPath)
      : DEFAULT_POLICY_PATH;
    const decision = evaluateInvokePolicy(
      loadPolicyCached(policyPath),
      entry.caseData.token,
      entry.caseData.request,
    );
    const expectedClass = classifyExpectedAllow(entry.caseData.expectedAllow);
    const predictedClass = classifyDecision(decision);
    return {
      ...base,
      supported: true,
      passed: decision.allow === entry.caseData.expectedAllow,
      expectedClass,
      predictedClass,
      raw: {
        allow: decision.allow,
        status: decision.status,
        reasonCode: decision.reasonCode,
        matchedRulePath: decision.matchedRulePath,
        policyPath: relative(REPO_ROOT, policyPath),
      },
    };
  }

  if (entry.caseData.kind !== "invoke-policy") {
    return { ...base, supported: false, passed: null, expectedClass: null, predictedClass: null, raw: { reason: "unsupported-kind" } };
  }
  const policyPath = entry.caseData.policyPath
    ? resolve(dirname(resolve(REPO_ROOT, entry.sourceFile)), entry.caseData.policyPath)
    : DEFAULT_POLICY_PATH;
  const decision = evaluateInvokePolicy(
    loadPolicyCached(policyPath),
    entry.caseData.token,
    entry.caseData.request,
  );
  const expectedClass = classifyExpectedAllow(entry.caseData.expectedAllow);
  const predictedClass = classifyDecision(decision);
  return {
    ...base,
    supported: true,
    passed: decision.allow === entry.caseData.expectedAllow,
    expectedClass,
    predictedClass,
    raw: {
      allow: decision.allow,
      status: decision.status,
      reasonCode: decision.reasonCode,
      matchedRulePath: decision.matchedRulePath,
      policyPath: relative(REPO_ROOT, policyPath),
    },
  };
}

function ratio(numerator: number, denominator: number): number | null {
  return denominator > 0 ? numerator / denominator : null;
}

function toRoundedMs(value: number): number {
  return Number(value.toFixed(3));
}

function percentile(values: number[], p: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return toRoundedMs(sorted[idx]!);
}

function buildProfiling(caseDurationsMs: number[], cpuUsage: NodeJS.CpuUsage, wallTimeMs: number, rssStart: number, rssPeak: number, rssEnd: number): EngineProfiling {
  const cpuUserMs = toRoundedMs(cpuUsage.user / 1000);
  const cpuSystemMs = toRoundedMs(cpuUsage.system / 1000);
  const cpuTotalMs = toRoundedMs(cpuUserMs + cpuSystemMs);
  const avgCaseMs =
    caseDurationsMs.length > 0
      ? toRoundedMs(caseDurationsMs.reduce((sum, value) => sum + value, 0) / caseDurationsMs.length)
      : null;

  return {
    wallTimeMs: toRoundedMs(wallTimeMs),
    avgCaseMs,
    p50CaseMs: percentile(caseDurationsMs, 50),
    p95CaseMs: percentile(caseDurationsMs, 95),
    p99CaseMs: percentile(caseDurationsMs, 99),
    cpuUserMs,
    cpuSystemMs,
    cpuTotalMs,
    avgCpuMsPerCase: caseDurationsMs.length > 0 ? toRoundedMs(cpuTotalMs / caseDurationsMs.length) : null,
    peakRssDeltaMiB: toRoundedMs((rssPeak - rssStart) / BYTES_PER_MEBIBYTE),
    endRssDeltaMiB: toRoundedMs((rssEnd - rssStart) / BYTES_PER_MEBIBYTE),
  };
}

function computeMetrics(results: CaseResult[]): BinaryMetrics | null {
  const executed = results.filter((result) => result.supported && result.expectedClass && result.predictedClass);
  if (executed.length === 0) return null;

  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const result of executed) {
    const expected = result.expectedClass!;
    const predicted = result.predictedClass!;
    if (expected === "attack" && predicted === "attack") tp++;
    else if (expected === "benign" && predicted === "benign") tn++;
    else if (expected === "benign" && predicted === "attack") fp++;
    else fn++;
  }

  return {
    tp,
    tn,
    fp,
    fn,
    accuracy: ratio(tp + tn, tp + tn + fp + fn),
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    f1: (() => {
      const precision = ratio(tp, tp + fp);
      const recall = ratio(tp, tp + fn);
      return precision !== null && recall !== null && precision + recall > 0
        ? (2 * precision * recall) / (precision + recall)
        : null;
    })(),
    attackBlockRate: ratio(tp, tp + fn),
    falsePositiveRate: ratio(fp, fp + tn),
  };
}

function summarizeBySuite(results: CaseResult[]): SuiteSummary[] {
  const suiteNames = [...new Set(results.map((result) => result.suite))].sort();
  return suiteNames.map((suite) => {
    const suiteResults = results.filter((result) => result.suite === suite);
    const executed = suiteResults.filter((result) => result.supported);
    const passed = executed.filter((result) => result.passed === true).length;
    const failed = executed.filter((result) => result.passed === false).length;
    const skipped = suiteResults.filter((result) => !result.supported).length;
    return {
      suite,
      executed: executed.length,
      passed,
      failed,
      skipped,
      metrics: computeMetrics(executed),
    };
  });
}

async function buildEngineReport(
  engine: EngineName,
  loadedCases: LoadedCase[],
  runtime: BenchmarkRuntime,
): Promise<EngineReport> {
  const results: CaseResult[] = [];
  const supportedCaseDurationsMs: number[] = [];
  const cpuStart = process.cpuUsage();
  const wallStart = performance.now();
  const rssStart = process.memoryUsage().rss;
  let rssPeak = rssStart;

  for (const entry of loadedCases) {
    const caseStart = performance.now();
    const result = await executeCase(engine, entry, runtime);
    const durationMs = toRoundedMs(performance.now() - caseStart);
    result.raw = { ...result.raw, durationMs };
    if (result.supported) {
      supportedCaseDurationsMs.push(durationMs);
    }
    rssPeak = Math.max(rssPeak, process.memoryUsage().rss);
    results.push(result);
  }

  const wallTimeMs = performance.now() - wallStart;
  const cpuUsage = process.cpuUsage(cpuStart);
  const rssEnd = process.memoryUsage().rss;

  const executed = results.filter((result) => result.supported);
  const passed = executed.filter((result) => result.passed === true).length;
  const failed = executed.filter((result) => result.passed === false).length;
  const skipped = results.filter((result) => !result.supported).length;

  return {
    engine,
    summary: {
      totalCases: results.length,
      executed: executed.length,
      passed,
      failed,
      skipped,
      metrics: computeMetrics(executed),
      profiling: buildProfiling(supportedCaseDurationsMs, cpuUsage, wallTimeMs, rssStart, rssPeak, rssEnd),
    },
    suites: summarizeBySuite(results),
    results,
  };
}

function printSummary(report: BenchmarkReport): void {
  process.stdout.write(`[benchmark] loaded ${report.totalLoadedCases} cases\n`);
  if (report.scanner) {
    process.stdout.write(
      `[benchmark] scanner-mode=${report.scanner.mode} model=${report.scanner.ollamaModel} timeoutMs=${report.scanner.ollamaTimeoutMs} assisted=${report.scanner.modelAssistedCases}\n`,
    );
  }
  for (const engine of report.reports) {
    const summary = engine.summary;
    process.stdout.write(
      `[benchmark] ${engine.engine}: executed=${summary.executed} passed=${summary.passed} failed=${summary.failed} skipped=${summary.skipped}\n`,
    );
    if (summary.metrics) {
      process.stdout.write(
        `[benchmark] ${engine.engine}: accuracy=${formatMetric(summary.metrics.accuracy)} ` +
          `precision=${formatMetric(summary.metrics.precision)} ` +
          `recall=${formatMetric(summary.metrics.recall)} ` +
          `f1=${formatMetric(summary.metrics.f1)}\n`,
      );
    }
    process.stdout.write(
      `[benchmark] ${engine.engine}: p50=${formatMetric(summary.profiling.p50CaseMs)}ms ` +
        `p95=${formatMetric(summary.profiling.p95CaseMs)}ms ` +
        `p99=${formatMetric(summary.profiling.p99CaseMs)}ms ` +
        `cpu/case=${formatMetric(summary.profiling.avgCpuMsPerCase)}ms ` +
        `peak-rss-delta=${summary.profiling.peakRssDeltaMiB.toFixed(3)}MiB\n`,
    );
  }
  if (report.suiteFilter?.length) {
    process.stdout.write(`[benchmark] suites=${report.suiteFilter.join(",")}\n`);
  }
  process.stdout.write(`[benchmark] report written to ${report.outputPath}\n`);
}

function scannerEngineEnabled(engines: EngineName[]): boolean {
  return engines.includes("scanner") || engines.includes("plugin-scanner") || engines.includes("full-prism");
}

function formatMetric(value: number | null): string {
  return value === null ? "n/a" : value.toFixed(3);
}

type MockOllamaHandle = {
  url: string;
  close: () => Promise<void>;
};

type ScannerServiceHandle = {
  url: string;
  authToken: string;
  getModelAssistedCases: () => number;
  close: () => Promise<void>;
};

type HookHandler = (...args: any[]) => any;

function createPluginMockApi(pluginConfig: Record<string, unknown> = {}) {
  const hooks = new Map<string, HookHandler[]>();
  const api = {
    id: "prism-security",
    name: "PRISM",
    source: "benchmark",
    config: {},
    pluginConfig,
    runtime: {},
    logger: { info: () => {}, warn: () => {}, error: () => {} },
    registerTool: () => {},
    registerHook: () => {},
    registerHttpRoute: () => {},
    registerChannel: () => {},
    registerGatewayMethod: () => {},
    registerCli: () => {},
    registerService: () => {},
    registerProvider: () => {},
    registerCommand: () => {},
    resolvePath: (p: string) => p,
    on: (hookName: string, handler: HookHandler) => {
      if (!hooks.has(hookName)) hooks.set(hookName, []);
      hooks.get(hookName)!.push(handler);
    },
  };
  return { api: api as any, hooks };
}

function getPluginHook(hooks: Map<string, HookHandler[]>, name: string): HookHandler {
  const handlers = hooks.get(name);
  if (!handlers?.length) {
    throw new Error(`plugin hook not registered: ${name}`);
  }
  return handlers[0]!;
}

function buildScannerMockMap(loadedCases: LoadedCase[]): Map<string, { verdict: "benign" | "suspicious" | "malicious"; score: number; reasons: string[] }> {
  const map = new Map<string, { verdict: "benign" | "suspicious" | "malicious"; score: number; reasons: string[] }>();
  for (const entry of loadedCases) {
    if (entry.caseData.kind === "scan-text" && entry.caseData.scannerMock) {
      map.set(entry.caseData.text, {
        verdict: entry.caseData.scannerMock.verdict,
        score: entry.caseData.scannerMock.score ?? 0,
        reasons: entry.caseData.scannerMock.reasons ?? [],
      });
      continue;
    }
    if (entry.caseData.kind === "plugin-flow") {
      for (const step of entry.caseData.steps) {
        if (step.type !== "after_tool_call" || !step.scannerMock) continue;
        map.set(step.resultText, {
          verdict: step.scannerMock.verdict,
          score: step.scannerMock.score ?? 0,
          reasons: step.scannerMock.reasons ?? [],
        });
      }
    }
  }
  return map;
}

function countScannerMockCases(loadedCases: LoadedCase[]): number {
  let count = 0;
  for (const entry of loadedCases) {
    if (entry.caseData.kind === "scan-text" && entry.caseData.scannerMock) {
      count++;
      continue;
    }
    if (entry.caseData.kind === "plugin-flow") {
      count += entry.caseData.steps.filter((step) => step.type === "after_tool_call" && !!step.scannerMock).length;
    }
  }
  return count;
}

function extractScannerPromptText(prompt: string): string {
  const marker = "\n\nText:\n";
  const idx = prompt.indexOf(marker);
  return idx >= 0 ? prompt.slice(idx + marker.length) : prompt;
}

async function startMockOllama(loadedCases: LoadedCase[]): Promise<MockOllamaHandle> {
  const responses = buildScannerMockMap(loadedCases);
  const server = http.createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/api/generate") {
      res.statusCode = 404;
      res.end("not found");
      return;
    }

    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      try {
        const body = JSON.parse(raw) as { prompt?: string };
        const text = extractScannerPromptText(body.prompt ?? "");
        const matched = responses.get(text);
        if (!matched) {
          res.statusCode = 503;
          res.setHeader("content-type", "application/json; charset=utf-8");
          res.end(JSON.stringify({ error: "no mock response configured" }));
          return;
        }

        res.statusCode = 200;
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify({
          response: JSON.stringify({
            verdict: matched.verdict,
            score: matched.score,
            reasons: matched.reasons,
          }),
        }));
      } catch (error) {
        res.statusCode = 400;
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ error: String(error) }));
      }
    });
  });

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("mock ollama server failed to bind to a TCP port");
  }

  return {
    url: `http://127.0.0.1:${address.port}/api/generate`,
    close: async () => {
      server.close();
      await once(server, "close");
    },
  };
}

async function startScannerService(): Promise<ScannerServiceHandle> {
  const authToken = "benchmark-scanner-token";
  const originalToken = process.env.SCANNER_AUTH_TOKEN;
  let modelAssistedCases = 0;
  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz") {
      res.statusCode = 200;
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method !== "POST" || req.url !== "/scan") {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: "not found" }));
      return;
    }
    const auth = String(req.headers.authorization ?? "");
    if (auth !== `Bearer ${authToken}`) {
      res.statusCode = 401;
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 120_000) req.destroy();
    });
    req.on("end", async () => {
      try {
        const body = JSON.parse(raw || "{}") as { text?: string };
        const result = await classify(String(body.text ?? ""));
        if (result.modelUsed) modelAssistedCases++;
        res.statusCode = 200;
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify(result));
      } catch (error) {
        res.statusCode = 400;
        res.setHeader("content-type", "application/json; charset=utf-8");
        res.end(JSON.stringify({ error: String(error) }));
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("scanner service failed to bind to a TCP port");
  }
  return {
    url: `http://127.0.0.1:${address.port}/scan`,
    authToken,
    getModelAssistedCases: () => modelAssistedCases,
    close: async () => {
      server.close();
      await once(server, "close");
      if (originalToken === undefined) delete process.env.SCANNER_AUTH_TOKEN;
      else process.env.SCANNER_AUTH_TOKEN = originalToken;
    },
  };
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const loadedCases = loadCases(opts.caseRoots, opts.suiteFilter);
  if (loadedCases.length === 0) {
    process.stdout.write("[benchmark] no cases found; add JSON cases under the selected case roots\n");
  }

  const originalOllamaUrl = process.env.OLLAMA_URL;
  let mockOllama: MockOllamaHandle | null = null;
  let scannerService: ScannerServiceHandle | null = null;
  if (opts.scannerMode === "mock" && opts.engines.includes("scanner")) {
    mockOllama = await startMockOllama(loadedCases);
    process.env.OLLAMA_URL = mockOllama.url;
    process.stdout.write(`[benchmark] scanner mock Ollama: ${mockOllama.url}\n`);
  }
  if (opts.scannerMode === "mock" && (opts.engines.includes("plugin-scanner") || opts.engines.includes("full-prism"))) {
    if (!mockOllama) {
      mockOllama = await startMockOllama(loadedCases);
      process.env.OLLAMA_URL = mockOllama.url;
      process.stdout.write(`[benchmark] scanner mock Ollama: ${mockOllama.url}\n`);
    }
  }
  if (opts.engines.includes("plugin-scanner") || opts.engines.includes("full-prism")) {
    scannerService = await startScannerService();
    process.stdout.write(`[benchmark] plugin scanner service: ${scannerService.url}\n`);
  }

  try {
      const reports: EngineReport[] = [];
      for (const engine of opts.engines) {
        reports.push(
          await buildEngineReport(engine, loadedCases, {
            scannerService,
            scannerMode: opts.scannerMode,
            pluginScannerTimeoutMs: getPluginScannerTimeoutMs(opts.scannerMode),
          }),
        );
      }

    mkdirSync(dirname(opts.outputPath), { recursive: true });
    const report: BenchmarkReport = {
      generatedAt: new Date().toISOString(),
      repoRoot: REPO_ROOT,
      caseRoots: opts.caseRoots,
      suiteFilter: opts.suiteFilter,
      outputPath: opts.outputPath,
      engines: opts.engines,
      totalLoadedCases: loadedCases.length,
        scanner: scannerEngineEnabled(opts.engines)
          ? {
              mode: opts.scannerMode,
              requireAssistedPath: opts.requireScannerAssistedPath,
              ollamaUrl: getOllamaUrl(),
              ollamaModel: getOllamaModel(),
              ollamaTimeoutMs: getOllamaTimeoutMs(),
              ollamaTemperature: getOllamaTemperature(),
              ollamaSeed: getOllamaSeed(),
              pluginScannerTimeoutMs: getPluginScannerTimeoutMs(opts.scannerMode),
              mockAnnotatedCases: countScannerMockCases(loadedCases),
              modelAssistedCases:
                (scannerService?.getModelAssistedCases() ?? 0) +
                reports
                .flatMap((engine) => engine.results)
                .filter((result) => result.supported && result.raw.modelUsed === true).length,
          }
        : null,
      reports,
    };
    writeFileSync(opts.outputPath, JSON.stringify(report, null, 2) + "\n");
    printSummary(report);
    if (
      report.scanner &&
      opts.requireScannerAssistedPath &&
      report.scanner.modelAssistedCases === 0
    ) {
      process.stderr.write(
        "[benchmark] ERROR scanner assisted path was required but zero cases used the model-assisted path\n",
      );
      process.exitCode = 1;
    }
  } finally {
    if (scannerService) {
      await scannerService.close();
    }
    if (mockOllama) {
      await mockOllama.close();
    }
    if (originalOllamaUrl === undefined) delete process.env.OLLAMA_URL;
    else process.env.OLLAMA_URL = originalOllamaUrl;
  }
}

void main().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  process.stderr.write(`[benchmark] ERROR ${message}\n`);
  process.exitCode = 1;
});
