import { existsSync, readFileSync } from "node:fs";
import { evaluateInvokePolicy, loadPolicy } from "@kyaclaw/proxy/policy";
import type { InvokeBody, InvokePolicyDecision } from "@kyaclaw/proxy/policy";

type FixtureExpectation = {
  allow: boolean;
  status: number;
  reasonCode: string;
  matchedRulePath: string;
};

type FixtureCase = {
  name: string;
  token: string;
  request: InvokeBody;
  expect: FixtureExpectation;
};

type FixtureSuiteResult = {
  total: number;
  passed: number;
  failed: number;
};

type SimulateRequestOpts = {
  token: string;
  policyPath: string;
  requestJson?: string;
  requestFile?: string;
};

type RunFixturesOpts = {
  policyPath: string;
  fixturesPath: string;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
};

function ensureObject(input: unknown, source: string): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`expected JSON object in ${source}`);
  }
  return input as Record<string, unknown>;
}

function parseJsonObject(raw: string, source: string): Record<string, unknown> {
  try {
    return ensureObject(JSON.parse(raw), source);
  } catch (err) {
    throw new Error(`invalid json in ${source}: ${String(err)}`);
  }
}

function parseFixtureCase(entry: unknown, index: number): FixtureCase {
  const record = ensureObject(entry, `fixtures[${index}]`);
  const name = typeof record.name === "string" && record.name.trim()
    ? record.name.trim()
    : `fixture-${index + 1}`;
  const token = typeof record.token === "string" ? record.token : "";
  const request = ensureObject(record.request, `fixtures[${index}].request`) as InvokeBody;
  const expectRaw = ensureObject(record.expect, `fixtures[${index}].expect`);

  const allow = expectRaw.allow;
  const status = expectRaw.status;
  const reasonCode = expectRaw.reasonCode;
  const matchedRulePath = expectRaw.matchedRulePath;
  if (typeof allow !== "boolean") {
    throw new Error(`fixtures[${index}].expect.allow must be boolean`);
  }
  if (typeof status !== "number" || !Number.isInteger(status)) {
    throw new Error(`fixtures[${index}].expect.status must be integer`);
  }
  if (typeof reasonCode !== "string" || !reasonCode) {
    throw new Error(`fixtures[${index}].expect.reasonCode must be non-empty string`);
  }
  if (typeof matchedRulePath !== "string" || !matchedRulePath) {
    throw new Error(`fixtures[${index}].expect.matchedRulePath must be non-empty string`);
  }

  return {
    name,
    token,
    request,
    expect: { allow, status, reasonCode, matchedRulePath },
  };
}

function decisionMatchesExpectation(
  decision: InvokePolicyDecision,
  expected: FixtureExpectation,
): boolean {
  return decision.allow === expected.allow &&
    decision.status === expected.status &&
    decision.reasonCode === expected.reasonCode &&
    decision.matchedRulePath === expected.matchedRulePath;
}

function selectRequestPayload(opts: SimulateRequestOpts): Record<string, unknown> {
  const hasJson = opts.requestJson !== undefined;
  const hasFile = opts.requestFile !== undefined;
  if (hasJson === hasFile) {
    throw new Error("provide exactly one of --request or --request-file");
  }

  if (opts.requestJson !== undefined) {
    return parseJsonObject(opts.requestJson, "--request");
  }

  if (!existsSync(opts.requestFile!)) {
    throw new Error(`request file not found: ${opts.requestFile}`);
  }
  const raw = readFileSync(opts.requestFile!, "utf8");
  return parseJsonObject(raw, opts.requestFile!);
}

export function runPolicySimulation(opts: SimulateRequestOpts): InvokePolicyDecision {
  const policy = loadPolicy(opts.policyPath);
  const request = selectRequestPayload(opts);
  return evaluateInvokePolicy(policy, opts.token, request as InvokeBody);
}

export function runPolicyFixtureSuite(opts: RunFixturesOpts): FixtureSuiteResult {
  const out = opts.stdout ?? ((line: string) => process.stdout.write(line + "\n"));
  const errOut = opts.stderr ?? ((line: string) => process.stderr.write(line + "\n"));
  const policy = loadPolicy(opts.policyPath);

  if (!existsSync(opts.fixturesPath)) {
    throw new Error(`fixtures file not found: ${opts.fixturesPath}`);
  }
  const raw = readFileSync(opts.fixturesPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error(`fixtures file must be a JSON array: ${opts.fixturesPath}`);
  }

  let passed = 0;
  let failed = 0;
  for (let i = 0; i < parsed.length; i++) {
    const fixture = parseFixtureCase(parsed[i], i);
    const decision = evaluateInvokePolicy(policy, fixture.token, fixture.request);
    if (decisionMatchesExpectation(decision, fixture.expect)) {
      passed++;
      out(`[policy-fixture] PASS ${fixture.name}`);
      continue;
    }

    failed++;
    errOut(`[policy-fixture] FAIL ${fixture.name}`);
    errOut(
      `[policy-fixture] expected allow=${fixture.expect.allow} status=${fixture.expect.status} ` +
        `reason=${fixture.expect.reasonCode} path=${fixture.expect.matchedRulePath}`,
    );
    errOut(
      `[policy-fixture] actual   allow=${decision.allow} status=${decision.status} ` +
        `reason=${decision.reasonCode} path=${decision.matchedRulePath}`,
    );
  }

  out(`[policy-fixture] ${passed} passed, ${failed} failed, ${parsed.length} total`);
  return { total: parsed.length, passed, failed };
}
