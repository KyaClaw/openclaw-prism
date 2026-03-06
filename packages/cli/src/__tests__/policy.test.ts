import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { runPolicyFixtureSuite, runPolicySimulation } from "../policy.js";

const POLICY_PATH = fileURLToPath(
  new URL("../../../../config/invoke-guard.policy.json", import.meta.url),
);
const FIXTURE_PATH = fileURLToPath(
  new URL("../../../../config/invoke-guard.simulator.fixtures.json", import.meta.url),
);

describe("policy simulator CLI helpers", () => {
  it("simulates one invoke request with deterministic explain path", () => {
    const result = runPolicySimulation({
      policyPath: POLICY_PATH,
      token: "replace-with-long-random-token",
      requestJson: JSON.stringify({
        tool: "read",
        sessionKey: "agent:example:sim",
        args: { path: "/tmp/demo.txt" },
      }),
    });

    expect(result.allow).toBe(true);
    expect(result.status).toBe(200);
    expect(result.reasonCode).toBe("allow");
    expect(result.matchedRulePath).toBe("clients[0].allowTools[1]");
  });

  it("executes fixture regression suite from repo fixtures", () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const result = runPolicyFixtureSuite({
      policyPath: POLICY_PATH,
      fixturesPath: FIXTURE_PATH,
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line),
    });

    expect(result.total).toBeGreaterThan(0);
    expect(result.failed).toBe(0);
    expect(stderr).toHaveLength(0);
    expect(stdout.at(-1)).toContain("0 failed");
  });
});
