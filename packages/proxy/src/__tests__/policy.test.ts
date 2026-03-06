import { describe, expect, it } from "vitest";
import { evaluateInvokePolicy } from "../policy.js";
import type { Policy } from "../policy.js";

const POLICY: Policy = {
  host: "127.0.0.1",
  port: 0,
  upstreamUrl: "http://127.0.0.1:19999",
  upstreamTokenEnv: "TEST_UPSTREAM_TOKEN",
  defaultDenyTools: ["browser"],
  clients: [
    {
      id: "fixture-client",
      token: "fixture-token",
      allowedSessionPrefixes: ["fixture:"],
      allowTools: ["read", "exec", "browser", "bash"],
      denyTools: ["exec"],
    },
  ],
};

describe("evaluateInvokePolicy", () => {
  it("allows request and returns matching allowTools path", () => {
    const result = evaluateInvokePolicy(POLICY, "fixture-token", {
      tool: "read",
      sessionKey: "fixture:1",
      args: { path: "/tmp/demo.txt" },
    });
    expect(result.allow).toBe(true);
    expect(result.status).toBe(200);
    expect(result.reasonCode).toBe("allow");
    expect(result.matchedRulePath).toBe("clients[0].allowTools[0]");
  });

  it("denies default-deny tools with explicit path", () => {
    const result = evaluateInvokePolicy(POLICY, "fixture-token", {
      tool: "browser",
      sessionKey: "fixture:2",
    });
    expect(result.allow).toBe(false);
    expect(result.reasonCode).toBe("tool-default-deny");
    expect(result.matchedRulePath).toBe("defaultDenyTools[0]");
  });

  it("denies client deny-list tools with explicit path", () => {
    const result = evaluateInvokePolicy(POLICY, "fixture-token", {
      tool: "exec",
      sessionKey: "fixture:3",
      args: { command: "echo safe" },
    });
    expect(result.allow).toBe(false);
    expect(result.reasonCode).toBe("tool-client-deny");
    expect(result.matchedRulePath).toBe("clients[0].denyTools[0]");
  });

  it("denies dangerous exec and reports built-in guard path", () => {
    const result = evaluateInvokePolicy(POLICY, "fixture-token", {
      tool: "bash",
      sessionKey: "fixture:4",
      args: { command: "bash -c whoami" },
    });
    expect(result.allow).toBe(false);
    expect(result.reasonCode).toBe("dangerous-exec");
    expect(result.matchedRulePath).toBe("builtin.execDanger.shell-trampoline");
  });
});
