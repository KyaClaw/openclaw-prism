import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  readConfigStore,
  updateConfigStore,
  validateSecurityConfig,
  RevisionConflictError,
  ConfigValidationError,
} from "../config-store.js";

function writePolicy(config: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "prism-dashboard-policy-"));
  const path = join(dir, "security.policy.json");
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  return path;
}

describe("config-store", () => {
  it("reads config and computes revision", () => {
    const policyPath = writePolicy({
      riskTtlMs: 180000,
      execAllowedPrefixes: ["node", "git"],
      protectedPathExceptions: [],
    });
    const loaded = readConfigStore(policyPath);
    expect(loaded.path).toBe(policyPath);
    expect(loaded.revision).toMatch(/^[0-9a-f]{16}$/);
    expect(loaded.config.execAllowedPrefixes).toEqual(["node", "git"]);
  });

  it("updates config with optimistic revision control", () => {
    const policyPath = writePolicy({
      execAllowedPrefixes: ["node"],
      execBlockedPatterns: ["rm\\s+-rf\\s+/"],
    });
    const before = readConfigStore(policyPath);
    const after = updateConfigStore({
      customPath: policyPath,
      expectedRevision: before.revision,
      config: {
        ...before.config,
        execAllowedPrefixes: ["node", "curl"],
      },
    });
    expect(after.revision).not.toBe(before.revision);
    expect(after.changedFields).toContain("execAllowedPrefixes");

    const persisted = JSON.parse(readFileSync(policyPath, "utf8")) as { execAllowedPrefixes: string[] };
    expect(persisted.execAllowedPrefixes).toEqual(["node", "curl"]);
  });

  it("throws revision conflict when expected revision mismatches", () => {
    const policyPath = writePolicy({ execAllowedPrefixes: ["node"] });
    expect(() => {
      updateConfigStore({
        customPath: policyPath,
        expectedRevision: "ffffffffffffffff",
        config: { execAllowedPrefixes: ["node", "curl"] },
      });
    }).toThrow(RevisionConflictError);
  });

  it("validates regex fields and rejects invalid patterns", () => {
    const validation = validateSecurityConfig({
      execBlockedPatterns: ["(unmatched"],
      outboundSecretPatterns: ["AKIA[0-9A-Z]{16}"],
    });
    expect(validation.valid).toBe(false);
    expect(validation.errors.some((issue) => issue.field.startsWith("execBlockedPatterns"))).toBe(true);
  });

  it("validates domain entries and rejects URLs and whitespace", () => {
    const valid = validateSecurityConfig({
      blockedDomains: ["webhook.site", "requestbin.com"],
      riskyDomains: ["ngrok.io"],
    });
    expect(valid.valid).toBe(true);

    const urlForm = validateSecurityConfig({
      blockedDomains: ["https://webhook.site/abc"],
    });
    expect(urlForm.valid).toBe(false);
    expect(urlForm.errors[0]!.message).toContain("domain, not a URL");

    const withSpace = validateSecurityConfig({
      riskyDomains: ["ngrok .io"],
    });
    expect(withSpace.valid).toBe(false);
    expect(withSpace.errors[0]!.message).toContain("whitespace");
  });

  it("throws config validation error on invalid update", () => {
    const policyPath = writePolicy({ execAllowedPrefixes: ["node"] });
    const current = readConfigStore(policyPath);
    expect(() => {
      updateConfigStore({
        customPath: policyPath,
        expectedRevision: current.revision,
        config: { execBlockedPatterns: ["(bad"] },
      });
    }).toThrow(ConfigValidationError);
  });
});
