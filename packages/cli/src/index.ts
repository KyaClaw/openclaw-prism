#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import { verifyAuditChain } from "@kyaclaw/shared/audit";
import { runPolicyFixtureSuite, runPolicySimulation } from "./policy.js";
import { runVerify } from "./verify.js";

// Auto-load .env from install directory
const INSTALL_DIR = "/opt/openclaw-prism";
const ENV_FILE = join(INSTALL_DIR, ".env");
if (process.env.PRISM_SKIP_DOTENV !== "1" && existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq);
    const val = trimmed.slice(eq + 1);
    if (!process.env[key]) process.env[key] = val;
  }
}

const AUDIT_DIR = join(homedir(), ".openclaw", "security");
const AUDIT_LOG = join(AUDIT_DIR, "audit.jsonl");
const VERIFY_SCANNER_URL = process.env.PRISM_VERIFY_SCANNER_URL ?? "http://127.0.0.1:18766/scan";
const VERIFY_PROXY_URL = process.env.PRISM_VERIFY_PROXY_URL ?? "http://127.0.0.1:18767/healthz";
const DEFAULT_POLICY_PATH = process.env.INVOKE_GUARD_POLICY ?? "./config/invoke-guard.policy.json";
const DEFAULT_POLICY_FIXTURES = "./config/invoke-guard.simulator.fixtures.json";

const program = new Command();
program
  .name("openclaw-prism")
  .description("PRISM — Proactive Runtime Injection Shield & Monitor")
  .version("0.1.0");

// ── start command ──
program
  .command("start")
  .argument("[service]", "Service to start: scanner, proxy, monitor, or all", "all")
  .description("Start PRISM security services")
  .action((service: string) => {
    const services = service === "all" ? ["scanner", "proxy", "monitor"] : [service];
    for (const svc of services) {
      const envKey = `PRISM_${svc.toUpperCase()}_START`;
      process.stdout.write(`[prism] starting ${svc}...\n`);

      let modulePath: string;
      switch (svc) {
        case "scanner":
          modulePath = "@kyaclaw/scanner";
          break;
        case "proxy":
          modulePath = "@kyaclaw/proxy";
          break;
        case "monitor":
          modulePath = "@kyaclaw/monitor";
          break;
        default:
          process.stderr.write(`[prism] unknown service: ${svc}\n`);
          continue;
      }

      const child = spawn(
        process.execPath,
        ["--import", "tsx", "-e", `process.env.${envKey}="1"; import("${modulePath}")`],
        { stdio: "inherit", detached: false },
      );
      child.on("error", (err) => {
        process.stderr.write(`[prism] failed to start ${svc}: ${err.message}\n`);
      });
    }
  });

// ── status command ──
program
  .command("status")
  .description("Check status of PRISM services")
  .action(async () => {
    const checks = [
      { name: "scanner", url: "http://127.0.0.1:18766/healthz" },
      { name: "proxy", url: "http://127.0.0.1:18767/healthz" },
    ];

    for (const { name, url } of checks) {
      try {
        const resp = await fetch(url, { signal: AbortSignal.timeout(2000) });
        const body = await resp.json() as { ok?: boolean };
        process.stdout.write(`[${name}] ${body.ok ? "OK" : "ERROR"} (${resp.status})\n`);
      } catch {
        process.stdout.write(`[${name}] OFFLINE\n`);
      }
    }

    // Check audit log
    if (existsSync(AUDIT_LOG)) {
      const lines = readFileSync(AUDIT_LOG, "utf8").trim().split("\n");
      process.stdout.write(`[audit] ${lines.length} entries in ${AUDIT_LOG}\n`);
    } else {
      process.stdout.write(`[audit] no audit log found\n`);
    }
  });

// ── verify command ──
program
  .command("verify")
  .description("Post-upgrade security verification")
  .action(async () => {
    const exitCode = await runVerify({
      scannerUrl: VERIFY_SCANNER_URL,
      proxyUrl: VERIFY_PROXY_URL,
      scannerToken: process.env.SCANNER_AUTH_TOKEN,
    });
    if (exitCode > 0) process.exitCode = exitCode;
  });

// ── policy subcommands ──
const policy = program.command("policy").description("Invoke-guard policy simulator");

policy
  .command("simulate")
  .requiredOption("--token <token>", "Caller token to simulate")
  .option("--policy <path>", "Policy file path", DEFAULT_POLICY_PATH)
  .option("--request <json>", "Invoke request JSON payload")
  .option("--request-file <path>", "Path to invoke request JSON file")
  .description("Dry-run one /tools/invoke request and explain allow/deny rule path")
  .action((opts: { token: string; policy: string; request?: string; requestFile?: string }) => {
    try {
      const result = runPolicySimulation({
        token: opts.token,
        policyPath: opts.policy,
        requestJson: opts.request,
        requestFile: opts.requestFile,
      });
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } catch (err) {
      process.stderr.write(`[policy] ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
  });

policy
  .command("test-fixtures")
  .option("--policy <path>", "Policy file path", DEFAULT_POLICY_PATH)
  .option("--fixtures <path>", "Fixture file path", DEFAULT_POLICY_FIXTURES)
  .description("Run fixture regression tests for invoke-guard policy decisions")
  .action((opts: { policy: string; fixtures: string }) => {
    try {
      const result = runPolicyFixtureSuite({
        policyPath: opts.policy,
        fixturesPath: opts.fixtures,
      });
      if (result.failed > 0) process.exitCode = 1;
    } catch (err) {
      process.stderr.write(`[policy] ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    }
  });

// ── audit subcommands ──
const audit = program.command("audit").description("Audit log operations");

audit
  .command("tail")
  .option("-n, --lines <count>", "Number of lines to show", "20")
  .description("Show recent audit log entries")
  .action((opts: { lines: string }) => {
    if (!existsSync(AUDIT_LOG)) {
      process.stdout.write("No audit log found.\n");
      return;
    }
    const lines = readFileSync(AUDIT_LOG, "utf8").trim().split("\n");
    const count = Math.min(Number(opts.lines) || 20, lines.length);
    const tail = lines.slice(-count);
    for (const line of tail) {
      try {
        const entry = JSON.parse(line);
        process.stdout.write(`${entry.ts} ${entry.event} ${JSON.stringify(entry)}\n`);
      } catch {
        process.stdout.write(line + "\n");
      }
    }
  });

audit
  .command("verify")
  .description("Verify audit integrity (HMAC + chain continuity)")
  .action(() => {
    if (!existsSync(AUDIT_LOG)) {
      process.stdout.write("No audit log found.\n");
      return;
    }
    const lines = readFileSync(AUDIT_LOG, "utf8").trim().split("\n");
    const result = verifyAuditChain(lines);
    const { valid, invalid, firstInvalidLine } = result;
    if (firstInvalidLine !== null) {
      process.stderr.write(`[audit] INVALID chain at line ${firstInvalidLine}\n`);
    }
    process.stdout.write(`[audit] ${valid} valid, ${invalid} invalid out of ${lines.length} entries\n`);
    if (invalid > 0) process.exitCode = 1;
  });

program.parse();
