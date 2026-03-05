#!/usr/bin/env node
import http from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { heuristicScan } from "@kyaclaw/shared/heuristics";

const HOST = process.env.SCANNER_HOST ?? "127.0.0.1";
const PORT = Number(process.env.SCANNER_PORT ?? "18766");
const OLLAMA_URL = process.env.OLLAMA_URL ?? "http://127.0.0.1:11434/api/generate";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL ?? "qwen3:30b";
const MAX_TEXT = 30_000;
const TIMEOUT_MS = 3_000;

function json(res: http.ServerResponse, status: number, payload: unknown) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(payload));
}

function readBearer(req: http.IncomingMessage): string {
  const raw = String(req.headers["authorization"] ?? "");
  if (!raw.toLowerCase().startsWith("bearer ")) return "";
  return raw.slice(7).trim();
}

function digestToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

function tokenMatches(expected: string, provided: string): boolean {
  return timingSafeEqual(digestToken(expected), digestToken(provided));
}

function getScannerAuthToken(): string {
  return process.env.SCANNER_AUTH_TOKEN ?? "";
}

async function ollamaJudge(
  text: string,
): Promise<{ verdict: string; score: number; reasons: string[] }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const resp = await fetch(OLLAMA_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        stream: false,
        prompt:
          `Classify prompt injection risk. Return ONLY JSON: {"verdict":"benign|suspicious|malicious","score":0-100,"reasons":["..."]}\n\nText:\n` +
          text.slice(0, MAX_TEXT),
        options: { temperature: 0.1 },
      }),
    });
    if (!resp.ok) throw new Error(`ollama ${resp.status}`);
    const data = (await resp.json()) as { response: string };
    const match = data.response.match(/\{[\s\S]*\}/);
    if (match) {
      const parsed = JSON.parse(match[0]);
      return {
        verdict:
          parsed.verdict === "malicious" || parsed.verdict === "suspicious"
            ? parsed.verdict
            : "benign",
        score: Math.max(0, Math.min(100, Number(parsed.score) || 0)),
        reasons: Array.isArray(parsed.reasons)
          ? parsed.reasons.map(String).slice(0, 8)
          : [],
      };
    }
    return { verdict: "benign", score: 0, reasons: [] };
  } finally {
    clearTimeout(timer);
  }
}

export async function classify(text: string) {
  const h = heuristicScan(text);
  if (h.score >= 70)
    return { verdict: "malicious" as const, score: h.score, reasons: h.reasons };

  try {
    const m = await ollamaJudge(text);
    const score = Math.max(h.score, m.score);
    const reasons = [...new Set([...h.reasons, ...m.reasons])];
    if (m.verdict === "malicious" || score >= 75)
      return { verdict: "malicious" as const, score, reasons };
    if (m.verdict === "suspicious" || score >= 35)
      return { verdict: "suspicious" as const, score, reasons };
    return { verdict: "benign" as const, score, reasons };
  } catch {
    return {
      verdict: h.suspicious ? ("suspicious" as const) : ("benign" as const),
      score: h.score,
      reasons: h.reasons,
    };
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/healthz")
      return json(res, 200, { ok: true });
    if (req.method !== "POST" || req.url !== "/scan")
      return json(res, 404, { error: "not found" });
    const scannerAuthToken = getScannerAuthToken();
    if (!scannerAuthToken) {
      return json(res, 503, { error: "SCANNER_AUTH_TOKEN is required" });
    }
    const providedToken = readBearer(req);
    if (!providedToken || !tokenMatches(scannerAuthToken, providedToken)) {
      return json(res, 401, { error: "unauthorized" });
    }

    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (c) => {
      raw += c;
      if (raw.length > MAX_TEXT * 4) req.destroy();
    });
    req.on("end", async () => {
      try {
        const body = JSON.parse(raw || "{}") as { text?: string };
        const result = await classify((body.text ?? "").slice(0, MAX_TEXT));
        json(res, 200, result);
      } catch (err) {
        json(res, 400, { error: String(err) });
      }
    });
  });
}

// Start server when run directly
const isMainModule = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ""));
if (isMainModule || process.env.PRISM_SCANNER_START) {
  if (!getScannerAuthToken()) {
    process.stderr.write("[scanner] SCANNER_AUTH_TOKEN is required\n");
    process.exit(1);
  }
  const server = createServer();
  server.listen(PORT, HOST, () => {
    process.stdout.write(`[scanner] http://${HOST}:${PORT}\n`);
  });
}
