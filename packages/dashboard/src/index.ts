#!/usr/bin/env node
import http from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { listBlockEvents, CursorNotFoundError, parseCursor } from "./audit-reader.js";
import {
  readConfigStore,
  updateConfigStore,
  validateSecurityConfig,
  RevisionConflictError,
  ConfigValidationError,
} from "./config-store.js";
import {
  applyAllowAction,
  previewAllowAction,
  describeAllowAction,
  SourceCursorNotFoundError,
  SourceCursorValidationError,
  AllowActionUnsupportedError,
  AllowActionMismatchError,
  ConfirmationRequiredError,
} from "./allow-actions.js";
import { generateHtml } from "./html.js";

const HOST = process.env.DASHBOARD_HOST ?? "127.0.0.1";
const PORT = Number(process.env.DASHBOARD_PORT ?? "18768");
const MAX_BODY = 512 * 1024; // 512KB
const INTERNAL_AUDIT_TIMEOUT_MS = 1200;
const DEFAULT_AUDIT_LOG = join(homedir(), ".openclaw", "security", "audit.jsonl");

// ── Utility functions (same pattern as scanner/proxy) ──

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

function getDashboardToken(): string | null {
  const token = process.env.PRISM_DASHBOARD_TOKEN?.trim() ?? "";
  return token ? token : null;
}

function getInternalAuditToken(): string | null {
  const token = process.env.PRISM_INTERNAL_TOKEN?.trim() ?? "";
  return token ? token : null;
}

function getInternalAuditPort(): number {
  return Number(process.env.PRISM_INTERNAL_PORT ?? "18769");
}

function getAuditPath(): string {
  return process.env.PRISM_AUDIT_LOG ?? DEFAULT_AUDIT_LOG;
}

function parseLimit(raw: string | null): number {
  const n = Number(raw ?? "100");
  if (!Number.isFinite(n) || n <= 0) return 100;
  return Math.min(1000, Math.floor(n));
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function changedFieldsFromPayload(payload: unknown): string[] {
  if (!Array.isArray(payload)) return [];
  return payload.filter((item): item is string => typeof item === "string");
}

async function readJsonBody(req: http.IncomingMessage, maxBytes = MAX_BODY): Promise<Record<string, unknown>> {
  return await new Promise<Record<string, unknown>>((resolve, reject) => {
    let raw = "";
    let ended = false;
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > maxBytes && !ended) {
        ended = true;
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (ended) return;
      try {
        const parsed = JSON.parse(raw || "{}") as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          reject(new Error("json body must be an object"));
          return;
        }
        resolve(parsed as Record<string, unknown>);
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", (err) => {
      if (ended) return;
      reject(err);
    });
  });
}

async function emitInternalAuditEvent(payload: Record<string, unknown>): Promise<boolean> {
  const token = getInternalAuditToken();
  if (!token) return false;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), INTERNAL_AUDIT_TIMEOUT_MS);
  try {
    const resp = await fetch(`http://127.0.0.1:${getInternalAuditPort()}/internal/audit`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// ── Server ──

export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const pathname = url.pathname;

    // Healthz — no auth required
    if (req.method === "GET" && pathname === "/healthz") {
      return json(res, 200, { ok: true });
    }

    // HTML page — no auth required (token entered in browser)
    if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
      const nonce = randomBytes(16).toString("base64");
      res.statusCode = 200;
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.setHeader(
        "content-security-policy",
        `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`,
      );
      res.end(generateHtml(nonce));
      return;
    }

    // All /api/* routes require Bearer token auth
    if (pathname.startsWith("/api/")) {
      const token = getDashboardToken();
      if (!token) {
        return json(res, 503, { error: "PRISM_DASHBOARD_TOKEN not configured" });
      }
      const provided = readBearer(req);
      if (!provided || !tokenMatches(token, provided)) {
        void emitInternalAuditEvent({
          event: "dashboard_auth_failed",
          ip: req.socket.remoteAddress ?? "unknown",
        });
        return json(res, 401, { error: "unauthorized" });
      }

      if (req.method === "GET" && pathname === "/api/blocks") {
        const cursor = url.searchParams.get("cursor") ?? undefined;
        if (cursor && !parseCursor(cursor)) {
          return json(res, 400, { error: "invalid cursor format" });
        }
        const since = url.searchParams.get("since");
        if (since && !Number.isFinite(Date.parse(since))) {
          return json(res, 400, { error: "since must be a valid ISO timestamp" });
        }

        const eventQuery = url.searchParams.get("event");
        const events = eventQuery
          ? eventQuery.split(",").map((v) => v.trim()).filter(Boolean)
          : undefined;
        const q = url.searchParams.get("q") ?? undefined;
        const session = url.searchParams.get("session") ?? undefined;
        const limit = parseLimit(url.searchParams.get("limit"));

        try {
          const page = listBlockEvents({
            auditLogPath: getAuditPath(),
            query: {
              cursor,
              limit,
              events,
              since: since ?? undefined,
              session,
              q,
            },
          });
          if (page.sizeWarning) {
            res.setHeader("X-Audit-Size-Warning", "true");
          }
          const currentConfig = readConfigStore().config;

          const blocks = page.blocks.map((entry) => ({
            ...entry.record,
            fingerprint: entry.fingerprint,
            cursor: entry.cursor,
            allowAction: describeAllowAction(entry.record, currentConfig),
          }));
          return json(res, 200, { blocks, nextCursor: page.nextCursor, hasMore: page.hasMore });
        } catch (err) {
          if (err instanceof CursorNotFoundError) {
            return json(res, 404, { error: err.message });
          }
          return json(res, 500, { error: "failed to read audit log" });
        }
      }

      if (req.method === "GET" && pathname === "/api/config") {
        try {
          const data = readConfigStore();
          return json(res, 200, data);
        } catch {
          return json(res, 500, { error: "failed to read config" });
        }
      }

      if (req.method === "POST" && pathname === "/api/config/validate") {
        try {
          const body = await readJsonBody(req);
          if (!isRecord(body.config)) {
            return json(res, 400, { error: "config must be an object" });
          }
          const config = body.config;
          const validation = validateSecurityConfig(config);
          if (!validation.valid) {
            return json(res, 200, { valid: false, errors: validation.errors });
          }
          return json(res, 200, {
            valid: true,
            ...(validation.warnings.length > 0 ? { warnings: validation.warnings } : {}),
          });
        } catch (err) {
          return json(res, 400, { error: (err as Error).message });
        }
      }

      if (req.method === "PUT" && pathname === "/api/config") {
        try {
          const body = await readJsonBody(req);
          const config = body.config;
          const revision = asString(body.revision);
          if (!isRecord(config) || !revision) {
            return json(res, 400, { error: "config and revision are required" });
          }

          const updated = updateConfigStore({
            config,
            expectedRevision: revision,
          });

          void emitInternalAuditEvent({
            event: "dashboard_config_updated",
            revision: updated.revision,
            changedFields: changedFieldsFromPayload(updated.changedFields),
          });

          return json(res, 200, {
            ok: true,
            revision: updated.revision,
            updatedAt: updated.lastModified,
          });
        } catch (err) {
          if (err instanceof RevisionConflictError) {
            return json(res, 409, { error: err.message, currentRevision: err.currentRevision });
          }
          if (err instanceof ConfigValidationError) {
            return json(res, 422, { error: err.message, issues: err.issues });
          }
          return json(res, 400, { error: (err as Error).message });
        }
      }

      if (req.method === "POST" && pathname === "/api/allow/preview") {
        try {
          const body = await readJsonBody(req);
          const sourceCursor = asString(body.sourceCursor);
          if (!sourceCursor) return json(res, 400, { error: "sourceCursor is required" });

          const preview = previewAllowAction({
            sourceCursor,
            auditLogPath: getAuditPath(),
          });
          if (!preview.supported) {
            return json(res, 200, preview);
          }
          return json(res, 200, preview);
        } catch (err) {
          if (err instanceof SourceCursorValidationError) {
            return json(res, 400, { error: err.message });
          }
          if (err instanceof SourceCursorNotFoundError) {
            return json(res, 404, { error: err.message });
          }
          return json(res, 400, { error: (err as Error).message });
        }
      }

      if (req.method === "POST" && pathname === "/api/allow/apply") {
        try {
          const body = await readJsonBody(req);
          const sourceCursor = asString(body.sourceCursor);
          const revision = asString(body.revision);
          const confirmation = asString(body.confirmation);
          if (!sourceCursor || !revision) {
            return json(res, 400, { error: "sourceCursor and revision are required" });
          }

          const result = applyAllowAction({
            sourceCursor,
            revision,
            confirmation: confirmation || undefined,
            action: body.action as Record<string, unknown> | undefined,
            auditLogPath: getAuditPath(),
          });

          void emitInternalAuditEvent({
            event: "dashboard_allow_applied",
            actionType: result.action.type,
            value: result.action.value,
            revision: result.revision,
            sourceCursor: result.sourceCursor,
          });

          return json(res, 200, {
            ok: true,
            revision: result.revision,
            updatedAt: result.lastModified,
            action: result.summary,
          });
        } catch (err) {
          if (err instanceof SourceCursorValidationError) {
            return json(res, 400, { error: err.message });
          }
          if (err instanceof SourceCursorNotFoundError) {
            return json(res, 404, { error: err.message });
          }
          if (err instanceof AllowActionMismatchError) {
            return json(res, 409, { error: err.message });
          }
          if (err instanceof ConfirmationRequiredError) {
            return json(res, 403, { error: err.message });
          }
          if (err instanceof AllowActionUnsupportedError) {
            return json(res, 422, { error: err.reason });
          }
          if (err instanceof RevisionConflictError) {
            return json(res, 409, { error: err.message, currentRevision: err.currentRevision });
          }
          if (err instanceof ConfigValidationError) {
            return json(res, 422, { error: err.message, issues: err.issues });
          }
          return json(res, 400, { error: (err as Error).message });
        }
      }

      return json(res, 404, { error: "not found" });
    }

    return json(res, 404, { error: "not found" });
  });
}

// ── Start server when run directly ──
const isMainModule =
  process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/^.*\//, ""));
if (isMainModule || process.env.PRISM_DASHBOARD_START) {
  if (!getDashboardToken()) {
    process.stderr.write("[dashboard] PRISM_DASHBOARD_TOKEN is required\n");
    process.exit(1);
  }
  const server = createServer();
  server.listen(PORT, HOST, () => {
    process.stdout.write(`[dashboard] http://${HOST}:${PORT}\n`);
  });
}
