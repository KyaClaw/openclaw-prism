const INJECTION_PATTERNS: Array<{ name: string; re: RegExp; score: number }> = [
  { name: "override-instruction", re: /ignore\s+(all\s+)?(previous|above|prior)\s+instructions/i, score: 35 },
  { name: "system-prompt-exfil", re: /(reveal|print|dump).*(system prompt|hidden prompt)/i, score: 30 },
  { name: "credential-exfil", re: /(send|post|upload).*(token|secret|credential|api.?key)/i, score: 35 },
  { name: "tool-abuse-cmd", re: /(run|execute).*(rm\s+-rf|curl\s+.*\|\s*sh)/i, score: 40 },
  { name: "jailbreak", re: /(developer mode|do anything now|DAN|ignore safety)/i, score: 30 },
  { name: "role-override", re: /you\s+are\s+now\s+(a|an|the)\s+/i, score: 25 },
  { name: "zero-width-chars", re: /[\u200b\u200c\u200d\ufeff\u00ad]/, score: 30 },
  { name: "format-injection", re: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|system\|>/i, score: 40 },
  { name: "pretend", re: /pretend\s+(you|that|to)\s+(are|be|have)/i, score: 20 },
  { name: "override-rules", re: /override\s+(your|the|all)\s+(instructions|rules|safety)/i, score: 35 },
];

const HIGH_RISK_VERB_RE = /\b(ignore|override|bypass|disable|reveal|dump|print|expose|execute|run|spawn|launch)\b/i;
const OBFUSCATION_MARKER_RE = /(%[0-9a-f]{2}|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|[\u200b\u200c\u200d\ufeff\u00ad])/i;

const FEATURE_RULES: Array<{ name: string; re: RegExp; score: number }> = [
  {
    name: "feature-control-plane-takeover",
    re: /\b(ignore|override|bypass|disable|forget)\b[\s\S]{0,60}\b(instruction|rule|policy|safety|guardrail)s?\b/i,
    score: 18,
  },
  {
    name: "feature-exfil-intent",
    re: /\b(reveal|dump|print|expose|send|upload|exfiltrate)\b[\s\S]{0,80}\b(system prompt|hidden prompt|secret|token|credential|api.?key)\b/i,
    score: 18,
  },
  {
    name: "feature-exec-pivot-intent",
    re: /\b(run|execute|spawn|launch)\b[\s\S]{0,100}\b(bash|sh|zsh|powershell|cmd|python\s+-c|node\s+-e|rm\s+-rf|curl\s+[^|]*\|\s*(sh|bash|zsh))\b/i,
    score: 22,
  },
];

export { INJECTION_PATTERNS };

function decodePercentLayers(text: string, maxRounds = 2): string {
  let current = text;
  for (let i = 0; i < maxRounds; i++) {
    if (!/%[0-9a-f]{2}/i.test(current)) break;
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  return current;
}

function decodeEscapedSequences(text: string): string {
  return text
    .replace(/\\x([0-9a-f]{2})/gi, (_m, hex: string) => {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) ? String.fromCharCode(code) : _m;
    })
    .replace(/\\u([0-9a-f]{4})/gi, (_m, hex: string) => {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) ? String.fromCharCode(code) : _m;
    });
}

export function canonicalizeText(text: string): { text: string; transforms: string[] } {
  const transforms: string[] = [];
  let next = typeof text.normalize === "function" ? text.normalize("NFKC") : text;
  if (next !== text) transforms.push("unicode-nfkc");

  const escapedDecoded = decodeEscapedSequences(next);
  if (escapedDecoded !== next) {
    transforms.push("escape-decoded");
    next = escapedDecoded;
  }

  const percentDecoded = decodePercentLayers(next);
  if (percentDecoded !== next) {
    transforms.push("percent-decoded");
    next = percentDecoded;
  }

  const noZeroWidth = next.replace(/[\u200b\u200c\u200d\ufeff\u00ad]/g, "");
  if (noZeroWidth !== next) {
    transforms.push("zero-width-stripped");
    next = noZeroWidth;
  }

  const collapsed = next.replace(/\s+/g, " ").trim();
  if (collapsed !== next) {
    transforms.push("whitespace-collapsed");
    next = collapsed;
  }

  return { text: next, transforms };
}

export function heuristicScan(text: string): {
  suspicious: boolean;
  score: number;
  reasons: string[];
} {
  const canonical = canonicalizeText(text);
  let score = 0;
  const reasons: string[] = [];
  const seen = new Set<string>();

  function add(reason: string, weight: number) {
    if (seen.has(reason)) return;
    seen.add(reason);
    score += weight;
    reasons.push(reason);
  }

  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(text) || p.re.test(canonical.text)) {
      add(p.name, p.score);
    }
  }

  for (const feature of FEATURE_RULES) {
    if (feature.re.test(canonical.text)) {
      add(feature.name, feature.score);
    }
  }

  if (
    canonical.transforms.length > 0 &&
    OBFUSCATION_MARKER_RE.test(text) &&
    HIGH_RISK_VERB_RE.test(canonical.text)
  ) {
    add("feature-obfuscation-layer", 12);
  }

  if (
    canonical.transforms.includes("percent-decoded") &&
    /(override-instruction|system-prompt-exfil|override-rules)/.test(reasons.join(","))
  ) {
    add("feature-encoded-directive", 12);
  }

  if (
    canonical.transforms.includes("escape-decoded") &&
    /(override-instruction|system-prompt-exfil|override-rules)/.test(reasons.join(","))
  ) {
    add("feature-escaped-directive", 12);
  }

  if (canonical.transforms.length > 0 && reasons.length > 0) {
    const transformLabel = `canonicalization:${canonical.transforms.join("+")}`;
    if (!seen.has(transformLabel)) {
      seen.add(transformLabel);
      reasons.push(transformLabel);
    }
  }

  return { suspicious: score >= 25, score, reasons };
}
