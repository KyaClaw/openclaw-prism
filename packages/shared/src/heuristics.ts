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

export { INJECTION_PATTERNS };

export function heuristicScan(text: string): {
  suspicious: boolean;
  score: number;
  reasons: string[];
} {
  let score = 0;
  const reasons: string[] = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(text)) {
      score += p.score;
      reasons.push(p.name);
    }
  }
  return { suspicious: score >= 25, score, reasons };
}
