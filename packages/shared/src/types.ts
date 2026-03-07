export type ScanVerdict = {
  verdict: "benign" | "suspicious" | "malicious";
  score: number;
  reasons: string[];
};

export type SessionRisk = {
  score: number;
  reasons: string[];
  expiresAt: number;
};

export type SecurityConfig = {
  riskTtlMs?: number;
  persistRiskState?: boolean;
  riskStateFile?: string;
  maxScanChars?: number;
  scanTools?: string[];
  protectedPathPatterns?: string[];
  execAllowedPrefixes?: string[];
  execBlockedPatterns?: string[];
  scannerUrl?: string;
  scannerTimeoutMs?: number;
  blockOnScannerFailure?: boolean;
  outboundSecretPatterns?: string[];
  /** Exact canonical paths exempted from protectedPathPatterns (set by Dashboard allow). */
  protectedPathExceptions?: string[];
  /** Tier A: domains hard-blocked for scan tools (exfil endpoints). */
  blockedDomains?: string[];
  /** Tier B: domains that bump risk score but don't hard-block (dual-use infrastructure). */
  riskyDomains?: string[];
};
