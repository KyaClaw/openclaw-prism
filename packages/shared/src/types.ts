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
};
