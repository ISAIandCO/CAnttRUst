export type HostKind = "dns" | "ipv4" | "ipv6" | "localhost" | "invalid";

export type NormalizedHost = {
  ascii: string;
  display: string;
  kind: HostKind;
  protectedZone: "ru" | "su" | "rf" | null;
};

export type CertificateSnapshot = {
  rawDER: Uint8Array;
  derSha256: string;
  firefoxSha256?: string;
  subject: string;
  issuer: string;
  isBuiltInRoot: boolean;
  validityStart: number;
  validityEnd: number;
};

export type ProtectedCa = {
  id: string;
  name: string;
  rootDerSha256: string[];
  allowedDnsZones: string[];
  allowIp: boolean;
  ctPolicy: string;
};

export type ProtectedCaMatch = {
  ca: ProtectedCa;
  certificate: CertificateSnapshot;
  certificateIndex: number;
};

export type ValidSct = {
  logId: string;
  operator: string;
  timestamp: number;
};

export type CtVerdict =
  | { status: "valid"; validScts: ValidSct[]; policy: string }
  | { status: "invalid"; reason: "missing_embedded_sct" | "no_trusted_log" | "invalid_sct_signature" | "sct_outside_log_interval" | "log_not_accepted_at_sct_time" | "policy_not_satisfied"; observedLogIds: string[] }
  | { status: "indeterminate"; reason: "certificate_parse_error" | "issuer_not_found" | "unsupported_signature_algorithm" | "internal_error" };

export type CtMode = "yandex-required" | "hardened";

export type ExceptionScope = "zone" | "ct" | "all";
export type ExceptionDuration = "session" | "hour" | "permanent";

export type AllowlistEntry = {
  id: string;
  type: "exact-host";
  host: string;
  createdAt: string;
  note?: string;
  scope?: ExceptionScope;
  expiresAt?: number;
  sessionId?: string;
  incognito?: boolean;
};

export type Settings = {
  schema: 1;
  enabled: boolean;
  ctMode: CtMode;
  allowlist: AllowlistEntry[];
};

export type SecurityEvent = {
  id: string;
  timestamp: string;
  tabId: number;
  incognito: boolean;
  host: string;
  originalUrl: string;
  reason: "protected_ca_outside_zone" | "ct_invalid" | "ct_indeterminate";
  leafSha256: string;
  matchedCaSha256: string;
  leafSubject: string;
  leafIssuer: string;
  matchedCaId: string;
  ctSummary?: { status: string; validOperators: string[] };
};

export type PublicSecurityEvent = Omit<SecurityEvent, "originalUrl">;
