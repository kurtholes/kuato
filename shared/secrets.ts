/**
 * Secret Detection and Scrubbing
 *
 * Detects and optionally redacts sensitive information in session data
 * including API keys, passwords, tokens, and connection strings.
 *
 * Usage:
 *   import { detectSecrets, scrubSecrets } from './secrets.js';
 *
 *   const findings = detectSecrets(text);
 *   const cleanText = scrubSecrets(text);
 */

// =============================================================================
// TYPES
// =============================================================================

export interface SecretFinding {
  type: SecretType;
  pattern: string;
  match: string;
  redacted: string;
  startIndex: number;
  endIndex: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export type SecretType =
  | 'aws_access_key'
  | 'aws_secret_key'
  | 'github_token'
  | 'github_oauth'
  | 'gitlab_token'
  | 'slack_token'
  | 'slack_webhook'
  | 'stripe_key'
  | 'stripe_secret'
  | 'openai_key'
  | 'anthropic_key'
  | 'google_api_key'
  | 'firebase_key'
  | 'twilio_key'
  | 'sendgrid_key'
  | 'mailgun_key'
  | 'jwt_token'
  | 'bearer_token'
  | 'basic_auth'
  | 'private_key'
  | 'ssh_key'
  | 'password_assignment'
  | 'password_url'
  | 'connection_string'
  | 'database_url'
  | 'generic_secret'
  | 'generic_api_key'
  | 'generic_token'
  | 'ip_address'
  | 'email_address';

// =============================================================================
// SECRET PATTERNS
// =============================================================================

interface SecretPattern {
  type: SecretType;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    type: 'aws_access_key',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: 'critical',
    description: 'AWS Access Key ID',
  },
  {
    type: 'aws_secret_key',
    pattern: /\b([A-Za-z0-9/+=]{40})\b(?=.*(?:aws|secret|key))/gi,
    severity: 'critical',
    description: 'AWS Secret Access Key',
  },

  // GitHub
  {
    type: 'github_token',
    pattern: /\b(ghp_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token',
  },
  {
    type: 'github_token',
    pattern: /\b(gho_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub OAuth Token',
  },
  {
    type: 'github_token',
    pattern: /\b(ghu_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub User Token',
  },
  {
    type: 'github_token',
    pattern: /\b(ghs_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub Server Token',
  },
  {
    type: 'github_token',
    pattern: /\b(ghr_[A-Za-z0-9]{36,})\b/g,
    severity: 'critical',
    description: 'GitHub Refresh Token',
  },

  // GitLab
  {
    type: 'gitlab_token',
    pattern: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g,
    severity: 'critical',
    description: 'GitLab Personal Access Token',
  },

  // Slack
  {
    type: 'slack_token',
    pattern: /\b(xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,})\b/g,
    severity: 'critical',
    description: 'Slack Token',
  },
  {
    type: 'slack_webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'high',
    description: 'Slack Webhook URL',
  },

  // Stripe
  {
    type: 'stripe_key',
    pattern: /\b(pk_live_[A-Za-z0-9]{24,})\b/g,
    severity: 'high',
    description: 'Stripe Publishable Key (Live)',
  },
  {
    type: 'stripe_secret',
    pattern: /\b(sk_live_[A-Za-z0-9]{24,})\b/g,
    severity: 'critical',
    description: 'Stripe Secret Key (Live)',
  },
  {
    type: 'stripe_key',
    pattern: /\b(pk_test_[A-Za-z0-9]{24,})\b/g,
    severity: 'low',
    description: 'Stripe Publishable Key (Test)',
  },
  {
    type: 'stripe_secret',
    pattern: /\b(sk_test_[A-Za-z0-9]{24,})\b/g,
    severity: 'medium',
    description: 'Stripe Secret Key (Test)',
  },

  // OpenAI
  {
    type: 'openai_key',
    pattern: /\b(sk-[A-Za-z0-9]{32,})\b/g,
    severity: 'critical',
    description: 'OpenAI API Key',
  },
  {
    type: 'openai_key',
    pattern: /\b(sk-proj-[A-Za-z0-9\-_]{32,})\b/g,
    severity: 'critical',
    description: 'OpenAI Project API Key',
  },

  // Anthropic
  {
    type: 'anthropic_key',
    pattern: /\b(sk-ant-[A-Za-z0-9\-_]{32,})\b/g,
    severity: 'critical',
    description: 'Anthropic API Key',
  },

  // Google
  {
    type: 'google_api_key',
    pattern: /\b(AIza[A-Za-z0-9\-_]{35})\b/g,
    severity: 'high',
    description: 'Google API Key',
  },
  {
    type: 'firebase_key',
    pattern: /\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b/g,
    severity: 'high',
    description: 'Firebase Cloud Messaging Key',
  },

  // Twilio
  {
    type: 'twilio_key',
    pattern: /\b(SK[a-f0-9]{32})\b/g,
    severity: 'high',
    description: 'Twilio API Key',
  },

  // SendGrid
  {
    type: 'sendgrid_key',
    pattern: /\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b/g,
    severity: 'critical',
    description: 'SendGrid API Key',
  },

  // Mailgun
  {
    type: 'mailgun_key',
    pattern: /\b(key-[A-Za-z0-9]{32})\b/g,
    severity: 'high',
    description: 'Mailgun API Key',
  },

  // JWT / Bearer Tokens
  {
    type: 'jwt_token',
    pattern: /\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b/g,
    severity: 'high',
    description: 'JWT Token',
  },
  {
    type: 'bearer_token',
    pattern: /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gi,
    severity: 'high',
    description: 'Bearer Token',
  },
  {
    type: 'basic_auth',
    pattern: /Basic\s+([A-Za-z0-9+/]+=*)/gi,
    severity: 'high',
    description: 'Basic Auth Credentials',
  },

  // Private Keys
  {
    type: 'private_key',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critical',
    description: 'Private Key',
  },
  {
    type: 'ssh_key',
    pattern: /-----BEGIN\s+(?:OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critical',
    description: 'SSH Private Key',
  },

  // Database Connection Strings
  {
    type: 'database_url',
    pattern: /\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|rabbitmq):\/\/[^\s'"]+)/gi,
    severity: 'critical',
    description: 'Database Connection String',
  },
  {
    type: 'connection_string',
    pattern: /\b(Server=[^;]+;.*Password=[^;]+)/gi,
    severity: 'critical',
    description: 'SQL Server Connection String',
  },

  // Password Assignments (in code/config)
  {
    type: 'password_assignment',
    pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|api-key|auth)[\s]*[:=][\s]*['"`]([^'"`\s]{8,})['"`]/gi,
    severity: 'high',
    description: 'Password/Secret Assignment',
  },
  {
    type: 'password_url',
    pattern: /:\/\/[^:]+:([^@]+)@/g,
    severity: 'critical',
    description: 'Password in URL',
  },

  // Generic patterns (lower confidence, checked last)
  {
    type: 'generic_api_key',
    pattern: /\b([A-Za-z0-9]{32,64})\b(?=.*(?:api[_\-]?key|apikey))/gi,
    severity: 'medium',
    description: 'Potential API Key',
  },
  {
    type: 'generic_secret',
    pattern: /\b([A-Za-z0-9+/]{40,}={0,2})\b(?=.*(?:secret|private|credential))/gi,
    severity: 'medium',
    description: 'Potential Secret',
  },
  {
    type: 'generic_token',
    pattern: /\b([A-Fa-f0-9]{64})\b/g, // 256-bit hex strings (common for tokens)
    severity: 'low',
    description: 'Potential Token (64-char hex)',
  },

  // PII
  {
    type: 'email_address',
    pattern: /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b/g,
    severity: 'low',
    description: 'Email Address',
  },
  {
    type: 'ip_address',
    pattern: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g,
    severity: 'low',
    description: 'IP Address',
  },
];

// =============================================================================
// DETECTION FUNCTIONS
// =============================================================================

/**
 * Detect secrets in text and return findings
 */
export function detectSecrets(
  text: string,
  options: {
    minSeverity?: 'critical' | 'high' | 'medium' | 'low';
    types?: SecretType[];
  } = {}
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const severityOrder = ['low', 'medium', 'high', 'critical'];
  const minSeverityIndex = severityOrder.indexOf(options.minSeverity || 'low');

  for (const secretPattern of SECRET_PATTERNS) {
    // Filter by type if specified
    if (options.types && !options.types.includes(secretPattern.type)) {
      continue;
    }

    // Filter by severity
    if (severityOrder.indexOf(secretPattern.severity) < minSeverityIndex) {
      continue;
    }

    // Reset regex lastIndex
    secretPattern.pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    while ((match = secretPattern.pattern.exec(text)) !== null) {
      const captured = match[1] || match[0];
      const startIndex = match.index;
      const endIndex = startIndex + match[0].length;

      // Skip very short matches (likely false positives)
      if (captured.length < 8) continue;

      // Skip if it looks like a file path or common word
      if (isLikelyFalsePositive(captured, secretPattern.type)) continue;

      findings.push({
        type: secretPattern.type,
        pattern: secretPattern.description,
        match: captured,
        redacted: redactSecret(captured, secretPattern.type),
        startIndex,
        endIndex,
        severity: secretPattern.severity,
      });
    }
  }

  // Deduplicate by match value
  const seen = new Set<string>();
  return findings.filter((f) => {
    if (seen.has(f.match)) return false;
    seen.add(f.match);
    return true;
  });
}

/**
 * Check if a match is likely a false positive
 */
function isLikelyFalsePositive(match: string, type: SecretType): boolean {
  // Skip common words and file paths
  const falsePositives = [
    /^[a-z]+$/i, // All letters (likely a word)
    /^\/[\w/.-]+$/, // File path
    /^\.[\w/.-]+$/, // Relative file path
    /^(node_modules|dist|build|src|lib|test|spec)/i, // Common directories
    /^(function|class|const|let|var|import|export|return|if|else|for|while)/i, // JS keywords
    /^(undefined|null|true|false|NaN|Infinity)$/i, // JS values
    /^[0-9]+$/, // Just numbers
    /^[a-f0-9]{32}$/i, // MD5 hash (often not a secret)
  ];

  // IP address validation - skip private/local IPs
  if (type === 'ip_address') {
    if (
      match.startsWith('127.') ||
      match.startsWith('10.') ||
      match.startsWith('192.168.') ||
      match.startsWith('0.') ||
      match === '255.255.255.255'
    ) {
      return true;
    }
  }

  // Email - skip obvious test emails
  if (type === 'email_address') {
    if (
      match.includes('example.com') ||
      match.includes('test.com') ||
      match.includes('localhost') ||
      match.startsWith('test@') ||
      match.startsWith('example@')
    ) {
      return true;
    }
  }

  return falsePositives.some((pattern) => pattern.test(match));
}

/**
 * Redact a secret, keeping some characters for context
 */
function redactSecret(secret: string, type: SecretType): string {
  // For private keys, just indicate it was redacted
  if (type === 'private_key' || type === 'ssh_key') {
    return '[PRIVATE_KEY_REDACTED]';
  }

  // For URLs with passwords, redact just the password part
  if (type === 'password_url') {
    return '***';
  }

  // For connection strings, try to preserve structure
  if (type === 'database_url' || type === 'connection_string') {
    return secret.replace(/:([^:@]+)@/, ':***@');
  }

  // For most secrets, show first 4 and last 4 characters
  if (secret.length > 12) {
    const prefix = secret.slice(0, 4);
    const suffix = secret.slice(-4);
    const middle = '*'.repeat(Math.min(secret.length - 8, 16));
    return `${prefix}${middle}${suffix}`;
  }

  // Short secrets get fully redacted
  return '*'.repeat(secret.length);
}

// =============================================================================
// SCRUBBING FUNCTIONS
// =============================================================================

/**
 * Remove/redact all detected secrets from text
 */
export function scrubSecrets(
  text: string,
  options: {
    minSeverity?: 'critical' | 'high' | 'medium' | 'low';
    replacement?: 'redact' | 'remove' | 'tag';
    tagFormat?: string; // For 'tag' mode, e.g., '[{type}]'
  } = {}
): string {
  const { minSeverity = 'medium', replacement = 'redact' } = options;

  const findings = detectSecrets(text, { minSeverity });

  // Sort by startIndex descending so we can replace from end to start
  findings.sort((a, b) => b.startIndex - a.startIndex);

  let result = text;
  for (const finding of findings) {
    let replacementText: string;

    switch (replacement) {
      case 'remove':
        replacementText = '';
        break;
      case 'tag':
        replacementText = (options.tagFormat || '[{type}]').replace('{type}', finding.type.toUpperCase());
        break;
      case 'redact':
      default:
        replacementText = finding.redacted;
    }

    result =
      result.slice(0, finding.startIndex) +
      replacementText +
      result.slice(finding.endIndex);
  }

  return result;
}

/**
 * Check if text contains any secrets above a severity threshold
 */
export function containsSecrets(
  text: string,
  minSeverity: 'critical' | 'high' | 'medium' | 'low' = 'high'
): boolean {
  const findings = detectSecrets(text, { minSeverity });
  return findings.length > 0;
}

/**
 * Get a summary of secrets found in text
 */
export function getSecretsSummary(text: string): {
  total: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
} {
  const findings = detectSecrets(text);

  const bySeverity: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  const byType: Record<string, number> = {};

  for (const finding of findings) {
    bySeverity[finding.severity]++;
    byType[finding.type] = (byType[finding.type] || 0) + 1;
  }

  return {
    total: findings.length,
    bySeverity,
    byType,
  };
}
