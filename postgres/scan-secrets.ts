#!/usr/bin/env bun
/**
 * Scan Sessions for Secrets
 *
 * Scans session data in the database for potential secrets and credentials.
 * Can optionally scrub detected secrets from the database.
 *
 * Usage:
 *   bun run postgres/scan-secrets.ts              # Scan and report
 *   bun run postgres/scan-secrets.ts --scrub      # Scan and scrub secrets
 *   bun run postgres/scan-secrets.ts --severity high  # Only high+ severity
 *
 * Environment:
 *   DATABASE_URL - PostgreSQL connection string
 */

import { parseArgs } from 'util';
import postgres from 'postgres';
import { detectSecrets, scrubSecrets, getSecretsSummary, type SecretFinding } from '../shared/secrets.js';

// =============================================================================
// CONFIGURATION
// =============================================================================

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost/claude_sessions';

const sql = postgres(DATABASE_URL, {
  max: 5,
  idle_timeout: 20,
});

// =============================================================================
// TYPES
// =============================================================================

interface ScanResult {
  sessionId: string;
  messageIndex: number;
  findings: SecretFinding[];
}

interface ScanSummary {
  totalSessions: number;
  sessionsWithSecrets: number;
  totalFindings: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
}

// =============================================================================
// SCANNING FUNCTIONS
// =============================================================================

async function scanAllSessions(
  minSeverity: 'critical' | 'high' | 'medium' | 'low'
): Promise<{ results: ScanResult[]; summary: ScanSummary }> {
  console.log('Fetching sessions from database...');

  const sessions = await sql`
    SELECT id, user_messages
    FROM sessions
    WHERE user_messages IS NOT NULL
    ORDER BY ended_at DESC
  `;

  console.log(`Scanning ${sessions.length} sessions for secrets...\n`);

  const results: ScanResult[] = [];
  const summary: ScanSummary = {
    totalSessions: sessions.length,
    sessionsWithSecrets: 0,
    totalFindings: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    byType: {},
  };

  for (const session of sessions) {
    const messages = session.user_messages as string[];
    if (!Array.isArray(messages)) continue;

    let sessionHasSecrets = false;

    for (let i = 0; i < messages.length; i++) {
      const message = messages[i];
      if (!message) continue;

      const findings = detectSecrets(message, { minSeverity });

      if (findings.length > 0) {
        sessionHasSecrets = true;
        results.push({
          sessionId: session.id,
          messageIndex: i,
          findings,
        });

        // Update summary
        for (const finding of findings) {
          summary.totalFindings++;
          summary.bySeverity[finding.severity]++;
          summary.byType[finding.type] = (summary.byType[finding.type] || 0) + 1;
        }
      }
    }

    if (sessionHasSecrets) {
      summary.sessionsWithSecrets++;
    }
  }

  return { results, summary };
}

async function scrubAllSecrets(
  minSeverity: 'critical' | 'high' | 'medium' | 'low'
): Promise<number> {
  console.log('Fetching sessions from database...');

  const sessions = await sql`
    SELECT id, user_messages
    FROM sessions
    WHERE user_messages IS NOT NULL
  `;

  console.log(`Processing ${sessions.length} sessions...\n`);

  let updatedCount = 0;

  for (const session of sessions) {
    const messages = session.user_messages as string[];
    if (!Array.isArray(messages)) continue;

    let hasChanges = false;
    const scrubbedMessages: string[] = [];

    for (const message of messages) {
      if (!message) {
        scrubbedMessages.push(message);
        continue;
      }

      const scrubbed = scrubSecrets(message, { minSeverity });
      if (scrubbed !== message) {
        hasChanges = true;
      }
      scrubbedMessages.push(scrubbed);
    }

    if (hasChanges) {
      // Update the database
      await sql`
        UPDATE sessions
        SET user_messages = ${sql.json(scrubbedMessages)},
            search_text = ${scrubbedMessages.join(' ')}
        WHERE id = ${session.id}
      `;
      updatedCount++;
      console.log(`  Scrubbed: ${session.id}`);
    }
  }

  return updatedCount;
}

// =============================================================================
// DISPLAY FUNCTIONS
// =============================================================================

function displayResults(results: ScanResult[], summary: ScanSummary): void {
  console.log('='.repeat(70));
  console.log('  SECRET SCAN RESULTS');
  console.log('='.repeat(70));
  console.log('');

  // Summary
  console.log('Summary:');
  console.log(`  Total sessions scanned: ${summary.totalSessions}`);
  console.log(`  Sessions with secrets:  ${summary.sessionsWithSecrets}`);
  console.log(`  Total findings:         ${summary.totalFindings}`);
  console.log('');

  if (summary.totalFindings > 0) {
    console.log('By Severity:');
    for (const [severity, count] of Object.entries(summary.bySeverity)) {
      if (count > 0) {
        const icon = severity === 'critical' ? '🔴' :
                     severity === 'high' ? '🟠' :
                     severity === 'medium' ? '🟡' : '🟢';
        console.log(`  ${icon} ${severity}: ${count}`);
      }
    }
    console.log('');

    console.log('By Type:');
    const sortedTypes = Object.entries(summary.byType)
      .sort((a, b) => b[1] - a[1]);
    for (const [type, count] of sortedTypes) {
      console.log(`  ${type}: ${count}`);
    }
    console.log('');

    // Show top findings
    console.log('-'.repeat(70));
    console.log('Sample Findings (first 20):');
    console.log('-'.repeat(70));

    let shown = 0;
    for (const result of results) {
      if (shown >= 20) break;

      for (const finding of result.findings) {
        if (shown >= 20) break;

        const icon = finding.severity === 'critical' ? '🔴' :
                     finding.severity === 'high' ? '🟠' :
                     finding.severity === 'medium' ? '🟡' : '🟢';

        console.log(`\n${icon} [${finding.severity.toUpperCase()}] ${finding.pattern}`);
        console.log(`   Session: ${result.sessionId}`);
        console.log(`   Found:   ${finding.match.slice(0, 50)}${finding.match.length > 50 ? '...' : ''}`);
        console.log(`   Redact:  ${finding.redacted}`);
        shown++;
      }
    }
  }

  console.log('');
  console.log('='.repeat(70));
}

// =============================================================================
// CLI
// =============================================================================

async function main() {
  const { values } = parseArgs({
    options: {
      scrub: { type: 'boolean', short: 's' },
      severity: { type: 'string', default: 'high' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help) {
    console.log(`
Secret Scanner for Kuato Sessions

Usage:
  bun run scan-secrets.ts [options]

Options:
  -s, --scrub              Scrub detected secrets from database
  --severity <level>       Minimum severity (critical, high, medium, low)
                           Default: high
  -h, --help               Show this help

Environment:
  DATABASE_URL             PostgreSQL connection string

Examples:
  bun run scan-secrets.ts                    # Scan and report
  bun run scan-secrets.ts --scrub            # Scrub high+ severity secrets
  bun run scan-secrets.ts --severity medium  # Include medium severity
`);
    process.exit(0);
  }

  const minSeverity = (values.severity || 'high') as 'critical' | 'high' | 'medium' | 'low';

  try {
    if (values.scrub) {
      console.log(`\nScrubbing secrets (severity >= ${minSeverity})...\n`);

      const count = await scrubAllSecrets(minSeverity);

      console.log('');
      console.log('='.repeat(70));
      console.log(`  Scrubbing complete: ${count} sessions updated`);
      console.log('='.repeat(70));
    } else {
      const { results, summary } = await scanAllSessions(minSeverity);
      displayResults(results, summary);

      if (summary.totalFindings > 0) {
        console.log('');
        console.log('To scrub detected secrets, run:');
        console.log('  bun run scan-secrets.ts --scrub');
        console.log('');
      }
    }
  } finally {
    await sql.end();
  }
}

main().catch((error) => {
  console.error('Scan failed:', error instanceof Error ? error.message : 'Unknown error');
  process.exit(1);
});
