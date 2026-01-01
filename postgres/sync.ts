#!/usr/bin/env bun
/**
 * Sync Claude Code sessions to PostgreSQL
 *
 * Usage:
 *   bun run postgres/sync.ts                    # Incremental sync (new/changed)
 *   bun run postgres/sync.ts --all              # Full sync
 *   bun run postgres/sync.ts --days 7           # Last 7 days only
 *   bun run postgres/sync.ts --force            # Re-sync even if unchanged
 *
 * Environment:
 *   DATABASE_URL          - PostgreSQL connection string
 *   CLAUDE_SESSIONS_DIR   - Sessions directory (default: ~/.claude/projects)
 *
 * SECURITY NOTES:
 * - Uses file-based locking to prevent race conditions
 * - Graceful shutdown on SIGTERM/SIGINT
 * - Transaction-based updates for data integrity
 */

import { readdirSync, statSync, readFileSync, writeFileSync, unlinkSync, existsSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import { parseArgs } from 'util';
import postgres from 'postgres';
import { parseSessionFile } from '../shared/parser.js';
import type { ParsedSession } from '../shared/types.js';

// =============================================================================
// CONFIGURATION
// =============================================================================

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost/claude_sessions';
const DEFAULT_SESSIONS_DIR =
  process.env.CLAUDE_SESSIONS_DIR ||
  join(process.env.HOME || '', '.claude', 'projects');

// Lock file for preventing concurrent syncs
const LOCK_FILE = join(DEFAULT_SESSIONS_DIR, '.kuato-sync.lock');
const LOCK_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

// =============================================================================
// DATABASE CONNECTION
// =============================================================================

const sql = postgres(DATABASE_URL, {
  max: 5,
  idle_timeout: 20,
  connect_timeout: 10,
});

// =============================================================================
// INTERFACES
// =============================================================================

interface SyncOptions {
  all?: boolean;
  days?: number;
  force?: boolean;
  limit?: number;
}

interface SyncStats {
  created: number;
  updated: number;
  skipped: number;
  errors: number;
}

// =============================================================================
// LOCK MANAGEMENT
// =============================================================================

interface LockInfo {
  pid: number;
  startedAt: string;
  hostname: string;
}

/**
 * Acquire an exclusive lock for syncing
 * @returns true if lock acquired, false if already locked
 */
function acquireLock(): boolean {
  try {
    // Check if lock exists and is still valid
    if (existsSync(LOCK_FILE)) {
      const lockContent = readFileSync(LOCK_FILE, 'utf-8');
      try {
        const lockInfo: LockInfo = JSON.parse(lockContent);
        const lockAge = Date.now() - new Date(lockInfo.startedAt).getTime();

        // If lock is too old, it's stale - remove it
        if (lockAge > LOCK_TIMEOUT_MS) {
          console.warn(`Removing stale lock from PID ${lockInfo.pid} (age: ${Math.round(lockAge / 1000)}s)`);
          unlinkSync(LOCK_FILE);
        } else {
          // Lock is still valid
          console.error(`Sync already in progress (PID ${lockInfo.pid}, started ${lockInfo.startedAt})`);
          return false;
        }
      } catch {
        // Invalid lock file, remove it
        console.warn('Removing invalid lock file');
        unlinkSync(LOCK_FILE);
      }
    }

    // Create new lock
    const lockInfo: LockInfo = {
      pid: process.pid,
      startedAt: new Date().toISOString(),
      hostname: process.env.HOSTNAME || 'unknown',
    };

    writeFileSync(LOCK_FILE, JSON.stringify(lockInfo, null, 2), { flag: 'wx' });
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      // Race condition - another process got the lock first
      console.error('Another sync process acquired the lock first');
      return false;
    }
    throw error;
  }
}

/**
 * Release the sync lock
 */
function releaseLock(): void {
  try {
    if (existsSync(LOCK_FILE)) {
      // Only remove if it's our lock
      const lockContent = readFileSync(LOCK_FILE, 'utf-8');
      try {
        const lockInfo: LockInfo = JSON.parse(lockContent);
        if (lockInfo.pid === process.pid) {
          unlinkSync(LOCK_FILE);
        }
      } catch {
        // Invalid lock file, safe to remove
        unlinkSync(LOCK_FILE);
      }
    }
  } catch (error) {
    console.warn('Error releasing lock:', error instanceof Error ? error.message : 'Unknown error');
  }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Calculate MD5 hash of file contents
 */
function fileHash(filePath: string): string {
  const content = readFileSync(filePath);
  return createHash('md5').update(content).digest('hex');
}

/**
 * Get existing session hashes from database
 */
async function getExistingHashes(): Promise<Map<string, string>> {
  const rows = await sql`
    SELECT id, transcript_hash FROM sessions WHERE transcript_hash IS NOT NULL
  `;
  return new Map(rows.map((r) => [r.id, r.transcript_hash]));
}

/**
 * Find all session directories
 */
function findSessionDirs(baseDir: string): string[] {
  try {
    return readdirSync(baseDir)
      .map((name) => join(baseDir, name))
      .filter((path) => {
        try {
          return statSync(path).isDirectory();
        } catch {
          return false;
        }
      });
  } catch (error) {
    console.warn(`Error reading directory ${baseDir}:`, error instanceof Error ? error.message : 'Unknown error');
    return [];
  }
}

/**
 * Find JSONL files to sync
 */
function findFilesToSync(
  baseDir: string,
  options: SyncOptions
): { path: string; mtime: Date }[] {
  const files: { path: string; mtime: Date }[] = [];
  const sessionDirs = findSessionDirs(baseDir);

  const cutoffDate = options.days
    ? new Date(Date.now() - options.days * 24 * 60 * 60 * 1000)
    : null;

  for (const dir of sessionDirs) {
    try {
      for (const file of readdirSync(dir)) {
        if (!file.endsWith('.jsonl')) continue;

        const filePath = join(dir, file);
        try {
          const stat = statSync(filePath);

          // Skip old files unless doing full sync
          if (cutoffDate && stat.mtime < cutoffDate) continue;

          files.push({ path: filePath, mtime: stat.mtime });
        } catch {
          // File not accessible
          continue;
        }
      }
    } catch {
      // Directory not readable
      continue;
    }
  }

  // Sort by modification time (newest first)
  files.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

  // Apply limit
  if (options.limit) {
    return files.slice(0, options.limit);
  }

  return files;
}

// =============================================================================
// SYNC FUNCTIONS
// =============================================================================

/**
 * Sync a single session to the database using a transaction
 */
async function syncSession(
  filePath: string,
  existingHashes: Map<string, string>,
  options: SyncOptions
): Promise<'created' | 'updated' | 'skipped' | 'error'> {
  try {
    // Parse session
    const session = parseSessionFile(filePath);
    if (!session) {
      return 'skipped';
    }

    // Skip empty sessions
    if (session.userMessages.length === 0) {
      return 'skipped';
    }

    // Check if already synced with same hash
    const hash = fileHash(filePath);
    const existingHash = existingHashes.get(session.id);

    if (existingHash === hash && !options.force) {
      return 'skipped';
    }

    // Build search text from user messages
    const searchText = session.userMessages.join(' ');

    // Use transaction for atomic updates
    await sql.begin(async (tx) => {
      await tx`
        INSERT INTO sessions (
          id,
          started_at,
          ended_at,
          git_branch,
          cwd,
          version,
          message_count,
          input_tokens,
          output_tokens,
          cache_creation_tokens,
          cache_read_tokens,
          user_messages,
          tools_used,
          files_touched,
          models_used,
          model_tokens,
          search_text,
          transcript_path,
          transcript_hash,
          synced_at
        ) VALUES (
          ${session.id},
          ${session.startedAt},
          ${session.endedAt},
          ${session.gitBranch},
          ${session.cwd},
          ${session.version},
          ${session.messageCount},
          ${session.inputTokens},
          ${session.outputTokens},
          ${session.cacheCreationTokens},
          ${session.cacheReadTokens},
          ${tx.json(session.userMessages)},
          ${tx.json(session.toolsUsed)},
          ${tx.json(session.filesFromToolCalls)},
          ${tx.json(session.modelsUsed)},
          ${tx.json(session.modelTokens)},
          ${searchText},
          ${filePath},
          ${hash},
          NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
          started_at = EXCLUDED.started_at,
          ended_at = EXCLUDED.ended_at,
          git_branch = EXCLUDED.git_branch,
          cwd = EXCLUDED.cwd,
          version = EXCLUDED.version,
          message_count = EXCLUDED.message_count,
          input_tokens = EXCLUDED.input_tokens,
          output_tokens = EXCLUDED.output_tokens,
          cache_creation_tokens = EXCLUDED.cache_creation_tokens,
          cache_read_tokens = EXCLUDED.cache_read_tokens,
          user_messages = EXCLUDED.user_messages,
          tools_used = EXCLUDED.tools_used,
          files_touched = EXCLUDED.files_touched,
          models_used = EXCLUDED.models_used,
          model_tokens = EXCLUDED.model_tokens,
          search_text = EXCLUDED.search_text,
          transcript_path = EXCLUDED.transcript_path,
          transcript_hash = EXCLUDED.transcript_hash,
          synced_at = NOW()
      `;
    });

    return existingHash ? 'updated' : 'created';
  } catch (error) {
    console.error(`Error syncing ${filePath}:`, error instanceof Error ? error.message : 'Unknown error');
    return 'error';
  }
}

/**
 * Main sync function
 */
async function sync(baseDir: string, options: SyncOptions): Promise<SyncStats> {
  const stats: SyncStats = {
    created: 0,
    updated: 0,
    skipped: 0,
    errors: 0,
  };

  console.log(`Syncing sessions from: ${baseDir}`);

  // Get existing hashes for change detection
  const existingHashes = await getExistingHashes();
  console.log(`Found ${existingHashes.size} existing sessions in database`);

  // Find files to sync
  const files = findFilesToSync(baseDir, options);
  console.log(`Found ${files.length} session files to process`);

  // Process each file
  for (const { path: filePath } of files) {
    // Check for shutdown signal
    if (isShuttingDown) {
      console.log('Shutdown requested, stopping sync...');
      break;
    }

    const result = await syncSession(filePath, existingHashes, options);
    stats[result]++;

    if (result !== 'skipped') {
      console.log(`  ${result}: ${filePath}`);
    }
  }

  return stats;
}

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

let isShuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`\nReceived ${signal}. Shutting down gracefully...`);

  // Release lock
  releaseLock();

  // Close database connection
  try {
    await sql.end({ timeout: 5 });
    console.log('Database connections closed.');
  } catch (error) {
    console.error('Error closing database connections:', error);
  }

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// =============================================================================
// CLI ENTRY POINT
// =============================================================================

async function main() {
  const { values } = parseArgs({
    options: {
      all: { type: 'boolean', short: 'a' },
      days: { type: 'string', short: 'd' },
      force: { type: 'boolean', short: 'f' },
      limit: { type: 'string', short: 'l' },
      dir: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });

  if (values.help) {
    console.log(`
Claude Code Session Sync (PostgreSQL)

Usage:
  bun run sync.ts [options]

Options:
  -a, --all              Sync all sessions (not just recent)
  -d, --days <n>         Only sync last N days
  -f, --force            Re-sync even if file unchanged
  -l, --limit <n>        Max files to process
  --dir <path>           Sessions directory
  -h, --help             Show this help

Environment:
  DATABASE_URL           PostgreSQL connection string
  CLAUDE_SESSIONS_DIR    Default sessions directory

Examples:
  bun run sync.ts                    # Incremental sync
  bun run sync.ts --all              # Full sync
  bun run sync.ts --days 7           # Last week only
  bun run sync.ts --force            # Force re-sync

Security:
  - Uses file locking to prevent concurrent syncs
  - Transactions ensure data integrity
  - Graceful shutdown on SIGTERM/SIGINT
`);
    process.exit(0);
  }

  const options: SyncOptions = {
    all: values.all,
    days: values.days ? parseInt(values.days, 10) : undefined,
    force: values.force,
    limit: values.limit ? parseInt(values.limit, 10) : undefined,
  };

  const baseDir = values.dir || DEFAULT_SESSIONS_DIR;

  // Acquire lock
  if (!acquireLock()) {
    console.error('Could not acquire sync lock. Another sync may be in progress.');
    process.exit(1);
  }

  try {
    const stats = await sync(baseDir, options);

    console.log('\nSync complete:');
    console.log(`  Created: ${stats.created}`);
    console.log(`  Updated: ${stats.updated}`);
    console.log(`  Skipped: ${stats.skipped}`);
    console.log(`  Errors:  ${stats.errors}`);
  } finally {
    // Always release lock and close connection
    releaseLock();
    await sql.end();
  }
}

main().catch((error) => {
  console.error('Sync failed:', error instanceof Error ? error.message : 'Unknown error');
  releaseLock();
  process.exit(1);
});
