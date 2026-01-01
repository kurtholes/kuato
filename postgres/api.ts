#!/usr/bin/env bun
/**
 * Session Search API Server
 *
 * Usage:
 *   bun run postgres/api.ts
 *
 * Environment:
 *   DATABASE_URL    - PostgreSQL connection string
 *   PORT            - Server port (default: 3847)
 *   HOST            - Bind address (default: 127.0.0.1 for security)
 *   KUATO_API_KEY   - API key for authentication (auto-generated if not set)
 *   KUATO_SESSIONS_DIR - Base directory for session files (for path validation)
 *   KUATO_RATE_LIMIT - Requests per minute (default: 100)
 *
 * Endpoints:
 *   GET /sessions         - Search sessions
 *   GET /sessions/:id     - Get single session
 *   GET /sessions/stats   - Usage statistics
 *   GET /health           - Health check (no auth required)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { join, resolve, normalize } from 'path';
import { randomUUID } from 'crypto';
import postgres from 'postgres';

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost/claude_sessions';
const PORT = parseInt(process.env.PORT || '3847', 10);
const HOST = process.env.HOST || '127.0.0.1'; // Bind to localhost only by default

// API Key authentication
const API_KEY = process.env.KUATO_API_KEY || randomUUID();
if (!process.env.KUATO_API_KEY) {
  console.warn('');
  console.warn('='.repeat(70));
  console.warn('  WARNING: No KUATO_API_KEY set. Generated temporary key:');
  console.warn(`  ${API_KEY}`);
  console.warn('  Set KUATO_API_KEY environment variable to persist.');
  console.warn('='.repeat(70));
  console.warn('');
}

// Session files base directory for path traversal protection
const SESSIONS_BASE_DIR = resolve(
  process.env.KUATO_SESSIONS_DIR ||
    process.env.CLAUDE_SESSIONS_DIR ||
    join(process.env.HOME || '', '.claude', 'projects')
);

// Rate limiting configuration
const RATE_LIMIT_REQUESTS = parseInt(process.env.KUATO_RATE_LIMIT || '100', 10);
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute

// Input limits
const MAX_SEARCH_LENGTH = 1000;
const MAX_DAYS = 3650; // 10 years
const MAX_LIMIT = 100;
const MAX_TOOLS_COUNT = 50;
const MAX_FILE_PATTERN_LENGTH = 500;
const MAX_TRANSCRIPT_SIZE = 50 * 1024 * 1024; // 50MB

// =============================================================================
// DATABASE CONNECTION
// =============================================================================

const sql = postgres(DATABASE_URL, {
  max: 10, // Connection pool size
  idle_timeout: 20,
  connect_timeout: 10,
});

// =============================================================================
// RATE LIMITING
// =============================================================================

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitMap = new Map<string, RateLimitEntry>();

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now >= entry.resetAt) {
    // New window
    const resetAt = now + RATE_LIMIT_WINDOW_MS;
    rateLimitMap.set(ip, { count: 1, resetAt });
    return { allowed: true, remaining: RATE_LIMIT_REQUESTS - 1, resetAt };
  }

  if (entry.count >= RATE_LIMIT_REQUESTS) {
    return { allowed: false, remaining: 0, resetAt: entry.resetAt };
  }

  entry.count++;
  return { allowed: true, remaining: RATE_LIMIT_REQUESTS - entry.count, resetAt: entry.resetAt };
}

// Cleanup old rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap.entries()) {
    if (now >= entry.resetAt) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

// =============================================================================
// AUDIT LOGGING
// =============================================================================

interface AuditLogEntry {
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  query: Record<string, string>;
  userAgent: string;
  statusCode?: number;
  error?: string;
}

function auditLog(entry: AuditLogEntry): void {
  // Log to stdout in JSON format for easy parsing
  console.log(JSON.stringify({ type: 'audit', ...entry }));
}

// =============================================================================
// INPUT VALIDATION
// =============================================================================

function validatePositiveInt(value: string | undefined, defaultVal: number, max: number): number {
  if (!value) return defaultVal;
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed < 1) return defaultVal;
  return Math.min(parsed, max);
}

function validateDateString(value: string | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  if (isNaN(date.getTime())) return null;
  return date;
}

function validateSearchQuery(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_SEARCH_LENGTH) return null;
  return trimmed;
}

function validateToolsList(value: string | undefined): string[] | null {
  if (!value) return null;
  const tools = value.split(',').map((t) => t.trim()).filter(Boolean);
  if (tools.length === 0 || tools.length > MAX_TOOLS_COUNT) return null;
  return tools;
}

function validateFilePattern(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_FILE_PATTERN_LENGTH) return null;
  return trimmed;
}

function validateSessionId(value: string): boolean {
  // Session IDs should be UUIDs
  return /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value);
}

// =============================================================================
// PATH TRAVERSAL PROTECTION
// =============================================================================

function isPathSafe(filePath: string): boolean {
  try {
    const normalizedPath = normalize(resolve(filePath));
    const normalizedBase = normalize(SESSIONS_BASE_DIR);

    // Check that the path is within the allowed base directory
    return normalizedPath.startsWith(normalizedBase + '/') || normalizedPath === normalizedBase;
  } catch {
    return false;
  }
}

// =============================================================================
// CREATE APP
// =============================================================================

const app = new Hono();

// =============================================================================
// CORS MIDDLEWARE - Restrict to localhost origins
// =============================================================================

app.use(
  '*',
  cors({
    origin: (origin) => {
      // Allow requests with no origin (e.g., curl, direct API calls)
      if (!origin) return '*';

      // Only allow localhost origins
      if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
        return origin;
      }

      // Reject all other origins
      return null;
    },
    allowMethods: ['GET', 'OPTIONS'],
    allowHeaders: ['Authorization', 'Content-Type'],
    maxAge: 86400,
  })
);

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================

app.use('*', async (c, next) => {
  const path = c.req.path;

  // Health check doesn't require auth
  if (path === '/health') {
    return next();
  }

  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ success: false, error: 'Authentication required' }, 401);
  }

  const token = authHeader.slice(7);

  if (token !== API_KEY) {
    return c.json({ success: false, error: 'Invalid API key' }, 401);
  }

  return next();
});

// =============================================================================
// RATE LIMITING MIDDLEWARE
// =============================================================================

app.use('*', async (c, next) => {
  const path = c.req.path;

  // Health check doesn't count against rate limit
  if (path === '/health') {
    return next();
  }

  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
             c.req.header('x-real-ip') ||
             'unknown';

  const { allowed, remaining, resetAt } = checkRateLimit(ip);

  c.header('X-RateLimit-Limit', RATE_LIMIT_REQUESTS.toString());
  c.header('X-RateLimit-Remaining', remaining.toString());
  c.header('X-RateLimit-Reset', Math.ceil(resetAt / 1000).toString());

  if (!allowed) {
    return c.json(
      { success: false, error: 'Rate limit exceeded. Try again later.' },
      429
    );
  }

  return next();
});

// =============================================================================
// AUDIT LOGGING MIDDLEWARE
// =============================================================================

app.use('*', async (c, next) => {
  const startTime = Date.now();
  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
             c.req.header('x-real-ip') ||
             'unknown';

  const entry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    ip,
    method: c.req.method,
    path: c.req.path,
    query: c.req.query() as Record<string, string>,
    userAgent: c.req.header('user-agent') || 'unknown',
  };

  try {
    await next();
    entry.statusCode = c.res.status;
  } catch (error) {
    entry.statusCode = 500;
    entry.error = error instanceof Error ? error.message : 'Unknown error';
    throw error;
  } finally {
    // Don't log health checks to reduce noise
    if (c.req.path !== '/health') {
      auditLog(entry);
    }
  }
});

// =============================================================================
// SEARCH SESSIONS ENDPOINT
// =============================================================================

app.get('/sessions', async (c) => {
  const {
    search,
    days,
    since,
    until,
    tools,
    file_pattern,
    limit: limitStr,
  } = c.req.query();

  // Validate inputs
  const limit = validatePositiveInt(limitStr, 20, MAX_LIMIT);
  const daysNum = days ? validatePositiveInt(days, 0, MAX_DAYS) : null;
  const sinceDate = validateDateString(since);
  const untilDate = validateDateString(until);
  const searchQuery = validateSearchQuery(search);
  const toolsList = validateToolsList(tools);
  const filePattern = validateFilePattern(file_pattern);

  // Build query conditions using parameterized queries
  const conditions: string[] = [];
  const params: unknown[] = [];
  let paramIndex = 1;

  // Date filtering - FIXED: Using parameterized interval
  if (daysNum && daysNum > 0) {
    conditions.push(`ended_at > NOW() - $${paramIndex++}::interval`);
    params.push(`${daysNum} days`);
  }
  if (sinceDate) {
    conditions.push(`ended_at >= $${paramIndex++}`);
    params.push(sinceDate);
  }
  if (untilDate) {
    conditions.push(`ended_at <= $${paramIndex++}`);
    params.push(untilDate);
  }

  // Tool filtering
  if (toolsList) {
    conditions.push(`tools_used ?| $${paramIndex++}`);
    params.push(toolsList);
  }

  // File pattern filtering
  if (filePattern) {
    conditions.push(`EXISTS (
      SELECT 1 FROM jsonb_array_elements_text(files_touched) f
      WHERE f ILIKE $${paramIndex++}
    )`);
    params.push(`%${filePattern}%`);
  }

  // Full-text search
  let orderBy = 'ended_at DESC';
  let selectFields = `
    id,
    started_at,
    ended_at,
    git_branch,
    message_count,
    input_tokens,
    output_tokens,
    tools_used,
    files_touched,
    user_messages,
    models_used,
    summary,
    category,
    transcript_path
  `;

  if (searchQuery) {
    const tsQuery = searchQuery
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 20) // Limit number of search terms
      .map((term) => term.replace(/[^\w]/g, '')) // Remove special chars
      .filter((term) => term.length > 0)
      .map((term) => `${term}:*`)
      .join(' & ');

    if (tsQuery) {
      conditions.push(`search_vector @@ to_tsquery('english', $${paramIndex++})`);
      params.push(tsQuery);

      // Add relevance score
      selectFields += `,
        ts_rank(search_vector, to_tsquery('english', $${paramIndex++})) as relevance
      `;
      params.push(tsQuery);
      orderBy = 'relevance DESC, ended_at DESC';
    }
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Execute query with parameterized limit
  params.push(limit);
  const query = `
    SELECT ${selectFields}
    FROM sessions
    ${whereClause}
    ORDER BY ${orderBy}
    LIMIT $${paramIndex}
  `;

  try {
    const rows = await sql.unsafe(query, params);

    return c.json({
      success: true,
      count: rows.length,
      data: rows,
    });
  } catch (error) {
    // Log error details server-side only
    console.error('Search error:', error instanceof Error ? error.message : 'Unknown error');
    return c.json({ success: false, error: 'Search failed' }, 500);
  }
});

// =============================================================================
// STATISTICS ENDPOINT
// NOTE: This must be defined BEFORE /sessions/:id to avoid route conflict
// =============================================================================

app.get('/sessions/stats', async (c) => {
  const { days } = c.req.query();
  const daysNum = validatePositiveInt(days, 7, MAX_DAYS);

  try {
    // Using parameterized interval query
    const intervalParam = `${daysNum} days`;

    const stats = await sql`
      SELECT
        COUNT(*) as session_count,
        SUM(input_tokens) as total_input_tokens,
        SUM(output_tokens) as total_output_tokens,
        SUM(cache_creation_tokens) as total_cache_creation_tokens,
        SUM(cache_read_tokens) as total_cache_read_tokens,
        SUM(message_count) as total_messages,
        MIN(started_at) as earliest_session,
        MAX(ended_at) as latest_session
      FROM sessions
      WHERE ended_at > NOW() - ${intervalParam}::interval
    `;

    // Category breakdown
    const categories = await sql`
      SELECT
        category,
        COUNT(*) as count
      FROM sessions
      WHERE ended_at > NOW() - ${intervalParam}::interval
        AND category IS NOT NULL
      GROUP BY category
      ORDER BY count DESC
    `;

    // Model breakdown
    const modelStats = await sql`
      SELECT
        model_key as model,
        SUM((model_value->>'input')::bigint) as input_tokens,
        SUM((model_value->>'output')::bigint) as output_tokens
      FROM sessions,
        jsonb_each(model_tokens) as m(model_key, model_value)
      WHERE ended_at > NOW() - ${intervalParam}::interval
      GROUP BY model_key
      ORDER BY input_tokens DESC
    `;

    return c.json({
      success: true,
      data: {
        ...stats[0],
        days: daysNum,
        by_category: categories,
        by_model: modelStats,
      },
    });
  } catch (error) {
    console.error('Stats error:', error instanceof Error ? error.message : 'Unknown error');
    return c.json({ success: false, error: 'Failed to get stats' }, 500);
  }
});

// =============================================================================
// GET SINGLE SESSION ENDPOINT
// =============================================================================

app.get('/sessions/:id', async (c) => {
  const { id } = c.req.param();
  const { with_transcript } = c.req.query();

  // Validate session ID format
  if (!validateSessionId(id)) {
    return c.json({ success: false, error: 'Invalid session ID format' }, 400);
  }

  try {
    const rows = await sql`
      SELECT
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
        tools_used,
        files_touched,
        user_messages,
        models_used,
        model_tokens,
        summary,
        category,
        transcript_path
      FROM sessions
      WHERE id = ${id}
    `;

    if (rows.length === 0) {
      return c.json({ success: false, error: 'Session not found' }, 404);
    }

    const session = rows[0] as Record<string, unknown>;

    // Optionally load transcript with path traversal protection
    if (with_transcript === 'true' && session.transcript_path) {
      const transcriptPath = session.transcript_path as string;

      // SECURITY: Validate path is within allowed directory
      if (!isPathSafe(transcriptPath)) {
        console.warn(`Path traversal attempt blocked: ${transcriptPath}`);
        // Don't expose the error to the client
      } else {
        try {
          const { readFileSync, statSync } = await import('fs');

          // Check file size before reading
          const stat = statSync(transcriptPath);
          if (stat.size > MAX_TRANSCRIPT_SIZE) {
            console.warn(`Transcript too large: ${transcriptPath} (${stat.size} bytes)`);
          } else {
            const content = readFileSync(transcriptPath, 'utf-8');
            const messages = content
              .trim()
              .split('\n')
              .filter(Boolean)
              .slice(0, 10000) // Limit number of messages
              .map((line) => {
                try {
                  return JSON.parse(line);
                } catch {
                  return null;
                }
              })
              .filter(Boolean);
            session.messages = messages;
          }
        } catch {
          // Transcript file not accessible - don't expose error details
        }
      }
    }

    return c.json({
      success: true,
      data: session,
    });
  } catch (error) {
    console.error('Get session error:', error instanceof Error ? error.message : 'Unknown error');
    return c.json({ success: false, error: 'Failed to get session' }, 500);
  }
});

// =============================================================================
// HEALTH CHECK ENDPOINT (No auth required)
// =============================================================================

app.get('/health', async (c) => {
  try {
    // Verify database connection
    await sql`SELECT 1`;
    return c.json({ status: 'ok', timestamp: new Date().toISOString() });
  } catch {
    return c.json({ status: 'unhealthy', error: 'Database connection failed' }, 503);
  }
});

// =============================================================================
// 404 HANDLER
// =============================================================================

app.notFound((c) => {
  return c.json({ success: false, error: 'Not found' }, 404);
});

// =============================================================================
// ERROR HANDLER
// =============================================================================

app.onError((error, c) => {
  console.error('Unhandled error:', error instanceof Error ? error.message : 'Unknown error');
  return c.json({ success: false, error: 'Internal server error' }, 500);
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================

async function shutdown(signal: string) {
  console.log(`\nReceived ${signal}. Shutting down gracefully...`);

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
// START SERVER
// =============================================================================

console.log('');
console.log('='.repeat(70));
console.log('  KUATO SESSION API SERVER');
console.log('='.repeat(70));
console.log('');
console.log('  SECURITY NOTICE:');
console.log('  - All endpoints (except /health) require Bearer token authentication');
console.log('  - CORS restricted to localhost origins');
console.log('  - Rate limiting: ' + RATE_LIMIT_REQUESTS + ' requests/minute');
console.log('  - Session files base: ' + SESSIONS_BASE_DIR);
console.log('');
console.log(`  Server: http://${HOST}:${PORT}`);
console.log(`  Database: ${DATABASE_URL.replace(/:[^@]+@/, ':***@')}`);
console.log('');
console.log('  Endpoints:');
console.log('    GET /sessions         - Search sessions');
console.log('    GET /sessions/:id     - Get single session');
console.log('    GET /sessions/stats   - Usage statistics');
console.log('    GET /health           - Health check (no auth)');
console.log('');
console.log('='.repeat(70));
console.log('');

export default {
  port: PORT,
  hostname: HOST,
  fetch: app.fetch,
};
