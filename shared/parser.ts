/**
 * Parse Claude Code session JSONL files
 *
 * Extracts structured data from raw session transcripts including:
 * - Token usage (total and per-model)
 * - User messages
 * - Tools used
 * - Files touched (from tool calls)
 * - Timestamps
 *
 * SECURITY NOTES:
 * - File size limits prevent memory exhaustion
 * - Recursion depth limits prevent stack overflow
 * - Input validation on all parsed data
 */

import { readFileSync, statSync } from 'fs';
import type {
  SessionMessage,
  AssistantMessage,
  ParsedSession,
  ContentBlock,
} from './types.js';
import { scrubSecrets, detectSecrets, type SecretFinding } from './secrets.js';

// =============================================================================
// SECURITY CONFIGURATION
// =============================================================================

// Maximum file size to parse (100MB)
const MAX_FILE_SIZE = 100 * 1024 * 1024;

// Maximum number of lines to parse per file
const MAX_LINES = 100000;

// Maximum recursion depth for nested object extraction
const MAX_RECURSION_DEPTH = 10;

// Maximum length for user messages (truncate if longer)
const MAX_MESSAGE_LENGTH = 100000;

// Maximum number of files to track per session
const MAX_FILES_PER_SESSION = 10000;

// Maximum number of tools to track per session
const MAX_TOOLS_PER_SESSION = 1000;

// Secret scrubbing configuration
const SCRUB_SECRETS = process.env.KUATO_SCRUB_SECRETS !== 'false'; // Enabled by default
const SCRUB_MIN_SEVERITY = (process.env.KUATO_SCRUB_SEVERITY || 'high') as 'critical' | 'high' | 'medium' | 'low';

// =============================================================================
// PARSING FUNCTIONS
// =============================================================================

/**
 * Parse a single JSONL file into structured session data
 * @param filePath Path to the JSONL file
 * @returns Parsed session data or null if invalid/too large
 */
export function parseSessionFile(filePath: string): ParsedSession | null {
  try {
    // Check file size before reading
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      console.warn(`File too large, skipping: ${filePath} (${stat.size} bytes)`);
      return null;
    }

    const content = readFileSync(filePath, 'utf-8');
    return parseSessionContent(content, filePath);
  } catch (error) {
    console.warn(`Error reading file ${filePath}:`, error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * Parse JSONL content string into structured session data
 * @param content JSONL content string
 * @param sessionId Optional session identifier (typically the file path)
 * @returns Parsed session data or null if invalid
 */
export function parseSessionContent(
  content: string,
  sessionId?: string
): ParsedSession | null {
  // Split into lines with limit
  const allLines = content.trim().split('\n').filter(Boolean);

  if (allLines.length === 0) {
    return null;
  }

  // Apply line limit
  const lines = allLines.slice(0, MAX_LINES);
  if (allLines.length > MAX_LINES) {
    console.warn(`File has ${allLines.length} lines, processing only first ${MAX_LINES}`);
  }

  const messages: SessionMessage[] = [];

  for (const line of lines) {
    // Skip very long lines that might be malformed
    if (line.length > 10 * 1024 * 1024) {
      console.warn('Skipping extremely long line');
      continue;
    }

    try {
      const parsed = JSON.parse(line);
      // Only include user/assistant messages (skip summary, system, etc.)
      if (parsed.type === 'user' || parsed.type === 'assistant') {
        messages.push(parsed as SessionMessage);
      }
    } catch {
      // Skip malformed lines - log for debugging if needed
      continue;
    }
  }

  if (messages.length === 0) {
    return null;
  }

  // Extract session metadata from first and last conversation messages
  const firstMessage = messages[0];
  const lastMessage = messages[messages.length - 1];

  // Initialize accumulators with size limits
  const userMessages: string[] = [];
  const toolsUsed = new Set<string>();
  const filesFromToolCalls = new Set<string>();
  const modelsUsed = new Set<string>();

  let inputTokens = 0;
  let outputTokens = 0;
  let cacheCreationTokens = 0;
  let cacheReadTokens = 0;

  const modelTokens: Record<
    string,
    { input: number; output: number; cacheCreation: number; cacheRead: number }
  > = {};

  for (const msg of messages) {
    if (msg.type === 'user') {
      // Extract user message text with length limit
      const userMsg = msg.message as { role: string; content: string };
      if (typeof userMsg.content === 'string' && userMsg.content.trim()) {
        let content = userMsg.content.length > MAX_MESSAGE_LENGTH
          ? userMsg.content.slice(0, MAX_MESSAGE_LENGTH) + '...[truncated]'
          : userMsg.content;

        // Scrub secrets from user messages if enabled
        if (SCRUB_SECRETS) {
          content = scrubSecrets(content, { minSeverity: SCRUB_MIN_SEVERITY });
        }

        userMessages.push(content);
      }
    } else if (msg.type === 'assistant') {
      const assistantMsg = msg.message as AssistantMessage;

      // Track model
      if (assistantMsg.model) {
        modelsUsed.add(assistantMsg.model);

        // Initialize model token tracking
        if (!modelTokens[assistantMsg.model]) {
          modelTokens[assistantMsg.model] = {
            input: 0,
            output: 0,
            cacheCreation: 0,
            cacheRead: 0,
          };
        }
      }

      // Accumulate token usage (with overflow protection)
      if (assistantMsg.usage) {
        const usage = assistantMsg.usage;
        inputTokens = safeAdd(inputTokens, usage.input_tokens || 0);
        outputTokens = safeAdd(outputTokens, usage.output_tokens || 0);
        cacheCreationTokens = safeAdd(cacheCreationTokens, usage.cache_creation_input_tokens || 0);
        cacheReadTokens = safeAdd(cacheReadTokens, usage.cache_read_input_tokens || 0);

        // Per-model tracking
        if (assistantMsg.model && modelTokens[assistantMsg.model]) {
          modelTokens[assistantMsg.model].input = safeAdd(
            modelTokens[assistantMsg.model].input,
            usage.input_tokens || 0
          );
          modelTokens[assistantMsg.model].output = safeAdd(
            modelTokens[assistantMsg.model].output,
            usage.output_tokens || 0
          );
          modelTokens[assistantMsg.model].cacheCreation = safeAdd(
            modelTokens[assistantMsg.model].cacheCreation,
            usage.cache_creation_input_tokens || 0
          );
          modelTokens[assistantMsg.model].cacheRead = safeAdd(
            modelTokens[assistantMsg.model].cacheRead,
            usage.cache_read_input_tokens || 0
          );
        }
      }

      // Extract tools and files from content blocks (with limits)
      if (Array.isArray(assistantMsg.content)) {
        for (const block of assistantMsg.content) {
          // Stop if we've hit our limits
          if (toolsUsed.size >= MAX_TOOLS_PER_SESSION &&
              filesFromToolCalls.size >= MAX_FILES_PER_SESSION) {
            break;
          }
          extractFromContentBlock(block, toolsUsed, filesFromToolCalls, 0);
        }
      }
    }
  }

  // Derive session ID from file path or first message
  const id =
    sessionId?.match(/([a-f0-9-]{36})\.jsonl$/)?.[1] ||
    firstMessage.sessionId ||
    'unknown';

  return {
    id,
    startedAt: new Date(firstMessage.timestamp),
    endedAt: new Date(lastMessage.timestamp),
    gitBranch: sanitizeString(firstMessage.gitBranch) || 'unknown',
    cwd: sanitizeString(firstMessage.cwd) || '',
    version: sanitizeString(firstMessage.version) || '',
    messageCount: messages.length,

    inputTokens,
    outputTokens,
    cacheCreationTokens,
    cacheReadTokens,

    userMessages,
    toolsUsed: Array.from(toolsUsed).slice(0, MAX_TOOLS_PER_SESSION),
    filesFromToolCalls: Array.from(filesFromToolCalls).slice(0, MAX_FILES_PER_SESSION),
    modelsUsed: Array.from(modelsUsed),
    modelTokens,
  };
}

/**
 * Extract tool names and file paths from a content block
 * @param block Content block to extract from
 * @param toolsUsed Set to add tool names to
 * @param filesFromToolCalls Set to add file paths to
 * @param depth Current recursion depth
 */
function extractFromContentBlock(
  block: ContentBlock,
  toolsUsed: Set<string>,
  filesFromToolCalls: Set<string>,
  depth: number
): void {
  // Prevent excessive recursion
  if (depth > MAX_RECURSION_DEPTH) {
    return;
  }

  // Check size limits
  if (toolsUsed.size >= MAX_TOOLS_PER_SESSION &&
      filesFromToolCalls.size >= MAX_FILES_PER_SESSION) {
    return;
  }

  if (block.type === 'tool_use' && block.name) {
    if (toolsUsed.size < MAX_TOOLS_PER_SESSION) {
      toolsUsed.add(sanitizeString(block.name) || 'unknown');
    }

    // Extract file paths from tool inputs
    if (block.input && typeof block.input === 'object') {
      extractFilePaths(block.input, filesFromToolCalls, depth + 1);
    }
  }
}

/**
 * Recursively extract file paths from tool input with depth limiting
 * @param input Tool input object
 * @param files Set to add file paths to
 * @param depth Current recursion depth
 */
function extractFilePaths(
  input: Record<string, unknown>,
  files: Set<string>,
  depth: number
): void {
  // Prevent excessive recursion
  if (depth > MAX_RECURSION_DEPTH) {
    return;
  }

  // Check size limit
  if (files.size >= MAX_FILES_PER_SESSION) {
    return;
  }

  for (const [key, value] of Object.entries(input)) {
    // Common file path parameter names
    if (
      ['file_path', 'path', 'file', 'filename', 'filePath'].includes(key) &&
      typeof value === 'string'
    ) {
      // Only add if it looks like a path and is reasonably sized
      if ((value.includes('/') || value.includes('\\')) && value.length < 4096) {
        files.add(sanitizeString(value) || '');
      }
    }

    // Recurse into nested objects (not arrays to avoid performance issues)
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      extractFilePaths(value as Record<string, unknown>, files, depth + 1);
    }
  }
}

/**
 * Get a simple text summary suitable for search indexing
 * @param session Parsed session data
 * @returns Searchable text string
 */
export function getSearchableText(session: ParsedSession): string {
  const parts: string[] = [];

  // User messages are highest signal
  parts.push(...session.userMessages);

  // Tools and files provide context
  parts.push(...session.toolsUsed);
  parts.push(...session.filesFromToolCalls);

  return parts.join(' ');
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Safe addition to prevent integer overflow
 */
function safeAdd(a: number, b: number): number {
  const result = a + b;
  // Check for overflow (use Number.MAX_SAFE_INTEGER as limit)
  if (result > Number.MAX_SAFE_INTEGER) {
    return Number.MAX_SAFE_INTEGER;
  }
  return result;
}

/**
 * Sanitize a string to remove control characters and limit length
 */
function sanitizeString(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  // Remove control characters except newlines and tabs
  const sanitized = value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  // Limit length
  return sanitized.slice(0, 10000);
}
