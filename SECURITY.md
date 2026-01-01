# Security Documentation

## Overview

Kuato is a session memory tool for Claude Code that stores and searches conversation transcripts. Due to the sensitive nature of this data (which may contain credentials, API keys, architectural decisions, and proprietary code), security is a critical concern.

## Data Sensitivity Warning

**Session data may contain:**
- API keys and credentials mentioned in conversations
- Database connection strings
- Internal API endpoints and architecture details
- Proprietary code and business logic
- Development decisions and security vulnerabilities discussed
- PII from test data or debugging sessions

**Treat your Kuato database as highly sensitive data.**

## Security Controls

### Authentication

All API endpoints (except `/health`) require Bearer token authentication.

```bash
# Set your API key
export KUATO_API_KEY="your-secure-api-key"

# Make authenticated requests
curl -H "Authorization: Bearer $KUATO_API_KEY" http://localhost:3847/sessions
```

**Best practices:**
- Generate a secure API key: `openssl rand -base64 32`
- Store the API key in environment variables, never in code
- Rotate API keys periodically
- Use different keys for development and production

### Network Security

**Default configuration binds to localhost only (127.0.0.1).**

```bash
# Default - localhost only (secure)
HOST=127.0.0.1

# Only change if you understand the implications
HOST=0.0.0.0  # WARNING: Exposes to network
```

**Recommendations:**
- Never expose Kuato to the public internet
- Use a VPN or SSH tunnel for remote access
- Configure firewall rules to restrict access
- Use TLS/HTTPS in production (reverse proxy recommended)

### CORS Protection

CORS is restricted to localhost origins only. Requests from external websites will be blocked.

### Rate Limiting

Default: 100 requests per minute per IP address.

```bash
# Customize rate limit
export KUATO_RATE_LIMIT=50  # requests per minute
```

### Input Validation

All inputs are validated and sanitized:
- Search queries: max 1000 characters
- Days parameter: max 3650 (10 years)
- Result limit: max 100 results
- Session IDs: UUID format validation
- File patterns: max 500 characters

### Path Traversal Protection

Transcript file paths are validated to ensure they stay within the configured sessions directory. Attempts to read files outside this directory are blocked and logged.

### Audit Logging

All API requests (except health checks) are logged in JSON format:
```json
{
  "type": "audit",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "ip": "127.0.0.1",
  "method": "GET",
  "path": "/sessions",
  "query": {"search": "authentication"},
  "userAgent": "curl/8.0.0",
  "statusCode": 200
}
```

### Database Security

- Use strong, randomly generated passwords
- Bind PostgreSQL to localhost by default
- Use connection pooling with limits
- Graceful shutdown closes connections properly

## Configuration

### Required Environment Variables

```bash
# API Authentication (required)
KUATO_API_KEY=your-secure-api-key

# Database (required for PostgreSQL)
POSTGRES_PASSWORD=your-secure-db-password
```

### Optional Environment Variables

```bash
# Network binding
HOST=127.0.0.1              # API bind address
POSTGRES_HOST=127.0.0.1     # Database bind address

# Rate limiting
KUATO_RATE_LIMIT=100        # Requests per minute

# Session files location
KUATO_SESSIONS_DIR=/path/to/sessions
CLAUDE_SESSIONS_DIR=/path/to/sessions
```

### Docker Security

The docker-compose configuration includes:
- `no-new-privileges:true` - Prevents privilege escalation
- `read_only: true` - Read-only filesystem
- Environment variable requirements (will fail if not set)
- Localhost-only port bindings by default

## Threat Model

### In Scope
- Unauthorized access to session data
- Path traversal attacks
- SQL injection attacks
- Denial of service (rate limiting)
- Information disclosure in logs/errors

### Mitigations Applied
| Threat | Mitigation |
|--------|------------|
| Unauthorized access | Bearer token authentication |
| Path traversal | Path validation, directory restriction |
| SQL injection | Parameterized queries throughout |
| DoS | Rate limiting, input size limits |
| Info disclosure | Generic error messages, safe logging |
| CORS attacks | Localhost-only origin restriction |
| Credential exposure | Environment variables, no hardcoding |

### Residual Risks
- **Local access**: If an attacker has access to your machine, they can read the database
- **Credential in sessions**: User messages may contain credentials - consider periodic cleanup
- **Backup exposure**: Database backups contain sensitive data - encrypt them
- **Shared networks**: Other users on the same network could potentially access if misconfigured

## Best Practices

### For Developers

1. **Never commit credentials**
   ```bash
   # Add to .gitignore
   .env
   *.env
   ```

2. **Use strong passwords**
   ```bash
   openssl rand -base64 32
   ```

3. **Regular cleanup**
   ```sql
   -- Delete old sessions
   DELETE FROM sessions WHERE ended_at < NOW() - INTERVAL '90 days';
   ```

4. **Monitor logs**
   ```bash
   # Watch for suspicious activity
   tail -f /var/log/kuato.log | jq 'select(.statusCode >= 400)'
   ```

### For Operations

1. **Firewall rules**
   ```bash
   # Block external access to Kuato port
   sudo ufw deny from any to any port 3847
   sudo ufw allow from 127.0.0.1 to any port 3847
   ```

2. **TLS termination** (recommended for any network access)
   ```nginx
   server {
       listen 443 ssl;
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://127.0.0.1:3847;
       }
   }
   ```

3. **Database encryption**
   - Enable PostgreSQL TDE for encryption at rest
   - Or use full-disk encryption on the host

4. **Backup security**
   ```bash
   # Encrypt backups
   pg_dump claude_sessions | gpg -c > backup.sql.gpg
   ```

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security concerns to the maintainers
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Changelog

### v1.0.0 (Security Hardening Release)

- Added Bearer token authentication
- Implemented path traversal protection
- Fixed SQL injection vulnerabilities (parameterized queries)
- Added CORS restrictions (localhost only)
- Added rate limiting
- Added input validation and size limits
- Added audit logging
- Added graceful shutdown handling
- Fixed race conditions with file locking
- Removed hardcoded credentials
- Added security documentation
