# Configuration

This guide covers all configuration options for OpenCode Cursor Proxy.

## OpenCode Configuration

### Basic Setup

Add to your `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-cursor-proxy"],
  "provider": {
    "cursor": {
      "name": "Cursor"
    }
  }
}
```

### Custom Model Configuration

You can customize model settings in your provider configuration:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["opencode-cursor-proxy"],
  "provider": {
    "cursor": {
      "name": "Cursor",
      "models": {
        "sonnet-4.5": {
          "name": "Claude Sonnet 4.5 (Custom)",
          "limit": {
            "context": 200000,
            "output": 16384
          }
        }
      }
    }
  }
}
```

## Environment Variables

All environment variables are optional and have sensible defaults.

### Server

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server listen port | `18741` |
| `HOST` | Server listen host | `localhost` |
| `CURSOR_ACCESS_TOKEN` | Provide access token directly (skip OAuth) | - |

### Debug & Logging

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_DEBUG` | Enable verbose debug logging | `0` |
| `CURSOR_TIMING` | Enable performance timing logs | `0` |
| `CURSOR_LOG_LEVEL` | Log level: `error`, `warn`, `info`, `debug` | `info` |
| `CURSOR_LOG_JSON` | Output logs in JSON format (for log aggregators) | `0` |

### Session & Cache

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_SESSION_REUSE` | Enable session reuse for tool-calling | `1` |
| `CURSOR_SESSION_TIMEOUT_MS` | Session timeout in milliseconds | `900000` (15min) |
| `CURSOR_MAX_SESSIONS` | Maximum number of cached sessions | `100` |
| `CURSOR_MODEL_CACHE_TTL_MS` | Model list cache TTL in milliseconds | `300000` (5min) |
| `CURSOR_MAX_BLOBS` | Maximum number of cached blobs | `1000` |
| `CURSOR_MAX_BLOB_SIZE` | Maximum blob size in bytes | `10485760` (10MB) |

### Network & Retry

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_REQUEST_TIMEOUT_MS` | Request timeout in milliseconds | `120000` (2min) |
| `CURSOR_MAX_RETRIES` | Maximum retry attempts for failed requests | `3` |
| `CURSOR_RETRY_ENABLED` | Enable automatic retry on transient errors | `1` |
| `CURSOR_RETRY_BASE_DELAY_MS` | Base delay for exponential backoff | `1000` |
| `CURSOR_RETRY_MAX_DELAY_MS` | Maximum delay between retries | `30000` |

### Heartbeat Detection

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_HEARTBEAT_IDLE_PROGRESS_MS` | Idle timeout after progress | `120000` (2min) |
| `CURSOR_HEARTBEAT_IDLE_NOPROGRESS_MS` | Idle timeout before first progress | `180000` (3min) |
| `CURSOR_HEARTBEAT_MAX_PROGRESS` | Max heartbeats after progress | `1000` |
| `CURSOR_HEARTBEAT_MAX_NOPROGRESS` | Max heartbeats before progress | `1000` |

### API Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_API_URL` | Cursor API base URL | `https://api2.cursor.sh` |
| `CURSOR_AGENT_PRIVACY_URL` | Agent privacy mode URL | `https://agent.api5.cursor.sh` |
| `CURSOR_AGENT_NON_PRIVACY_URL` | Agent non-privacy mode URL | `https://agentn.api5.cursor.sh` |
| `CURSOR_PRIVACY_MODE` | Enable privacy mode | `1` |
| `CURSOR_AGENT_TRY_API5` | Try API5 fallback endpoints | `0` |
| `CURSOR_CLIENT_VERSION` | Override client version header | (auto-detect) |

### Security

| Variable | Description | Default |
|----------|-------------|---------|
| `CURSOR_VALIDATE_SHELL` | Enable shell command validation | `0` |
| `CURSOR_SHELL_TIMEOUT_MS` | Shell command execution timeout | `60000` (1min) |

### Setting Environment Variables

```bash
# Linux/macOS - temporary
export CURSOR_DEBUG=1
export CURSOR_LOG_LEVEL=debug

# Linux/macOS - persistent (add to ~/.bashrc or ~/.zshrc)
echo 'export CURSOR_DEBUG=1' >> ~/.bashrc

# Or create a .env file (for development)
cat > .env << EOF
CURSOR_DEBUG=1
CURSOR_LOG_LEVEL=debug
PORT=8080
EOF
```

## Authentication Storage

Credentials are stored securely by OpenCode's credential manager:

- **Access Token**: Short-lived token for API calls (auto-refreshed)
- **Refresh Token**: Long-lived token for obtaining new access tokens

### Token Refresh

Access tokens are automatically refreshed:

- Before expiration (60-second buffer)
- On API authentication errors

## Model Limits

The plugin automatically determines model limits from the [llm-info](https://www.npmjs.com/package/llm-info) database. Default limits if not found:

```json
{
  "context": 128000,
  "output": 16384
}
```

### Model Mappings

| Cursor Model | llm-info Model |
|--------------|----------------|
| `sonnet-4.5` | `claude-sonnet-4-5-20250929` |
| `opus-4.5` | `claude-opus-4-5-20251101` |
| `gpt-5.2` | `gpt-5.2` |
| `gpt-5.1` | `gpt-5` |
| `gemini-3-pro` | `gemini-3-pro-preview` |
| `grok` | `grok-4` |

## Advanced Configuration

### Session Reuse

Session reuse optimizes performance for conversations with multiple tool calls by maintaining context across requests.

Disable if you experience issues:

```bash
export CURSOR_SESSION_REUSE=0
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Full debug mode (most verbose)
export CURSOR_DEBUG=1

# Or use log levels for finer control
export CURSOR_LOG_LEVEL=debug

# Enable performance timing
export CURSOR_TIMING=1

# JSON output for log aggregators
export CURSOR_LOG_JSON=1
```

Debug output includes:

- API request/response details
- Token refresh events
- Model discovery information
- Session management events
- Performance timing metrics

## Proxy Server Configuration

For development/debugging, you can run the standalone proxy server:

```bash
# Custom port
PORT=9000 bun run server

# With debug logging
CURSOR_DEBUG=1 bun run server

# Disable session reuse
CURSOR_SESSION_REUSE=0 bun run server
```

The proxy server exposes an OpenAI-compatible API at:

- `GET /v1/models` - List available models
- `POST /v1/chat/completions` - Chat completions (streaming and non-streaming)

## Troubleshooting Configuration

See [Troubleshooting](./troubleshooting.md) for common configuration issues.
