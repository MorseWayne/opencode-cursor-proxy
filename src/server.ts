/**
 * OpenAI-Compatible API Server
 *
 * Routes OpenAI API requests through Cursor's Agent API backend.
 * Supports:
 * - POST /v1/chat/completions (streaming and non-streaming)
 * - GET /v1/models
 *
 * Usage:
 *   CURSOR_ACCESS_TOKEN=<token> bun run src/server.ts
 *
 * Or with auto-loaded credentials:
 *   bun run src/server.ts
 */

import { FileCredentialManager } from "./lib/storage";
import { createRequestHandler } from "./lib/openai-compat";

// Debug logging - set CURSOR_DEBUG=1 to enable
const DEBUG = process.env.CURSOR_DEBUG === "1";
const debugLog = DEBUG ? console.log.bind(console) : () => {};

// --- Server Configuration ---

const PORT = Number.parseInt(process.env.PORT ?? "18741", 10);

// --- Authentication ---

async function getAccessToken(): Promise<string> {
  // First check environment variable
  const envToken = process.env.CURSOR_ACCESS_TOKEN;
  if (envToken) {
    return envToken;
  }

  // Fall back to credential manager
  const cm = new FileCredentialManager("cursor");
  const token = await cm.getAccessToken();
  if (!token) {
    throw new Error("No access token found. Set CURSOR_ACCESS_TOKEN or authenticate first.");
  }
  return token;
}

// --- Main ---

debugLog("Starting OpenAI-compatible API server...");

let accessToken: string;
try {
  accessToken = await getAccessToken();
  debugLog("Access token loaded successfully");
} catch (err) {
  console.error("Failed to get access token:", err instanceof Error ? err.message : String(err));
  process.exit(1);
}

// Create the request handler from shared module
const handleRequest = createRequestHandler({
  accessToken,
  log: debugLog,
});

Bun.serve({
  port: PORT,
  idleTimeout: 120, // 2 minutes to allow for long tool executions

  async fetch(req) {
    const url = new URL(req.url);

    // Enhanced health check with version info (server-specific)
    if (url.pathname === "/health" || url.pathname === "/") {
      return new Response(JSON.stringify({ status: "ok", version: "1.0.0" }), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    // Delegate to shared request handler
    return handleRequest(req);
  },
});

debugLog(`
╔════════════════════════════════════════════════════════════╗
║  OpenAI-Compatible API Server                              ║
╠════════════════════════════════════════════════════════════╣
║  Server running on http://localhost:${PORT.toString().padEnd(24)}║
║                                                            ║
║  Endpoints:                                                ║
║    POST /v1/chat/completions  - Chat completions           ║
║    GET  /v1/models            - List available models      ║
║    GET  /health               - Health check               ║
║                                                            ║
║  Usage with curl:                                          ║
║    curl http://localhost:${PORT}/v1/chat/completions ${" ".repeat(Math.max(0, 6 - PORT.toString().length))}║
║      -H "Content-Type: application/json" \                 ║
║      -d '{"model":"gpt-4o","messages":[...]}'              ║
║                                                            ║
║  Usage with OpenAI SDK:                                    ║
║    const openai = new OpenAI({                             ║
║      baseURL: "http://localhost:${PORT}/v1",${" ".repeat(Math.max(0, 20 - PORT.toString().length))}║
║      apiKey: "not-needed"                                  ║
║    });                                                     ║

╚════════════════════════════════════════════════════════════╝
`);
