/**
 * Cursor API Test Script
 *
 * Tests the CursorClient by making real API calls using stored credentials.
 *
 * Usage:
 *   bun scripts/api-test.ts [command]
 *
 * Commands:
 *   chat       - Send a simple chat request (non-streaming)
 *   stream     - Send a streaming chat request
 *   status     - Show current credentials status
 */

import { FileCredentialManager } from "../src/lib/storage";
import {
  CursorClient,
  createCursorClient,
  type ChatMessage,
} from "../src/lib/api/cursor-client";

// --- Helper Functions ---

function maskToken(token: string | undefined): string {
  if (!token) return "(not set)";
  if (token.length < 20) return "***";
  return `${token.substring(0, 10)}...${token.substring(token.length - 10)}`;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const base64Payload = token.split(".")[1];
    if (!base64Payload) return null;
    const payloadBuffer = Buffer.from(base64Payload, "base64");
    return JSON.parse(payloadBuffer.toString());
  } catch {
    return null;
  }
}

function formatDuration(seconds: number): string {
  if (seconds < 0) return "expired";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

// --- Commands ---

async function showStatus(credentialManager: FileCredentialManager) {
  console.log("\n=== Credentials Status ===\n");
  console.log(`Storage: ${credentialManager.getStoragePath()}`);

  const creds = await credentialManager.getAllCredentials();

  console.log("\nStored Credentials:");
  console.log(`  Access Token:  ${maskToken(creds.accessToken)}`);
  console.log(`  Refresh Token: ${maskToken(creds.refreshToken)}`);

  if (creds.accessToken) {
    const payload = decodeJwtPayload(creds.accessToken);
    if (payload && typeof payload.exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      const timeLeft = payload.exp - now;
      console.log(`  Token Expires: ${formatDuration(timeLeft)}`);

      if (timeLeft < 0) {
        console.log(
          "\n  WARNING: Token is expired! Run `bun run auth:login` first."
        );
      }
    }
  } else {
    console.log("\n  No credentials found. Run `bun run auth:login` first.");
  }
}

async function testChat(client: CursorClient) {
  console.log("\n=== Chat Test (Non-Streaming) ===\n");

  const messages: ChatMessage[] = [
    {
      role: "system",
      content: "You are a helpful assistant. Keep responses brief.",
    },
    {
      role: "user",
      content: "Say hello and tell me what model you are in one sentence.",
    },
  ];

  console.log("Sending request...");
  console.log(`  Model: claude-3.5-sonnet`);
  console.log(`  Messages: ${messages.length}`);
  console.log("");

  try {
    const response = await client.chat({
      model: "claude-3.5-sonnet",
      messages,
    });

    console.log("Response:");
    console.log("---");
    console.log(response);
    console.log("---");
    console.log("\nChat test completed successfully!");
  } catch (error) {
    console.error("Chat request failed:", error);
    process.exit(1);
  }
}

async function testStream(client: CursorClient) {
  console.log("\n=== Stream Test ===\n");

  const messages: ChatMessage[] = [
    {
      role: "system",
      content: "You are a helpful assistant. Keep responses brief.",
    },
    {
      role: "user",
      content: "Count from 1 to 5, with a brief pause between each number.",
    },
  ];

  console.log("Sending streaming request...");
  console.log(`  Model: claude-3.5-sonnet`);
  console.log(`  Messages: ${messages.length}`);
  console.log("");
  console.log("Response:");
  console.log("---");

  try {
    let fullContent = "";
    
    for await (const chunk of client.chatStream({
      model: "claude-3.5-sonnet",
      messages,
      stream: true,
    })) {
      if (chunk.type === "delta" && chunk.content) {
        process.stdout.write(chunk.content);
        fullContent += chunk.content;
      } else if (chunk.type === "error") {
        console.error("\nStream error:", chunk.error);
        process.exit(1);
      } else if (chunk.type === "done") {
        console.log("\n---");
        console.log(`\nTotal length: ${fullContent.length} characters`);
      }
    }

    console.log("\nStream test completed successfully!");
  } catch (error) {
    console.error("\nStream request failed:", error);
    process.exit(1);
  }
}

async function testModels(client: CursorClient) {
  console.log("\n=== Model Test ===\n");

  const models = [
    "gpt-4",
    "gpt-4o",
    "claude-3.5-sonnet",
    "claude-3-opus",
  ];

  const messages: ChatMessage[] = [
    {
      role: "user",
      content: "Reply with only: OK",
    },
  ];

  for (const model of models) {
    process.stdout.write(`Testing ${model}... `);
    try {
      const response = await client.chat({ model, messages });
      console.log(`OK (${response.length} chars)`);
    } catch (error) {
      console.log(`FAILED: ${error}`);
    }
  }
}

// --- Main ---

async function main() {
  const command = process.argv[2] || "help";
  const domain = process.env.CURSOR_AUTH_DOMAIN || "cursor";

  console.log("Cursor API Test");
  console.log("================");

  const credentialManager = new FileCredentialManager(domain);

  // Always show status first
  if (command !== "status") {
    const creds = await credentialManager.getAllCredentials();
    if (!creds.accessToken) {
      console.log("\nNo credentials found. Please run:");
      console.log("  bun run auth:login");
      process.exit(1);
    }

    // Check if token is expired
    const payload = decodeJwtPayload(creds.accessToken);
    if (payload && typeof payload.exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        console.log("\nToken is expired. Please run:");
        console.log("  bun run auth:login");
        process.exit(1);
      }
    }

    // Create client
    var client = createCursorClient(creds.accessToken);
  }

  switch (command) {
    case "status":
      await showStatus(credentialManager);
      break;

    case "chat":
      await testChat(client!);
      break;

    case "stream":
      await testStream(client!);
      break;

    case "models":
      await testModels(client!);
      break;

    case "help":
    default:
      if (command !== "help") {
        console.log(`\nUnknown command: ${command}`);
      }
      console.log("\nAvailable commands:");
      console.log("  status  - Show current credentials status");
      console.log("  chat    - Send a simple chat request (non-streaming)");
      console.log("  stream  - Send a streaming chat request");
      console.log("  models  - Test multiple models");
      console.log("\nExample:");
      console.log("  bun scripts/api-test.ts chat");
      if (command !== "help") {
        process.exit(1);
      }
      break;
  }
}

main().catch((error) => {
  console.error("Error:", error);
  process.exit(1);
});
