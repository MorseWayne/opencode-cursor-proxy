/**
 * KV Blob Investigation Script
 * 
 * This script triggers tool calls through the proxy and monitors KV blob data
 * during session continuation. Run the server with enhanced logging to capture blobs.
 * 
 * Usage: 
 * 1. Start the server: CURSOR_SESSION_REUSE=1 bun run src/server.ts 2>&1 | tee server.log
 * 2. Run this script: bun run scripts/investigate-kv-blobs.ts
 * 3. Analyze blobs in server.log
 */

const BASE_URL = process.env.BASE_URL || "http://localhost:18741";

interface SSEEvent {
  data: string;
}

async function readSSEChunks(resp: Response, onEvent: (evt: SSEEvent) => void): Promise<void> {
  if (!resp.body) throw new Error("No response body for SSE");
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 2);
      if (chunk.startsWith("data:")) {
        const data = chunk.slice(5).trim();
        onEvent({ data });
      }
    }
  }
}

async function makeInitialRequest(): Promise<{ toolCallId: string; toolName: string; toolArgs: any } | null> {
  console.log("\n=== Step 1: Initial request to trigger tool call ===\n");
  
  const body = {
    model: "gpt-4o",
    stream: true,
    messages: [
      { role: "user", content: "Please use the bash tool to run: echo 'Hello from KV blob investigation'" }
    ],
    tools: [
      {
        type: "function",
        function: {
          name: "bash",
          description: "Run a bash command",
          parameters: {
            type: "object",
            properties: { command: { type: "string", description: "The command to run" } },
            required: ["command"],
          },
        },
      },
    ],
  };

  const resp = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    console.error(`Request failed: ${resp.status}`);
    return null;
  }

  let toolCallId: string | null = null;
  let toolName: string | null = null;
  let toolArgs: any = null;
  let finishReason: string | null = null;
  let textContent = "";

  await readSSEChunks(resp, ({ data }) => {
    if (data === "[DONE]") return;
    try {
      const parsed = JSON.parse(data);
      
      // Check for tool calls
      const toolCalls = parsed?.choices?.[0]?.delta?.tool_calls;
      if (toolCalls && toolCalls.length > 0) {
        const tc = toolCalls[0];
        if (tc.id) toolCallId = tc.id;
        if (tc.function?.name) toolName = tc.function.name;
        if (tc.function?.arguments) {
          try {
            toolArgs = JSON.parse(tc.function.arguments);
          } catch {
            toolArgs = tc.function.arguments;
          }
        }
      }

      // Check for text content
      const content = parsed?.choices?.[0]?.delta?.content;
      if (content) textContent += content;

      // Check for finish reason
      const fr = parsed?.choices?.[0]?.finish_reason;
      if (fr) finishReason = fr;
    } catch (e) {
      // Ignore parse errors
    }
  });

  console.log(`Text received: "${textContent.slice(0, 100)}${textContent.length > 100 ? '...' : ''}"`);
  console.log(`Finish reason: ${finishReason}`);
  
  if (toolCallId && toolName) {
    console.log(`\nTool call detected:`);
    console.log(`  ID: ${toolCallId}`);
    console.log(`  Name: ${toolName}`);
    console.log(`  Args: ${JSON.stringify(toolArgs)}`);
    return { toolCallId, toolName, toolArgs };
  }

  console.log("No tool call detected");
  return null;
}

async function sendToolResult(toolCallId: string, result: string): Promise<void> {
  console.log("\n=== Step 2: Send tool result (triggers session reuse) ===\n");
  console.log(`Session ID from tool call: ${toolCallId.split('__')[0]}`);
  console.log(`Tool result: ${result.slice(0, 100)}...`);
  
  const body = {
    model: "gpt-4o",
    stream: true,
    messages: [
      { role: "user", content: "Please use the bash tool to run: echo 'Hello from KV blob investigation'" },
      {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: toolCallId,
            type: "function",
            function: {
              name: "bash",
              arguments: '{"command":"echo \'Hello from KV blob investigation\'"}'
            }
          }
        ]
      },
      {
        role: "tool",
        tool_call_id: toolCallId,
        content: result
      }
    ],
    // Note: We include tools to allow for multi-step flows
    tools: [
      {
        type: "function",
        function: {
          name: "bash",
          description: "Run a bash command",
          parameters: {
            type: "object",
            properties: { command: { type: "string", description: "The command to run" } },
            required: ["command"],
          },
        },
      },
    ],
  };

  console.log("\nSending tool result request...");
  console.log("(Watch server logs for KV blob activity)\n");

  const resp = await fetch(`${BASE_URL}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    console.error(`Request failed: ${resp.status}`);
    const text = await resp.text();
    console.error(`Error: ${text}`);
    return;
  }

  let textContent = "";
  let finishReason: string | null = null;
  let chunkCount = 0;

  console.log("--- Response stream ---");
  
  await readSSEChunks(resp, ({ data }) => {
    chunkCount++;
    if (data === "[DONE]") {
      console.log("[DONE]");
      return;
    }
    try {
      const parsed = JSON.parse(data);
      
      // Check for text content
      const content = parsed?.choices?.[0]?.delta?.content;
      if (content) {
        textContent += content;
        process.stdout.write(content);
      }

      // Check for finish reason
      const fr = parsed?.choices?.[0]?.finish_reason;
      if (fr) finishReason = fr;

      // Check for tool calls (in case model wants another tool)
      const toolCalls = parsed?.choices?.[0]?.delta?.tool_calls;
      if (toolCalls && toolCalls.length > 0) {
        console.log(`\n[Additional tool call: ${toolCalls[0]?.function?.name}]`);
      }

      // Check for errors
      if (parsed?.error) {
        console.error(`\nError in response: ${JSON.stringify(parsed.error)}`);
      }
    } catch (e) {
      console.log(`[Parse error for chunk ${chunkCount}]`);
    }
  });

  console.log("\n\n--- Summary ---");
  console.log(`Total chunks: ${chunkCount}`);
  console.log(`Text received: ${textContent.length} chars`);
  console.log(`Finish reason: ${finishReason}`);

  if (textContent.length === 0 && finishReason !== "tool_calls") {
    console.log("\n⚠️  No text received! This indicates the response was stored in KV blobs.");
    console.log("Check the server logs for [DEBUG] Blob data lines to see what was stored.");
  }
}

async function main() {
  console.log("=== KV Blob Investigation ===");
  console.log(`Target: ${BASE_URL}`);
  console.log("");
  console.log("This script triggers a tool call flow to observe KV blob behavior.");
  console.log("Watch the server logs for [DEBUG] lines showing KV blob activity.");
  console.log("");

  // Step 1: Make initial request to get tool call
  const toolCall = await makeInitialRequest();
  
  if (!toolCall) {
    console.log("\nNo tool call received. Try a different prompt or check server is running.");
    return;
  }

  // Step 2: Send tool result back
  const toolResult = JSON.stringify({
    stdout: "Hello from KV blob investigation\n",
    stderr: "",
    exitCode: 0,
    executionTimeMs: 15
  });

  await sendToolResult(toolCall.toolCallId, toolResult);

  console.log("\n=== Investigation Complete ===");
  console.log("Review server logs for KV blob details.");
  console.log("Look for lines containing:");
  console.log("  - [DEBUG] Blob data");
  console.log("  - [DEBUG] Detected assistant response blob");
  console.log("  - [Session ...] Emitting KV blob");
}

main().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});
