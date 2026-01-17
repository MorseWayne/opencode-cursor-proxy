// Session reuse manual harness covering multiple tool types.
// Requires server running on http://localhost:18741.
// Usage: bun run scripts/session-reuse-harness.ts

const BASE = process.env.HARNESS_BASE_URL ?? "http://localhost:18741";

interface SSEEvent {
  data: string;
}

type HarnessTool = "bash" | "read" | "list" | "grep" | "glob" | "mcp";

const TOOL_DEFS: Record<HarnessTool, any> = {
  bash: {
    type: "function",
    function: {
      name: "bash",
      description: "Run a bash command",
      parameters: {
        type: "object",
        properties: { command: { type: "string" } },
        required: ["command"],
      },
    },
  },
  read: {
    type: "function",
    function: {
      name: "read",
      description: "Read a file",
      parameters: {
        type: "object",
        properties: { filePath: { type: "string" } },
        required: ["filePath"],
      },
    },
  },
  list: {
    type: "function",
    function: {
      name: "list",
      description: "List a directory",
      parameters: {
        type: "object",
        properties: { path: { type: "string" } },
        required: ["path"],
      },
    },
  },
  grep: {
    type: "function",
    function: {
      name: "grep",
      description: "Search for a pattern",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string" },
          path: { type: "string" },
        },
        required: ["pattern"],
      },
    },
  },
  glob: {
    type: "function",
    function: {
      name: "glob",
      description: "Glob for files",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string" },
          path: { type: "string" },
        },
        required: ["pattern"],
      },
    },
  },
  mcp: {
    type: "function",
    function: {
      name: "opencode_tool",
      description: "Mock MCP tool",
      parameters: {
        type: "object",
        properties: { payload: { type: "string" } },
      },
    },
  },
};

const PROMPTS: Record<HarnessTool, string> = {
  bash: "Use the bash tool to run: echo harness",
  read: "Use the read tool to read /etc/hosts",
  list: "Use the list tool to list /tmp",
  grep: "Use the grep tool to search 'root' under /etc",
  glob: "Use the glob tool to list any files (pattern **/*.ts)",
  mcp: "Call the opencode_tool with any payload",
};

function buildToolResult(tool: HarnessTool): string {
  switch (tool) {
    case "bash":
      return JSON.stringify({ stdout: "ok-from-bash", stderr: "", exitCode: 0 });
    case "read":
      return "file-contents-from-harness";
    case "list":
      return "fileA\nfileB";
    case "grep":
    case "glob":
      return "/tmp/fileA\n/tmp/fileB";
    case "mcp":
      return JSON.stringify({ payload: "mcp-result" });
  }
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

async function startTurn(tool: HarnessTool, attempt: number = 1): Promise<string | null> {
  const body = {
    model: "gpt-4o",
    stream: true,
    messages: [{ role: "user", content: PROMPTS[tool] }],
    tools: [TOOL_DEFS[tool]],
  };

  const resp = await fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`startTurn failed (${tool}): ${resp.status}`);

  let toolCallId: string | null = null;
  await readSSEChunks(resp, ({ data }) => {
    if (data === "[DONE]") return;
    try {
      const parsed = JSON.parse(data);
      const toolCalls = parsed?.choices?.[0]?.delta?.tool_calls;
      if (toolCalls && toolCalls.length > 0 && toolCalls[0].id) {
        toolCallId = toolCalls[0].id;
      }
    } catch {
      // ignore malformed chunks
    }
  });

  if (toolCallId) return toolCallId;

  // Allow MCP to skip if model declines
  if (tool === "mcp") {
    console.warn("No tool_call_id for MCP; skipping");
    return null;
  }

  if (attempt >= 2) throw new Error(`No tool_call_id observed for ${tool}`);
  return startTurn(tool, attempt + 1);
}

async function continueTurn(tool_call_id: string, tool: HarnessTool): Promise<string> {
  const sessionId = tool_call_id.match(/^sess_([a-zA-Z0-9]+)/)?.[1] ?? "";
  const body = {
    model: "gpt-4o",
    stream: true,
    messages: [
      { role: "user", content: "Continue after tool" },
      {
        role: "tool",
        tool_call_id,
        content: buildToolResult(tool),
      },
    ],
  };

  const resp = await fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`continueTurn failed (${tool}): ${resp.status}`);

  let gotContent = false;
  await readSSEChunks(resp, ({ data }) => {
    if (data === "[DONE]") return;
    try {
      const parsed = JSON.parse(data);
      const content = parsed?.choices?.[0]?.delta?.content;
      if (content) gotContent = true;
    } catch {
      // ignore
    }
  });
  if (!gotContent) throw new Error(`No continuation content for session ${sessionId}`);
  return sessionId;
}

async function main() {
  console.log(`Harness against ${BASE}`);

  const tools: HarnessTool[] = ["bash", "read", "list", "grep", "glob", "mcp"];

  const toolCalls: Array<{ tool: HarnessTool; id: string }> = [];
  for (const tool of tools) {
    const tc = await startTurn(tool);
    if (tc) toolCalls.push({ tool, id: tc });
  }

  if (toolCalls.length === 0) throw new Error("No tool_call_ids observed");

  console.log("tool_call_ids:", toolCalls.map((t) => `${t.tool}:${t.id}`).join(", "));
  const ids = toolCalls.map((t) => t.id);
  if (new Set(ids).size !== ids.length) throw new Error("tool_call_ids should be unique");

  const sessionIds = await Promise.all(toolCalls.map((t) => continueTurn(t.id, t.tool)));
  if (new Set(sessionIds).size !== sessionIds.length) throw new Error("sessionIds should be unique");

  console.log("✔ Session reuse harness completed across tools (bash/read/list/grep/glob + optional mcp)");
}

main().catch((err) => {
  console.error("Harness failed:", err);
  process.exit(1);
});
