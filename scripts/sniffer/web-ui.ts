/**
 * Web UI for cursor-sniffer
 * 
 * Provides a browser-based interface for viewing and analyzing traffic.
 */

import { colors, type TrafficEntry, type ParsedMessage } from "./types";
import {
  addTrafficListener,
  emitTraffic,
  analyzeProtoFields,
  parseAgentClientMessage,
  parseAgentServerMessage,
  removeEnvelope,
  hexDump,
} from "./analyzer";
import { parseProtoFields } from "../../src/lib/api/proto/decoding";
import { parseInteractionUpdate } from "../../src/lib/api/proto/interaction";
import { parseExecServerMessage } from "../../src/lib/api/proto/exec";

const c = colors;

interface WebUIOptions {
  port: number;
  uiPort: number;
  verbose?: boolean;
  showRaw?: boolean;
}

// Traffic storage
const trafficHistory: TrafficEntry[] = [];
const MAX_HISTORY = 1000;

// WebSocket clients
const wsClients = new Set<WebSocket>();

// Generate the HTML UI
function generateHTML(uiPort: number): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cursor Sniffer - Traffic Analyzer</title>
  <style>
    :root {
      --bg-primary: #1a1a2e;
      --bg-secondary: #16213e;
      --bg-tertiary: #0f3460;
      --text-primary: #eaeaea;
      --text-secondary: #a0a0a0;
      --accent-blue: #4da6ff;
      --accent-green: #4dff88;
      --accent-yellow: #ffcc4d;
      --accent-red: #ff4d4d;
      --accent-purple: #b84dff;
      --border-color: #2a2a4a;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
      background: var(--bg-primary);
      color: var(--text-primary);
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    
    header {
      background: var(--bg-secondary);
      padding: 16px 24px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    header h1 {
      font-size: 18px;
      font-weight: 600;
      color: var(--accent-blue);
    }
    
    .status {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      color: var(--text-secondary);
    }
    
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-green);
      animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    .controls {
      display: flex;
      gap: 12px;
    }
    
    button {
      background: var(--bg-tertiary);
      border: 1px solid var(--border-color);
      color: var(--text-primary);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 12px;
      transition: all 0.2s;
    }
    
    button:hover {
      background: var(--accent-blue);
      border-color: var(--accent-blue);
    }
    
    .main {
      flex: 1;
      display: flex;
      overflow: hidden;
    }
    
    .traffic-list {
      width: 45%;
      border-right: 1px solid var(--border-color);
      overflow-y: auto;
    }
    
    .traffic-item {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      cursor: pointer;
      transition: background 0.2s;
    }
    
    .traffic-item:hover {
      background: var(--bg-secondary);
    }
    
    .traffic-item.selected {
      background: var(--bg-tertiary);
      border-left: 3px solid var(--accent-blue);
    }
    
    .traffic-item .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 4px;
    }
    
    .traffic-item .type {
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
    }
    
    .traffic-item .type.request {
      background: var(--accent-green);
      color: var(--bg-primary);
    }
    
    .traffic-item .type.response {
      background: var(--accent-blue);
      color: var(--bg-primary);
    }
    
    .traffic-item .time {
      font-size: 11px;
      color: var(--text-secondary);
    }
    
    .traffic-item .endpoint {
      font-size: 12px;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    .traffic-item .messages {
      font-size: 11px;
      color: var(--accent-yellow);
      margin-top: 4px;
    }
    
    .detail-panel {
      flex: 1;
      overflow-y: auto;
      padding: 20px;
      background: var(--bg-secondary);
    }
    
    .detail-section {
      margin-bottom: 24px;
    }
    
    .detail-section h3 {
      font-size: 12px;
      color: var(--accent-blue);
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    
    .detail-content {
      background: var(--bg-primary);
      border-radius: 8px;
      padding: 16px;
      font-size: 12px;
      line-height: 1.6;
    }
    
    .message-item {
      background: var(--bg-tertiary);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 8px;
    }
    
    .message-item .type {
      color: var(--accent-purple);
      font-weight: 600;
    }
    
    .message-item .summary {
      color: var(--accent-green);
      margin-left: 8px;
    }
    
    .message-item .details {
      margin-top: 8px;
      color: var(--text-secondary);
      font-size: 11px;
      white-space: pre-wrap;
      word-break: break-all;
    }
    
    .hex-dump {
      font-family: 'SF Mono', monospace;
      font-size: 11px;
      color: var(--text-secondary);
      white-space: pre;
      overflow-x: auto;
    }
    
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: var(--text-secondary);
      font-size: 14px;
    }
    
    .empty-state svg {
      width: 64px;
      height: 64px;
      margin-bottom: 16px;
      opacity: 0.5;
    }
    
    .filter-bar {
      background: var(--bg-secondary);
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
    }
    
    .filter-bar input {
      width: 100%;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      color: var(--text-primary);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 12px;
    }
    
    .filter-bar input::placeholder {
      color: var(--text-secondary);
    }
    
    .filter-bar input:focus {
      outline: none;
      border-color: var(--accent-blue);
    }
  </style>
</head>
<body>
  <header>
    <h1>Cursor Sniffer</h1>
    <div class="status">
      <div class="status-dot"></div>
      <span id="connection-status">Connected</span>
    </div>
    <div class="controls">
      <button onclick="clearTraffic()">Clear</button>
      <button onclick="exportTraffic()">Export</button>
    </div>
  </header>
  
  <div class="main">
    <div class="traffic-list">
      <div class="filter-bar">
        <input type="text" id="filter" placeholder="Filter by endpoint or message type..." oninput="filterTraffic()">
      </div>
      <div id="traffic-container"></div>
    </div>
    
    <div class="detail-panel" id="detail-panel">
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
        </svg>
        <p>Select a traffic entry to view details</p>
      </div>
    </div>
  </div>
  
  <script>
    const traffic = [];
    let selectedId = null;
    let ws = null;
    
    function connectWebSocket() {
      ws = new WebSocket('ws://localhost:${uiPort}/ws');
      
      ws.onopen = () => {
        document.getElementById('connection-status').textContent = 'Connected';
        document.querySelector('.status-dot').style.background = 'var(--accent-green)';
      };
      
      ws.onclose = () => {
        document.getElementById('connection-status').textContent = 'Disconnected';
        document.querySelector('.status-dot').style.background = 'var(--accent-red)';
        setTimeout(connectWebSocket, 2000);
      };
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'traffic') {
          traffic.unshift(data.entry);
          if (traffic.length > 500) traffic.pop();
          renderTraffic();
        } else if (data.type === 'history') {
          traffic.length = 0;
          traffic.push(...data.entries);
          renderTraffic();
        }
      };
    }
    
    function renderTraffic() {
      const container = document.getElementById('traffic-container');
      const filter = document.getElementById('filter').value.toLowerCase();
      
      const filtered = traffic.filter(t => {
        if (!filter) return true;
        const searchText = t.endpoint + ' ' + t.messages.map(m => m.type + ' ' + m.summary).join(' ');
        return searchText.toLowerCase().includes(filter);
      });
      
      container.innerHTML = filtered.map(t => \`
        <div class="traffic-item \${t.id === selectedId ? 'selected' : ''}" onclick="selectTraffic('\${t.id}')">
          <div class="header">
            <span class="type \${t.direction}">\${t.direction.toUpperCase()}</span>
            <span class="time">\${new Date(t.timestamp).toLocaleTimeString()}</span>
          </div>
          <div class="endpoint">\${t.endpoint}</div>
          <div class="messages">\${t.messages.map(m => m.summary || m.type).join(', ')}</div>
        </div>
      \`).join('');
    }
    
    function selectTraffic(id) {
      selectedId = id;
      renderTraffic();
      
      const entry = traffic.find(t => t.id === id);
      if (!entry) return;
      
      const panel = document.getElementById('detail-panel');
      
      panel.innerHTML = \`
        <div class="detail-section">
          <h3>Overview</h3>
          <div class="detail-content">
            <p><strong>ID:</strong> \${entry.id}</p>
            <p><strong>Direction:</strong> \${entry.direction}</p>
            <p><strong>Endpoint:</strong> \${entry.endpoint}</p>
            <p><strong>Time:</strong> \${new Date(entry.timestamp).toLocaleString()}</p>
            \${entry.method ? '<p><strong>Method:</strong> ' + entry.method + '</p>' : ''}
            \${entry.status ? '<p><strong>Status:</strong> ' + entry.status + '</p>' : ''}
          </div>
        </div>
        
        <div class="detail-section">
          <h3>Messages (\${entry.messages.length})</h3>
          <div class="detail-content">
            \${entry.messages.length === 0 ? '<p style="color: var(--text-secondary)">No parsed messages</p>' : 
              entry.messages.map(m => \`
                <div class="message-item">
                  <span class="type">\${m.type}</span>
                  <span class="summary">\${m.summary}</span>
                  \${Object.keys(m.details).length > 0 ? 
                    '<div class="details">' + JSON.stringify(m.details, null, 2) + '</div>' : ''}
                </div>
              \`).join('')
            }
          </div>
        </div>
        
        \${entry.rawData ? \`
          <div class="detail-section">
            <h3>Raw Data</h3>
            <div class="detail-content">
              <div class="hex-dump">\${entry.rawData}</div>
            </div>
          </div>
        \` : ''}
      \`;
    }
    
    function filterTraffic() {
      renderTraffic();
    }
    
    function clearTraffic() {
      traffic.length = 0;
      selectedId = null;
      renderTraffic();
      document.getElementById('detail-panel').innerHTML = \`
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          <p>Select a traffic entry to view details</p>
        </div>
      \`;
    }
    
    function exportTraffic() {
      const data = JSON.stringify(traffic, null, 2);
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cursor-traffic-' + new Date().toISOString().slice(0, 19).replace(/:/g, '-') + '.json';
      a.click();
      URL.revokeObjectURL(url);
    }
    
    connectWebSocket();
  </script>
</body>
</html>`;
}

// Track request counter
let requestCounter = 0;

// Logging utilities
function log(message: string): void {
  const timestamp = new Date().toISOString().slice(11, 23);
  console.log(`${c.dim}[${timestamp}]${c.reset} ${message}`);
}

function logSection(title: string, color: string = c.cyan): void {
  console.log(`\n${color}${"═".repeat(60)}${c.reset}`);
  console.log(`${color}${c.bright} ${title}${c.reset}`);
  console.log(`${color}${"═".repeat(60)}${c.reset}`);
}

// Broadcast to all WebSocket clients
function broadcast(message: object): void {
  const data = JSON.stringify(message);
  for (const client of wsClients) {
    try {
      client.send(data);
    } catch {
      wsClients.delete(client);
    }
  }
}

// Add traffic entry and broadcast
function addTrafficEntry(entry: TrafficEntry): void {
  trafficHistory.unshift(entry);
  if (trafficHistory.length > MAX_HISTORY) {
    trafficHistory.pop();
  }
  broadcast({ type: "traffic", entry });
  emitTraffic(entry);
}

// Analyze and create traffic entry
function createTrafficEntry(
  data: Uint8Array,
  direction: "request" | "response",
  endpoint: string,
  options: { verbose?: boolean; showRaw?: boolean }
): TrafficEntry {
  const payload = removeEnvelope(data);
  const messages: ParsedMessage[] = [];

  if (direction === "response") {
    messages.push(...parseAgentServerMessage(payload));
  } else {
    const msg = parseAgentClientMessage(payload);
    if (msg.summary) {
      messages.push(msg);
    }
  }

  const entry: TrafficEntry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    direction,
    endpoint,
    messages,
  };

  if (options.showRaw) {
    entry.rawData = hexDump(payload) as unknown as Uint8Array;
  }

  return entry;
}

/**
 * Start Web UI with proxy
 */
export async function startWebUI(options: WebUIOptions): Promise<void> {
  logSection("Cursor Traffic Sniffer - Web UI Mode", c.green);
  
  // Start WebSocket/HTTP server for UI
  const uiServer = Bun.serve({
    port: options.uiPort,
    
    fetch(req, server) {
      const url = new URL(req.url);
      
      // WebSocket upgrade
      if (url.pathname === "/ws") {
        const success = server.upgrade(req);
        if (success) return undefined;
        return new Response("WebSocket upgrade failed", { status: 500 });
      }
      
      // Serve HTML UI
      if (url.pathname === "/" || url.pathname === "/index.html") {
        return new Response(generateHTML(options.uiPort), {
          headers: { "Content-Type": "text/html" },
        });
      }
      
      // API: Get traffic history
      if (url.pathname === "/api/traffic") {
        return new Response(JSON.stringify(trafficHistory), {
          headers: { "Content-Type": "application/json" },
        });
      }
      
      return new Response("Not Found", { status: 404 });
    },
    
    websocket: {
      open(ws) {
        wsClients.add(ws as unknown as WebSocket);
        // Send history on connect
        ws.send(JSON.stringify({ type: "history", entries: trafficHistory }));
      },
      message() {
        // Handle incoming messages if needed
      },
      close(ws) {
        wsClients.delete(ws as unknown as WebSocket);
      },
    },
  });
  
  console.log(`
${c.cyan}Web UI Settings:${c.reset}
  Proxy Port: ${c.yellow}${options.port}${c.reset}
  Web UI Port: ${c.yellow}${options.uiPort}${c.reset}
  
${c.green}Web UI:${c.reset} ${c.bright}http://localhost:${options.uiPort}${c.reset}

${c.cyan}To use with Cursor:${c.reset}
  ${c.dim}export HTTP_PROXY=http://127.0.0.1:${options.port}${c.reset}
  ${c.dim}export HTTPS_PROXY=http://127.0.0.1:${options.port}${c.reset}
  ${c.dim}cursor .${c.reset}

${c.cyan}Listening for connections...${c.reset}
`);

  // Start proxy server
  const proxyServer = Bun.serve({
    port: options.port,
    
    async fetch(req) {
      const url = new URL(req.url);
      const reqId = `req-${++requestCounter}`;

      // Log incoming request
      log(`${c.green}→${c.reset} ${req.method} ${url.pathname}`);

      // Check if this is a Cursor API request
      const isCursorAPI = url.hostname.includes("cursor.sh");

      if (isCursorAPI) {
        console.log(`\n${c.green}${"═".repeat(60)}${c.reset}`);
        console.log(`${c.bright}${c.green} Request #${requestCounter}${c.reset}`);
        console.log(`${c.green}${"═".repeat(60)}${c.reset}`);
        console.log(`  ${c.cyan}Method:${c.reset} ${req.method}`);
        console.log(`  ${c.cyan}URL:${c.reset} ${url.href}`);

        // Read and analyze request body
        if (req.body) {
          const body = await req.arrayBuffer();
          const bodyBytes = new Uint8Array(body);

          if (bodyBytes.length > 0) {
            const entry = createTrafficEntry(bodyBytes, "request", url.pathname, options);
            entry.method = req.method;
            addTrafficEntry(entry);
            
            // Console output
            console.log(`\n${c.bgGreen}${c.bright} REQUEST ${c.reset} ${url.pathname}`);
            for (const msg of entry.messages) {
              console.log(`  ${c.cyan}${msg.type}:${c.reset} ${msg.summary}`);
              if (options.verbose && Object.keys(msg.details).length > 0) {
                console.log(`    ${c.dim}${JSON.stringify(msg.details)}${c.reset}`);
              }
            }
          }

          // Forward the request
          const targetUrl = url.href;
          const headers = new Headers(req.headers);

          try {
            const response = await fetch(targetUrl, {
              method: req.method,
              headers,
              body: bodyBytes,
            });

            // Handle SSE response
            if (response.headers.get("content-type")?.includes("event-stream")) {
              console.log(`\n${c.bgBlue}${c.bright} SSE STREAM ${c.reset}`);
              console.log(`  ${c.yellow}SSE stream detected - forwarding...${c.reset}`);
              
              // For SSE, we need to intercept each chunk
              // This is complex with Bun's fetch, so we forward as-is for now
              return response;
            }

            // Regular response
            const responseBody = await response.arrayBuffer();
            const responseBytes = new Uint8Array(responseBody);

            if (responseBytes.length > 0) {
              const entry = createTrafficEntry(responseBytes, "response", url.pathname, options);
              entry.status = response.status;
              addTrafficEntry(entry);
              
              // Console output
              console.log(`\n${c.bgBlue}${c.bright} RESPONSE ${c.reset} ${url.pathname}`);
              for (const msg of entry.messages) {
                const summaryColor =
                  msg.summary === "text" ? c.green :
                  msg.summary === "thinking" ? c.magenta :
                  msg.summary.includes("tool") ? c.yellow : c.cyan;
                console.log(`  ${c.cyan}${msg.type}:${c.reset} ${summaryColor}${msg.summary}${c.reset}`);
                if (options.verbose && Object.keys(msg.details).length > 0) {
                  console.log(`    ${c.dim}${JSON.stringify(msg.details)}${c.reset}`);
                }
              }
            }

            return new Response(responseBytes, {
              status: response.status,
              headers: response.headers,
            });
          } catch (err) {
            log(`${c.red}Error forwarding request: ${err}${c.reset}`);
            return new Response("Proxy Error", { status: 502 });
          }
        }
      }

      // For non-Cursor requests, just forward
      try {
        const response = await fetch(req.url, {
          method: req.method,
          headers: req.headers,
          body: req.body,
        });
        return response;
      } catch {
        return new Response("Proxy Error", { status: 502 });
      }
    },
  });

  log(`Proxy server started on port ${proxyServer.port}`);
  log(`Web UI available at http://localhost:${uiServer.port}`);

  // Keep running
  await new Promise(() => {});
}
