/**
 * TLS Interception Proxy for cursor-sniffer
 * 
 * Provides HTTPS MITM capability by:
 * 1. Auto-generating CA certificate on first run
 * 2. Dynamically generating certificates for each host
 * 3. Intercepting and analyzing encrypted traffic
 */

import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import * as net from "net";
import * as tls from "tls";
import { colors } from "./types";
import {
  analyzeProtoFields,
  parseAgentClientMessage,
  parseAgentServerMessage,
  removeEnvelope,
  hexDump,
  emitTraffic,
} from "./analyzer";

const c = colors;

interface TlsProxyOptions {
  port: number;
  verbose?: boolean;
  showRaw?: boolean;
}

// CA certificate paths
const CA_DIR = path.join(os.homedir(), ".cursor-sniffer");
const CA_KEY_PATH = path.join(CA_DIR, "ca.key");
const CA_CERT_PATH = path.join(CA_DIR, "ca.crt");

// Cache for generated certificates
const certCache = new Map<string, { key: string; cert: string }>();

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

/**
 * Ensure CA certificate exists, generate if not
 */
async function ensureCACertificate(): Promise<{ key: string; cert: string }> {
  // Create directory if needed
  if (!fs.existsSync(CA_DIR)) {
    fs.mkdirSync(CA_DIR, { recursive: true });
  }

  // Check if CA already exists
  if (fs.existsSync(CA_KEY_PATH) && fs.existsSync(CA_CERT_PATH)) {
    log(`${c.green}Using existing CA certificate${c.reset}`);
    return {
      key: fs.readFileSync(CA_KEY_PATH, "utf8"),
      cert: fs.readFileSync(CA_CERT_PATH, "utf8"),
    };
  }

  log(`${c.yellow}Generating new CA certificate...${c.reset}`);

  // Generate CA using openssl
  const { spawn } = await import("child_process");

  // Generate private key
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("openssl", [
      "genrsa",
      "-out", CA_KEY_PATH,
      "2048"
    ]);
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`openssl genrsa failed with code ${code}`));
    });
    proc.on("error", reject);
  });

  // Generate CA certificate
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("openssl", [
      "req",
      "-new",
      "-x509",
      "-days", "3650",
      "-key", CA_KEY_PATH,
      "-out", CA_CERT_PATH,
      "-subj", "/CN=Cursor Sniffer CA/O=cursor-sniffer/C=US"
    ]);
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`openssl req failed with code ${code}`));
    });
    proc.on("error", reject);
  });

  log(`${c.green}CA certificate generated successfully${c.reset}`);
  log(`${c.cyan}CA certificate path:${c.reset} ${CA_CERT_PATH}`);

  return {
    key: fs.readFileSync(CA_KEY_PATH, "utf8"),
    cert: fs.readFileSync(CA_CERT_PATH, "utf8"),
  };
}

/**
 * Generate certificate for a specific host
 */
async function generateHostCertificate(
  host: string,
  ca: { key: string; cert: string }
): Promise<{ key: string; cert: string }> {
  // Check cache
  const cached = certCache.get(host);
  if (cached) return cached;

  const hostKeyPath = path.join(CA_DIR, `${host}.key`);
  const hostCertPath = path.join(CA_DIR, `${host}.crt`);
  const hostCsrPath = path.join(CA_DIR, `${host}.csr`);

  const { spawn } = await import("child_process");

  // Generate host key
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("openssl", [
      "genrsa",
      "-out", hostKeyPath,
      "2048"
    ]);
    proc.on("close", (code) => code === 0 ? resolve() : reject());
    proc.on("error", reject);
  });

  // Generate CSR
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("openssl", [
      "req",
      "-new",
      "-key", hostKeyPath,
      "-out", hostCsrPath,
      "-subj", `/CN=${host}`
    ]);
    proc.on("close", (code) => code === 0 ? resolve() : reject());
    proc.on("error", reject);
  });

  // Create extension file for SAN
  const extPath = path.join(CA_DIR, `${host}.ext`);
  fs.writeFileSync(extPath, `
subjectAltName = DNS:${host}, DNS:*.${host}
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
`);

  // Sign with CA
  await new Promise<void>((resolve, reject) => {
    const proc = spawn("openssl", [
      "x509",
      "-req",
      "-in", hostCsrPath,
      "-CA", CA_CERT_PATH,
      "-CAkey", CA_KEY_PATH,
      "-CAcreateserial",
      "-out", hostCertPath,
      "-days", "365",
      "-extfile", extPath
    ]);
    proc.on("close", (code) => code === 0 ? resolve() : reject());
    proc.on("error", reject);
  });

  // Cleanup temp files
  try {
    fs.unlinkSync(hostCsrPath);
    fs.unlinkSync(extPath);
  } catch {
    // Ignore cleanup errors
  }

  const result = {
    key: fs.readFileSync(hostKeyPath, "utf8"),
    cert: fs.readFileSync(hostCertPath, "utf8"),
  };

  certCache.set(host, result);
  return result;
}

/**
 * Parse HTTP request from buffer
 */
function parseHttpRequest(data: Buffer): {
  method: string;
  url: string;
  host: string;
  headers: Record<string, string>;
  body: Buffer | null;
} | null {
  try {
    const str = data.toString();
    const headerEnd = str.indexOf("\r\n\r\n");
    if (headerEnd === -1) return null;

    const headerPart = str.slice(0, headerEnd);
    const lines = headerPart.split("\r\n");
    const [method, url] = lines[0]!.split(" ");

    const headers: Record<string, string> = {};
    for (let i = 1; i < lines.length; i++) {
      const colonIdx = lines[i]!.indexOf(":");
      if (colonIdx > 0) {
        const key = lines[i]!.slice(0, colonIdx).toLowerCase();
        const value = lines[i]!.slice(colonIdx + 1).trim();
        headers[key] = value;
      }
    }

    const body = headerEnd + 4 < data.length ? data.slice(headerEnd + 4) : null;

    return {
      method: method || "",
      url: url || "",
      host: headers.host || "",
      headers,
      body,
    };
  } catch {
    return null;
  }
}

/**
 * Analyze and log traffic
 */
function analyzeTraffic(
  data: Buffer,
  direction: "request" | "response",
  endpoint: string,
  options: { verbose?: boolean; showRaw?: boolean }
): void {
  if (data.length < 5) return;

  const payload = removeEnvelope(data);

  if (direction === "request") {
    console.log(`\n${c.bgGreen}${c.bright} REQUEST ${c.reset} ${endpoint}`);

    if (endpoint.includes("BidiAppend") || endpoint.includes("AgentService")) {
      const msg = parseAgentClientMessage(payload);
      console.log(`  ${c.cyan}Type:${c.reset} ${msg.summary || "Unknown"}`);
      if (options.verbose && Object.keys(msg.details).length > 0) {
        console.log(`  ${c.cyan}Details:${c.reset}`, JSON.stringify(msg.details, null, 2));
      }
    } else {
      console.log(analyzeProtoFields(payload, 1, options.showRaw));
    }
  } else {
    console.log(`\n${c.bgBlue}${c.bright} RESPONSE ${c.reset} ${endpoint}`);

    const messages = parseAgentServerMessage(payload);
    for (const msg of messages) {
      const summaryColor =
        msg.summary === "text" ? c.green :
        msg.summary === "thinking" ? c.magenta :
        msg.summary.includes("tool") ? c.yellow : c.cyan;

      console.log(`  ${c.cyan}${msg.type}:${c.reset} ${summaryColor}${msg.summary}${c.reset}`);
      if (options.verbose && Object.keys(msg.details).length > 0) {
        console.log(`    ${c.dim}${JSON.stringify(msg.details)}${c.reset}`);
      }
    }

    if (messages.length === 0) {
      console.log(analyzeProtoFields(payload, 1, options.showRaw));
    }
  }

  if (options.showRaw) {
    console.log(`\n${c.dim}Raw hex:${c.reset}`);
    console.log(hexDump(payload));
  }
}

/**
 * Handle HTTPS tunnel connection
 */
async function handleTunnel(
  clientSocket: net.Socket,
  host: string,
  port: number,
  ca: { key: string; cert: string },
  options: TlsProxyOptions
): Promise<void> {
  try {
    // Generate certificate for this host
    const hostCert = await generateHostCertificate(host, ca);

    // Send 200 Connection Established
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

    // Create TLS server socket
    const tlsOptions = {
      key: hostCert.key,
      cert: hostCert.cert,
      isServer: true,
    };

    const tlsSocket = new tls.TLSSocket(clientSocket, tlsOptions);

    // Collect data and forward to real server
    let requestData = Buffer.alloc(0);

    tlsSocket.on("data", async (chunk: Buffer) => {
      requestData = Buffer.concat([requestData, chunk]);

      // Parse HTTP request
      const request = parseHttpRequest(requestData);
      if (!request) return;

      // Log if Cursor API
      const isCursorAPI = host.includes("cursor.sh");
      if (isCursorAPI) {
        logSection(`Request to ${host}`, c.green);
        console.log(`  ${c.cyan}Method:${c.reset} ${request.method}`);
        console.log(`  ${c.cyan}URL:${c.reset} ${request.url}`);

        if (request.body && request.body.length > 0) {
          analyzeTraffic(request.body, "request", request.url, options);
        }
      }

      // Forward to real server
      const realSocket = tls.connect({
        host,
        port,
        servername: host,
      });

      realSocket.on("secureConnect", () => {
        realSocket.write(requestData);
      });

      let responseData = Buffer.alloc(0);
      realSocket.on("data", (respChunk: Buffer) => {
        responseData = Buffer.concat([responseData, respChunk]);
        tlsSocket.write(respChunk);
      });

      realSocket.on("end", () => {
        if (isCursorAPI && responseData.length > 0) {
          // Extract body from response
          const respStr = responseData.toString();
          const bodyStart = respStr.indexOf("\r\n\r\n");
          if (bodyStart > 0) {
            const body = responseData.slice(bodyStart + 4);
            if (body.length > 0) {
              analyzeTraffic(body, "response", request.url, options);
            }
          }
        }
        tlsSocket.end();
      });

      realSocket.on("error", (err) => {
        log(`${c.red}Real server error: ${err.message}${c.reset}`);
        tlsSocket.end();
      });

      // Reset for next request
      requestData = Buffer.alloc(0);
    });

    tlsSocket.on("error", (err) => {
      log(`${c.red}TLS socket error: ${err.message}${c.reset}`);
    });

  } catch (err) {
    log(`${c.red}Tunnel error: ${err}${c.reset}`);
    clientSocket.end();
  }
}

/**
 * Start TLS interception proxy
 */
export async function startTlsProxy(options: TlsProxyOptions): Promise<void> {
  // Ensure CA certificate exists
  let ca: { key: string; cert: string };
  try {
    ca = await ensureCACertificate();
  } catch (err) {
    console.error(`${c.red}Failed to create CA certificate: ${err}${c.reset}`);
    console.log(`${c.yellow}Make sure openssl is installed and available in PATH${c.reset}`);
    process.exit(1);
  }

  logSection("Cursor Traffic Sniffer - TLS Mode", c.green);
  console.log(`
${c.cyan}Proxy Settings:${c.reset}
  Port: ${c.yellow}${options.port}${c.reset}
  TLS Interception: ${c.green}enabled${c.reset}
  Verbose: ${c.yellow}${options.verbose}${c.reset}

${c.cyan}CA Certificate:${c.reset}
  ${c.dim}${CA_CERT_PATH}${c.reset}

${c.cyan}To use with Cursor:${c.reset}
  ${c.dim}export HTTP_PROXY=http://127.0.0.1:${options.port}${c.reset}
  ${c.dim}export HTTPS_PROXY=http://127.0.0.1:${options.port}${c.reset}
  ${c.dim}export NODE_EXTRA_CA_CERTS=${CA_CERT_PATH}${c.reset}
  ${c.dim}cursor .${c.reset}

${c.yellow}First time setup:${c.reset}
  Install the CA certificate to your system's trust store:

  ${c.dim}# Linux${c.reset}
  ${c.dim}sudo cp ${CA_CERT_PATH} /usr/local/share/ca-certificates/cursor-sniffer.crt${c.reset}
  ${c.dim}sudo update-ca-certificates${c.reset}

  ${c.dim}# macOS${c.reset}
  ${c.dim}sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ${CA_CERT_PATH}${c.reset}

${c.cyan}Listening for connections...${c.reset}
`);

  // Create proxy server
  const server = net.createServer((clientSocket) => {
    let requestData = Buffer.alloc(0);

    clientSocket.on("data", async (chunk) => {
      requestData = Buffer.concat([requestData, chunk]);

      // Check for CONNECT method (HTTPS tunnel request)
      const str = requestData.toString();
      if (str.startsWith("CONNECT ")) {
        const match = str.match(/CONNECT ([^:]+):(\d+)/);
        if (match) {
          const [, host, portStr] = match;
          const port = parseInt(portStr!, 10);
          log(`${c.cyan}CONNECT${c.reset} ${host}:${port}`);
          await handleTunnel(clientSocket, host!, port, ca, options);
          return;
        }
      }

      // Regular HTTP request (forward as-is)
      const request = parseHttpRequest(requestData);
      if (request && request.host) {
        try {
          const url = new URL(request.url.startsWith("http") ? request.url : `http://${request.host}${request.url}`);
          
          // Forward request
          const resp = await fetch(url.href, {
            method: request.method,
            headers: request.headers,
            body: request.body || undefined,
          });

          // Send response
          let response = `HTTP/1.1 ${resp.status} ${resp.statusText}\r\n`;
          resp.headers.forEach((value, key) => {
            response += `${key}: ${value}\r\n`;
          });
          response += "\r\n";

          clientSocket.write(response);

          const body = await resp.arrayBuffer();
          if (body.byteLength > 0) {
            clientSocket.write(Buffer.from(body));
          }
          clientSocket.end();
        } catch (err) {
          clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
          clientSocket.end();
        }
      }
    });

    clientSocket.on("error", () => {
      // Ignore client errors
    });
  });

  server.listen(options.port, () => {
    log(`TLS proxy server started on port ${options.port}`);
  });

  // Keep running
  await new Promise(() => {});
}
