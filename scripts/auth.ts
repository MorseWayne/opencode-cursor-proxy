/**
 * Authentication CLI
 *
 * This script provides a real authentication workflow (OAuth PKCE) compatible
 * with Cursor CLI credential storage.
 *
 * Usage:
 *   bun scripts/auth.ts [command]
 *
 * Commands:
 *   status     - Show current authentication status
 *   check      - Check if token is valid/expiring
 *   login      - Perform real OAuth login via browser
 *   logout     - Clear stored credentials
 *   refresh    - Force token refresh (requires API key)
 *   simulate   - Run a local simulation with a mock interceptor
 *   auth-key   - Authenticate using API key (from env or arg)
 *   auth-token - Authenticate using direct token (from env or arg)
 */

import { platform, homedir } from "node:os";
import { join, dirname } from "node:path";
import { promises as fs } from "node:fs";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { exec } from "node:child_process";

// --- Configuration ---

const CURSOR_WEBSITE_URL = "https://cursor.com";
const CURSOR_API_BASE_URL = "https://api2.cursor.sh";
const POLLING_ENDPOINT = `${CURSOR_API_BASE_URL}/auth/poll`;

// --- Types ---

interface CredentialManager {
  getAccessToken(): Promise<string | undefined>;
  getRefreshToken(): Promise<string | undefined>;
  getApiKey(): Promise<string | undefined>;
  getAllCredentials(): Promise<{
    accessToken?: string;
    refreshToken?: string;
    apiKey?: string;
  }>;
  setAuthentication(
    accessToken: string,
    refreshToken: string,
    apiKey?: string
  ): Promise<void>;
  clearAuthentication(): Promise<void>;
}

interface AuthResult {
  accessToken: string;
  refreshToken: string;
}

interface AuthParams {
  uuid: string;
  challenge: string;
  verifier: string;
  loginUrl: string;
}

interface LoginMetadata {
  uuid: string;
  verifier: string;
}

// --- Helper Functions ---

/**
 * Base64 URL encode a buffer (same as cursor-config/dist/auth/login.js)
 */
function base64URLEncode(buffer: Buffer): string {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Generate a SHA-256 hash of the input string
 */
function sha256(data: string): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * Generate authentication parameters (PKCE flow)
 */
function generateAuthParams(): AuthParams {
  // Generate a 32-byte random verifier
  const verifierArray = randomBytes(32);
  const verifier = base64URLEncode(verifierArray);

  // Generate challenge by SHA-256 hashing the verifier
  const challengeHash = sha256(verifier);
  const challenge = base64URLEncode(challengeHash);

  // Generate a UUID
  const uuid = randomUUID();

  // Construct the login URL
  const loginUrl = `${CURSOR_WEBSITE_URL}/loginDeepControl?challenge=${challenge}&uuid=${uuid}&mode=login&redirectTarget=cli`;

  return {
    uuid,
    challenge,
    verifier,
    loginUrl,
  };
}

/**
 * Decode JWT payload without signature verification (for display purposes only)
 */
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

/**
 * Check if a token is expiring soon (within 5 minutes)
 */
function isTokenExpiringSoon(token: string): boolean {
  try {
    const decoded = decodeJwtPayload(token);
    if (!decoded || typeof decoded.exp !== "number") return true;

    const currentTime = Math.floor(Date.now() / 1000);
    const expirationTime = decoded.exp;
    const timeLeft = expirationTime - currentTime;

    return timeLeft < 300; // 5 minutes
  } catch {
    return true;
  }
}

/**
 * Format seconds into human-readable duration
 */
function formatDuration(seconds: number): string {
  if (seconds < 0) return "expired";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

/**
 * Mask sensitive token data for display
 */
function maskToken(token: string | undefined): string {
  if (!token) return "(not set)";
  if (token.length < 20) return "***";
  return `${token.substring(0, 10)}...${token.substring(token.length - 10)}`;
}

/**
 * Open a URL in the default browser
 */
function openBrowser(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const command =
      platform() === "darwin"
        ? `open "${url}"`
        : platform() === "win32"
          ? `start "" "${url}"`
          : `xdg-open "${url}"`;

    exec(command, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

/**
 * Sleep for a given number of milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- Credential Manager ---

/**
 * FileCredentialManager - File-based credential storage
 */
class FileCredentialManager implements CredentialManager {
  private cachedAccessToken: string | null = null;
  private cachedRefreshToken: string | null = null;
  private cachedApiKey: string | null = null;
  private authFilePath: string;

  constructor(domain: string) {
    this.authFilePath = this.getAuthFilePath(domain);
  }

  private toWindowsTitleCase(domain: string): string {
    if (domain.length === 0) return domain;
    return domain.charAt(0).toUpperCase() + domain.slice(1).toLowerCase();
  }

  private getAuthFilePath(domain: string): string {
    const currentPlatform = platform();

    switch (currentPlatform) {
      case "win32": {
        const appData =
          process.env.APPDATA || join(homedir(), "AppData", "Roaming");
        const folder = this.toWindowsTitleCase(domain);
        return join(appData, folder, "auth.json");
      }
      case "darwin":
        return join(homedir(), `.${domain}`, "auth.json");
      default: {
        const configDir =
          process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
        return join(configDir, domain, "auth.json");
      }
    }
  }

  getStoragePath(): string {
    return this.authFilePath;
  }

  private async ensureDirectoryExists(): Promise<void> {
    const dir = dirname(this.authFilePath);
    try {
      await fs.mkdir(dir, { recursive: true });
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }

  private async readAuthData(): Promise<{
    accessToken?: string;
    refreshToken?: string;
    apiKey?: string;
  } | null> {
    try {
      const data = await fs.readFile(this.authFilePath, "utf-8");
      return JSON.parse(data);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      return null;
    }
  }

  private async writeAuthData(data: {
    accessToken: string;
    refreshToken: string;
    apiKey?: string;
  }): Promise<void> {
    await this.ensureDirectoryExists();
    await fs.writeFile(
      this.authFilePath,
      JSON.stringify(data, null, 2),
      "utf-8"
    );
  }

  async setAuthentication(
    accessToken: string,
    refreshToken: string,
    apiKey?: string
  ): Promise<void> {
    await this.writeAuthData({ accessToken, refreshToken, apiKey });
    this.cachedAccessToken = accessToken;
    this.cachedRefreshToken = refreshToken;
    this.cachedApiKey = apiKey ?? null;
  }

  async getAccessToken(): Promise<string | undefined> {
    if (this.cachedAccessToken) return this.cachedAccessToken;
    const authData = await this.readAuthData();
    if (authData?.accessToken) {
      this.cachedAccessToken = authData.accessToken;
      this.cachedRefreshToken = authData.refreshToken ?? null;
      return authData.accessToken;
    }
    return undefined;
  }

  async getRefreshToken(): Promise<string | undefined> {
    if (this.cachedRefreshToken) return this.cachedRefreshToken;
    const authData = await this.readAuthData();
    if (authData?.refreshToken) {
      this.cachedAccessToken = authData.accessToken ?? null;
      this.cachedRefreshToken = authData.refreshToken;
      return authData.refreshToken;
    }
    return undefined;
  }

  async getApiKey(): Promise<string | undefined> {
    if (this.cachedApiKey) return this.cachedApiKey;
    const authData = await this.readAuthData();
    if (authData?.apiKey) {
      this.cachedApiKey = authData.apiKey;
      return authData.apiKey;
    }
    return undefined;
  }

  async getAllCredentials(): Promise<{
    accessToken?: string;
    refreshToken?: string;
    apiKey?: string;
  }> {
    if (this.cachedAccessToken !== null && this.cachedRefreshToken !== null) {
      return {
        accessToken: this.cachedAccessToken || undefined,
        refreshToken: this.cachedRefreshToken || undefined,
        apiKey: this.cachedApiKey || undefined,
      };
    }
    const authData = await this.readAuthData();
    if (authData) {
      this.cachedAccessToken = authData.accessToken || null;
      this.cachedRefreshToken = authData.refreshToken || null;
      this.cachedApiKey = authData.apiKey || null;
      return authData;
    }
    return {};
  }

  async clearAuthentication(): Promise<void> {
    try {
      await fs.unlink(this.authFilePath);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    this.cachedAccessToken = null;
    this.cachedRefreshToken = null;
    this.cachedApiKey = null;
  }
}

/**
 * Create appropriate credential manager for the current platform
 */
function createCredentialManager(domain: string): FileCredentialManager {
  console.log(`[CredentialManager] Platform: ${platform()}`);
  console.log(`[CredentialManager] Domain: ${domain}`);
  return new FileCredentialManager(domain);
}

// --- LoginManager (from cursor-config/dist/auth/login.js) ---

class LoginManager {
  /**
   * Start the OAuth login flow
   * Returns metadata needed for polling and the URL to open in browser
   */
  startLogin(): { metadata: LoginMetadata; loginUrl: string } {
    const authParams = generateAuthParams();
    return {
      metadata: {
        uuid: authParams.uuid,
        verifier: authParams.verifier,
      },
      loginUrl: authParams.loginUrl,
    };
  }

  /**
   * Poll for authentication result
   * This waits for the user to complete the browser login
   */
  async waitForResult(metadata: LoginMetadata): Promise<AuthResult | null> {
    const maxAttempts = 150; // Maximum number of attempts
    const baseDelay = 1000; // 1 second base delay
    const maxDelay = 10000; // 10 seconds maximum delay
    const backoffMultiplier = 1.2; // Gentle exponential backoff
    const maxConsecutiveErrors = 3;

    let consecutiveErrors = 0;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const url = `${POLLING_ENDPOINT}?uuid=${metadata.uuid}&verifier=${metadata.verifier}`;
        const response = await fetch(url, {
          headers: {
            "Content-Type": "application/json",
          },
        });

        // 404 means authentication is still pending
        if (response.status === 404) {
          consecutiveErrors = 0;
          const delay = Math.min(
            baseDelay * Math.pow(backoffMultiplier, attempt),
            maxDelay
          );
          process.stdout.write(".");
          await sleep(delay);
          continue;
        }

        // Check for other error statuses
        if (!response.ok) {
          consecutiveErrors++;
          if (consecutiveErrors >= maxConsecutiveErrors) {
            console.log("\nToo many errors, stopping.");
            return null;
          }
          const delay = Math.min(
            baseDelay * Math.pow(backoffMultiplier, attempt),
            maxDelay
          );
          await sleep(delay);
          continue;
        }

        // Success case
        consecutiveErrors = 0;
        const authResult = await response.json();

        if (
          typeof authResult === "object" &&
          authResult !== null &&
          "accessToken" in authResult &&
          "refreshToken" in authResult
        ) {
          console.log("\n");
          return authResult as AuthResult;
        }

        return null;
      } catch {
        consecutiveErrors++;
        if (consecutiveErrors >= maxConsecutiveErrors) {
          console.log("\nNetwork error, stopping.");
          return null;
        }
        const delay = Math.min(
          baseDelay * Math.pow(backoffMultiplier, attempt),
          maxDelay
        );
        await sleep(delay);
      }
    }

    console.log("\nTimeout waiting for authentication.");
    return null;
  }

  /**
   * Exchange API key for access/refresh tokens
   */
  async loginWithApiKey(
    apiKey: string,
    options?: { endpoint?: string }
  ): Promise<AuthResult | null> {
    const baseUrl = options?.endpoint ?? CURSOR_API_BASE_URL;

    try {
      const response = await fetch(`${baseUrl}/auth/exchange_user_api_key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({}),
      });

      if (!response.ok) {
        console.log(`API key exchange failed: ${response.status}`);
        return null;
      }

      const authResult = await response.json();

      if (
        typeof authResult === "object" &&
        authResult !== null &&
        "accessToken" in authResult &&
        "refreshToken" in authResult
      ) {
        return authResult as AuthResult;
      }
    } catch (error) {
      console.log(`API key exchange error: ${error}`);
    }

    return null;
  }
}

// --- Auth Refresh Logic ---

async function getValidAccessToken(
  credentialManager: CredentialManager,
  endpoint: string
): Promise<string | null> {
  const currentToken = await credentialManager.getAccessToken();
  if (!currentToken) {
    return null;
  }

  if (!isTokenExpiringSoon(currentToken)) {
    return currentToken;
  }

  // Token is expiring soon, try to refresh with API key
  const apiKey = await credentialManager.getApiKey();
  if (apiKey) {
    console.log(
      "[Auth] Token expiring soon, attempting refresh with API key..."
    );
    const loginManager = new LoginManager();
    const result = await loginManager.loginWithApiKey(apiKey, { endpoint });
    if (result) {
      await credentialManager.setAuthentication(
        result.accessToken,
        result.refreshToken,
        apiKey
      );
      console.log("[Auth] Token refreshed successfully.");
      return result.accessToken;
    }
  }

  return currentToken;
}

// --- Interceptor Logic ---

type Request = { headers: Map<string, string>; url: string };
type NextFn = (req: Request) => Promise<unknown>;

function createAuthInterceptor(
  credentialManager: CredentialManager,
  opts: { baseUrl: string }
) {
  return (next: NextFn) => async (req: Request) => {
    const token = await getValidAccessToken(credentialManager, opts.baseUrl);

    if (token !== undefined && token !== null) {
      req.headers.set("authorization", `Bearer ${token}`);
    }

    // Set additional headers like the real implementation
    req.headers.set("x-ghost-mode", "true"); // Default to privacy mode
    req.headers.set("x-cursor-client-version", "cli-demo");
    req.headers.set("x-cursor-client-type", "cli");

    if (!req.headers.get("x-request-id")) {
      req.headers.set("x-request-id", randomUUID());
    }

    return next(req);
  };
}

// --- Demo Commands ---

async function showStatus(credentialManager: FileCredentialManager) {
  console.log("\n=== Authentication Status ===\n");

  console.log(`Storage: ${credentialManager.getStoragePath()}`);

  const creds = await credentialManager.getAllCredentials();

  console.log("\nStored Credentials:");
  console.log(`  Access Token:  ${maskToken(creds.accessToken)}`);
  console.log(`  Refresh Token: ${maskToken(creds.refreshToken)}`);
  console.log(`  API Key:       ${maskToken(creds.apiKey)}`);

  if (creds.accessToken) {
    const payload = decodeJwtPayload(creds.accessToken);
    if (payload) {
      console.log("\nAccess Token Details:");
      console.log(`  Subject (sub): ${payload.sub || "(not set)"}`);

      if (typeof payload.exp === "number") {
        const now = Math.floor(Date.now() / 1000);
        const timeLeft = payload.exp - now;
        const expDate = new Date(payload.exp * 1000);
        console.log(`  Expires:       ${expDate.toISOString()}`);
        console.log(
          `  Time Left:     ${formatDuration(timeLeft)}${timeLeft < 300 ? " (expiring soon!)" : ""}`
        );
      }

      if (typeof payload.iat === "number") {
        const iatDate = new Date(payload.iat * 1000);
        console.log(`  Issued At:     ${iatDate.toISOString()}`);
      }
    }
  }

  console.log("\nEnvironment Variables:");
  console.log(
    `  CURSOR_API_KEY:    ${process.env.CURSOR_API_KEY ? "(set)" : "(not set)"}`
  );
  console.log(
    `  CURSOR_AUTH_TOKEN: ${process.env.CURSOR_AUTH_TOKEN ? "(set)" : "(not set)"}`
  );
  console.log(
    `  CURSOR_API_ENDPOINT: ${process.env.CURSOR_API_ENDPOINT || "(not set, using default)"}`
  );
}

async function checkToken(credentialManager: CredentialManager) {
  console.log("\n=== Token Validation ===\n");

  const token = await credentialManager.getAccessToken();

  if (!token) {
    console.log("No access token stored.");
    return;
  }

  const payload = decodeJwtPayload(token);
  if (!payload) {
    console.log("Failed to decode token payload.");
    return;
  }

  const isExpiring = isTokenExpiringSoon(token);
  const now = Math.floor(Date.now() / 1000);
  const exp = typeof payload.exp === "number" ? payload.exp : 0;
  const timeLeft = exp - now;

  if (timeLeft < 0) {
    console.log(
      `Token Status: EXPIRED (${formatDuration(Math.abs(timeLeft))} ago)`
    );
  } else if (isExpiring) {
    console.log(
      `Token Status: EXPIRING SOON (${formatDuration(timeLeft)} remaining)`
    );
    console.log("  -> Token refresh would be triggered on next request");
  } else {
    console.log(`Token Status: VALID (${formatDuration(timeLeft)} remaining)`);
  }
}

async function performLogin(credentialManager: CredentialManager) {
  console.log("\n=== OAuth Login ===\n");

  const loginManager = new LoginManager();
  const { metadata, loginUrl } = loginManager.startLogin();

  console.log("Opening browser for authentication...");
  console.log(`\nIf your browser doesn't open, visit this URL:\n${loginUrl}\n`);

  try {
    await openBrowser(loginUrl);
  } catch {
    console.log("(Could not open browser automatically)");
  }

  console.log("Waiting for authentication");
  const authResult = await loginManager.waitForResult(metadata);

  if (authResult) {
    await credentialManager.setAuthentication(
      authResult.accessToken,
      authResult.refreshToken
    );

    const payload = decodeJwtPayload(authResult.accessToken);
    console.log("Login successful!");
    console.log(`  Auth ID: ${payload?.sub || "(unknown)"}`);
    console.log(`  Token stored securely.`);
  } else {
    console.log("Login failed or was cancelled.");
    process.exit(1);
  }
}

async function runSimulation(credentialManager: CredentialManager) {
  console.log("\n=== Authentication Flow Simulation ===\n");

  // 1. Check current state
  console.log("1. Checking current credentials...");
  const creds = await credentialManager.getAllCredentials();

  if (!creds.accessToken) {
    console.log("   No credentials found. Creating demo token...");

    // Create a demo token that expires in 10 minutes
    const now = Math.floor(Date.now() / 1000);
    const demoPayload = {
      sub: "demo-auth-id-12345",
      exp: now + 600, // 10 minutes
      iat: now,
    };
    const demoToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from(JSON.stringify(demoPayload)).toString("base64url")}.demo-signature`;

    await credentialManager.setAuthentication(
      demoToken,
      "demo-refresh-token",
      "demo-api-key"
    );
    console.log("   Demo credentials created.");
  } else {
    console.log("   Found existing credentials.");
  }

  // 2. Create interceptor
  console.log("\n2. Creating auth interceptor...");
  const authInterceptor = createAuthInterceptor(credentialManager, {
    baseUrl: "https://api2.cursor.sh",
  });

  // 3. Mock request
  console.log("\n3. Simulating API request...");
  const mockRequest: Request = {
    headers: new Map(),
    url: "https://api2.cursor.sh/v1/test",
  };

  const mockNext: NextFn = async (req) => {
    console.log(`\n   [Network] Request to: ${req.url}`);
    console.log("   [Network] Headers:");
    req.headers.forEach((value, key) => {
      if (key === "authorization") {
        console.log(
          `     ${key}: Bearer ${maskToken(value.replace("Bearer ", ""))}`
        );
      } else {
        console.log(`     ${key}: ${value}`);
      }
    });
    return { status: 200, body: "OK" };
  };

  const interceptorChain = authInterceptor(mockNext);
  await interceptorChain(mockRequest);

  // 4. Final status
  console.log("\n4. Final status:");
  const finalToken = await credentialManager.getAccessToken();
  if (finalToken) {
    const isExpiring = isTokenExpiringSoon(finalToken);
    console.log(`   Token valid: ${!isExpiring ? "Yes" : "No (expiring soon)"}`);
  }

  console.log("\n Demo complete.");
}

async function clearCredentials(credentialManager: CredentialManager) {
  console.log("\n=== Clearing Credentials ===\n");

  await credentialManager.clearAuthentication();
  console.log("All stored credentials have been cleared.");
}

async function authenticateWithApiKey(
  credentialManager: CredentialManager,
  apiKey?: string
) {
  console.log("\n=== API Key Authentication ===\n");

  const key = apiKey ?? process.env.CURSOR_API_KEY;
  const fromEnv = !apiKey && !!process.env.CURSOR_API_KEY;

  if (!key) {
    console.log("No API key provided.");
    console.log("Set CURSOR_API_KEY environment variable or pass as argument:");
    console.log("  bun scripts/auth.ts auth-key <your-api-key>");
    return;
  }

  console.log(
    `Using API key${fromEnv ? " (from CURSOR_API_KEY env)" : ""}...`
  );

  const loginManager = new LoginManager();
  const result = await loginManager.loginWithApiKey(key);

  if (result) {
    await credentialManager.setAuthentication(
      result.accessToken,
      result.refreshToken,
      key
    );

    const payload = decodeJwtPayload(result.accessToken);
    console.log("\nAuthentication successful!");
    console.log(`  Auth ID: ${payload?.sub || "(unknown)"}`);
  } else {
    console.log("\nAuthentication failed. Check your API key.");
    process.exit(1);
  }
}

async function authenticateWithToken(
  credentialManager: CredentialManager,
  authToken?: string
) {
  console.log("\n=== Direct Token Authentication ===\n");

  const token = authToken ?? process.env.CURSOR_AUTH_TOKEN;
  const fromEnv = !authToken && !!process.env.CURSOR_AUTH_TOKEN;

  if (!token) {
    console.log("No auth token provided.");
    console.log(
      "Set CURSOR_AUTH_TOKEN environment variable or pass as argument:"
    );
    console.log("  bun scripts/auth.ts auth-token <your-token>");
    return;
  }

  console.log(
    `Using direct token${fromEnv ? " (from CURSOR_AUTH_TOKEN env)" : ""}...`
  );

  // Validate token format
  const payload = decodeJwtPayload(token);
  if (!payload) {
    console.log("\nWarning: Token does not appear to be a valid JWT.");
  }

  // Set the token directly (bypasses login flow)
  await credentialManager.setAuthentication(token, token);

  console.log("\nToken stored successfully!");
  if (payload) {
    console.log(`  Auth ID: ${payload.sub || "(unknown)"}`);
    if (typeof payload.exp === "number") {
      const now = Math.floor(Date.now() / 1000);
      const timeLeft = payload.exp - now;
      console.log(`  Expires in: ${formatDuration(timeLeft)}`);
    }
  }
}

// --- Main Entry Point ---

async function main() {
  const command = process.argv[2] || "help";
  const arg = process.argv[3];

  // Use "cursor" domain to use the same credentials as real Cursor CLI
  // Use "cursor-demo" for isolated testing
  const domain = process.env.CURSOR_AUTH_DOMAIN || "cursor";

  console.log("Cursor CLI Authentication");
  console.log("=========================");

  const credentialManager = createCredentialManager(domain);

  switch (command) {
    case "status":
      await showStatus(credentialManager);
      break;

    case "check":
      await checkToken(credentialManager);
      break;

    case "login":
      await performLogin(credentialManager);
      break;

    case "logout":
    case "clear":
      await clearCredentials(credentialManager);
      break;

    case "refresh": {
      console.log("\n=== Token Refresh ===\n");
      const token = await getValidAccessToken(
        credentialManager,
        CURSOR_API_BASE_URL
      );
      if (token) {
        console.log("Token retrieved (refresh attempted if needed).");
      } else {
        console.log("No token available.");
      }
      break;
    }

    case "simulate":
      await runSimulation(credentialManager);
      break;

    case "auth-key":
      await authenticateWithApiKey(credentialManager, arg);
      break;

    case "auth-token":
      await authenticateWithToken(credentialManager, arg);
      break;

    case "help":
    default:
      if (command !== "help") {
        console.log(`\nUnknown command: ${command}`);
      }
      console.log("\nAvailable commands:");
      console.log("  status     - Show current authentication status");
      console.log("  check      - Check if token is valid/expiring");
      console.log("  login      - Perform real OAuth login via browser");
      console.log("  logout     - Clear stored credentials");
      console.log("  refresh    - Force token refresh (requires API key)");
      console.log("  simulate   - Run a local simulation with a mock interceptor");
      console.log("  auth-key   - Authenticate using API key");
      console.log("  auth-token - Authenticate using direct token");
      console.log("\nEnvironment variables:");
      console.log("  CURSOR_API_KEY      - API key for authentication");
      console.log("  CURSOR_AUTH_TOKEN   - Direct JWT token");
      console.log(
        "  CURSOR_AUTH_DOMAIN  - Storage domain (default: cursor)"
      );
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
