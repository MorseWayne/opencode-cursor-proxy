/**
 * Shared types for cursor-sniffer modules
 */

export interface CapturedRequest {
  id: string;
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: Uint8Array | null;
  timestamp: number;
}

export interface CapturedResponse {
  requestId: string;
  status: number;
  headers: Record<string, string>;
  chunks: Uint8Array[];
  timestamp: number;
}

export interface ParsedMessage {
  type: string;
  summary: string;
  details: Record<string, unknown>;
}

export interface TrafficEntry {
  id: string;
  timestamp: number;
  direction: "request" | "response";
  endpoint: string;
  method?: string;
  status?: number;
  messages: ParsedMessage[];
  rawData?: Uint8Array;
}

export interface SnifferOptions {
  port: number;
  verbose: boolean;
  showRaw: boolean;
  outputFile?: string;
  withCursor?: boolean;
  enableTls?: boolean;
  enableUi?: boolean;
  uiPort?: number;
}

export const DEFAULT_OPTIONS: SnifferOptions = {
  port: 8888,
  verbose: false,
  showRaw: false,
  uiPort: 8889,
};

// ANSI color codes
export const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgBlue: "\x1b[44m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgRed: "\x1b[41m",
};
