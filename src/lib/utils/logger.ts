/**
 * Structured Logger Module
 *
 * Provides consistent logging across the application with:
 * - Log levels (error, warn, info, debug)
 * - Structured metadata
 * - Optional JSON output
 * - Child loggers with context
 */

import { config, getLogLevel } from "../config";

// --- Types ---

export type LogLevel = "error" | "warn" | "info" | "debug";

export interface LogMeta {
  [key: string]: unknown;
}

export interface Logger {
  error(message: string, meta?: LogMeta): void;
  warn(message: string, meta?: LogMeta): void;
  info(message: string, meta?: LogMeta): void;
  debug(message: string, meta?: LogMeta): void;
  child(bindings: LogMeta): Logger;
  timing(label: string, durationMs: number, meta?: LogMeta): void;
}

// --- Log Level Priority ---

const LOG_LEVELS: Record<LogLevel, number> = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

// --- Formatters ---

function formatTimestamp(): string {
  return new Date().toISOString();
}

function formatMessage(
  level: LogLevel,
  message: string,
  meta: LogMeta,
  bindings: LogMeta
): string {
  const timestamp = formatTimestamp();
  const prefix = `[${timestamp}] [${level.toUpperCase().padEnd(5)}]`;

  const combinedMeta = { ...bindings, ...meta };
  const hasMetaKeys = Object.keys(combinedMeta).length > 0;

  if (hasMetaKeys) {
    const metaStr = Object.entries(combinedMeta)
      .map(([k, v]) => {
        if (typeof v === "object") {
          try {
            return `${k}=${JSON.stringify(v)}`;
          } catch {
            return `${k}=[Object]`;
          }
        }
        return `${k}=${v}`;
      })
      .join(" ");
    return `${prefix} ${message} ${metaStr}`;
  }

  return `${prefix} ${message}`;
}

function formatJson(
  level: LogLevel,
  message: string,
  meta: LogMeta,
  bindings: LogMeta
): string {
  return JSON.stringify({
    timestamp: formatTimestamp(),
    level,
    message,
    ...bindings,
    ...meta,
  });
}

// --- Logger Implementation ---

class LoggerImpl implements Logger {
  private bindings: LogMeta;
  private minLevel: number;
  private useJson: boolean;

  constructor(bindings: LogMeta = {}, options?: { minLevel?: LogLevel; useJson?: boolean }) {
    this.bindings = bindings;
    this.minLevel = LOG_LEVELS[options?.minLevel ?? getLogLevel()];
    this.useJson = options?.useJson ?? (process.env.CURSOR_LOG_JSON === "1");
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] <= this.minLevel;
  }

  private log(level: LogLevel, message: string, meta: LogMeta = {}): void {
    if (!this.shouldLog(level)) return;

    const output = this.useJson
      ? formatJson(level, message, meta, this.bindings)
      : formatMessage(level, message, meta, this.bindings);

    switch (level) {
      case "error":
        console.error(output);
        break;
      case "warn":
        console.warn(output);
        break;
      default:
        console.log(output);
    }
  }

  error(message: string, meta?: LogMeta): void {
    this.log("error", message, meta);
  }

  warn(message: string, meta?: LogMeta): void {
    this.log("warn", message, meta);
  }

  info(message: string, meta?: LogMeta): void {
    this.log("info", message, meta);
  }

  debug(message: string, meta?: LogMeta): void {
    this.log("debug", message, meta);
  }

  timing(label: string, durationMs: number, meta?: LogMeta): void {
    if (!config.debug.timing && !config.debug.enabled) return;
    this.log("info", `[TIMING] ${label}: ${durationMs}ms`, meta);
  }

  child(bindings: LogMeta): Logger {
    return new LoggerImpl(
      { ...this.bindings, ...bindings },
      { minLevel: Object.entries(LOG_LEVELS).find(([, v]) => v === this.minLevel)?.[0] as LogLevel, useJson: this.useJson }
    );
  }
}

// --- Factory Functions ---

/**
 * Create a new logger instance
 */
export function createLogger(name?: string, bindings?: LogMeta): Logger {
  const allBindings = name ? { logger: name, ...bindings } : bindings ?? {};
  return new LoggerImpl(allBindings);
}

/**
 * Create a child logger with additional context
 */
export function createChildLogger(parent: Logger, bindings: LogMeta): Logger {
  return parent.child(bindings);
}

// --- Default Logger ---

/**
 * Default logger instance for general use
 */
export const logger = createLogger();

// --- Specialized Loggers ---

/**
 * Logger for API operations
 */
export const apiLogger = createLogger("api");

/**
 * Logger for authentication operations
 */
export const authLogger = createLogger("auth");

/**
 * Logger for OpenAI compatibility layer
 */
export const openaiLogger = createLogger("openai-compat");

/**
 * Logger for session management
 */
export const sessionLogger = createLogger("session");

// --- Timing Utilities ---

/**
 * Create a timer for measuring operation duration
 */
export function createTimer(): () => number {
  const start = Date.now();
  return () => Date.now() - start;
}

/**
 * Measure and log the duration of an async operation
 */
export async function withTiming<T>(
  logger: Logger,
  label: string,
  operation: () => Promise<T>,
  meta?: LogMeta
): Promise<T> {
  const timer = createTimer();
  try {
    const result = await operation();
    logger.timing(label, timer(), { ...meta, success: true });
    return result;
  } catch (error) {
    logger.timing(label, timer(), { ...meta, success: false, error: String(error) });
    throw error;
  }
}
