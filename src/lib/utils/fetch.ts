/**
 * Fetch Utilities with Retry Support
 *
 * Provides robust HTTP request handling with:
 * - Exponential backoff retry
 * - Timeout support
 * - Transient error detection
 * - Request/response logging
 */

import { config } from "../config";
import { createLogger, createTimer, type Logger } from "./logger";

const logger = createLogger("fetch");

// --- Types ---

export interface RetryOptions {
  /** Maximum number of retry attempts (default: from config) */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms (default: from config) */
  baseDelayMs?: number;
  /** Maximum delay between retries in ms (default: from config) */
  maxDelayMs?: number;
  /** Request timeout in ms (default: from config) */
  timeoutMs?: number;
  /** Custom retry condition (default: retry on 5xx and network errors) */
  shouldRetry?: (error: Error, response?: Response, attempt: number) => boolean;
  /** Logger instance for this request */
  logger?: Logger;
}

export interface FetchWithRetryResult {
  response: Response;
  attempts: number;
  totalTimeMs: number;
}

// --- Error Types ---

export class FetchTimeoutError extends Error {
  constructor(timeoutMs: number) {
    super(`Request timed out after ${timeoutMs}ms`);
    this.name = "FetchTimeoutError";
  }
}

export class FetchRetryExhaustedError extends Error {
  lastError: Error;
  attempts: number;

  constructor(lastError: Error, attempts: number) {
    super(`Request failed after ${attempts} attempts: ${lastError.message}`);
    this.name = "FetchRetryExhaustedError";
    this.lastError = lastError;
    this.attempts = attempts;
  }
}

// --- Utility Functions ---

/**
 * Sleep for a specified duration
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Calculate delay with exponential backoff and jitter
 */
export function calculateBackoffDelay(
  attempt: number,
  baseDelayMs: number,
  maxDelayMs: number
): number {
  // Exponential backoff: baseDelay * 2^attempt
  const exponentialDelay = baseDelayMs * Math.pow(2, attempt);
  // Add jitter (0-25% of delay)
  const jitter = exponentialDelay * Math.random() * 0.25;
  // Cap at max delay
  return Math.min(exponentialDelay + jitter, maxDelayMs);
}

/**
 * Check if an error is a transient network error that should be retried
 */
export function isTransientError(error: Error): boolean {
  const transientCodes = [
    "ECONNRESET",
    "ECONNREFUSED",
    "ETIMEDOUT",
    "ENOTFOUND",
    "EAI_AGAIN",
    "EPIPE",
    "EHOSTUNREACH",
    "ENETUNREACH",
  ];

  const message = error.message.toLowerCase();
  const name = error.name;

  // Check for known transient error codes
  if (transientCodes.some((code) => message.includes(code.toLowerCase()))) {
    return true;
  }

  // Check for fetch-specific errors
  if (name === "FetchError" || name === "AbortError") {
    return true;
  }

  // Check for timeout
  if (name === "FetchTimeoutError") {
    return true;
  }

  return false;
}

/**
 * Check if a response status code indicates a retryable error
 */
export function isRetryableStatus(status: number): boolean {
  // Retry on server errors (5xx) except 501 (Not Implemented)
  if (status >= 500 && status !== 501) {
    return true;
  }

  // Retry on rate limiting
  if (status === 429) {
    return true;
  }

  // Retry on request timeout
  if (status === 408) {
    return true;
  }

  return false;
}

/**
 * Default retry condition
 */
export function defaultShouldRetry(
  error: Error,
  response?: Response,
  _attempt?: number
): boolean {
  // Always retry transient network errors
  if (isTransientError(error)) {
    return true;
  }

  // Retry on retryable status codes
  if (response && isRetryableStatus(response.status)) {
    return true;
  }

  return false;
}

// --- Main Fetch Function ---

/**
 * Fetch with automatic retry and timeout support
 *
 * @example
 * ```ts
 * // Basic usage
 * const { response } = await fetchWithRetry("https://api.example.com/data");
 *
 * // With options
 * const { response, attempts } = await fetchWithRetry("https://api.example.com/data", {
 *   method: "POST",
 *   body: JSON.stringify({ data: "value" }),
 * }, {
 *   maxRetries: 5,
 *   timeoutMs: 30000,
 * });
 * ```
 */
export async function fetchWithRetry(
  input: string | URL | Request,
  init?: RequestInit,
  options?: RetryOptions
): Promise<FetchWithRetryResult> {
  const {
    maxRetries = config.network.maxRetries,
    baseDelayMs = config.network.retryBaseDelayMs,
    maxDelayMs = config.network.retryMaxDelayMs,
    timeoutMs = config.network.requestTimeoutMs,
    shouldRetry = defaultShouldRetry,
    logger: requestLogger = logger,
  } = options ?? {};

  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const method = init?.method ?? "GET";
  const timer = createTimer();

  let lastError: Error = new Error("No attempts made");
  let lastResponse: Response | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      requestLogger.debug(`Attempt ${attempt + 1}/${maxRetries + 1}`, {
        method,
        url: url.substring(0, 100),
      });

      const response = await fetch(input, {
        ...init,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Success - return immediately
      if (response.ok) {
        requestLogger.debug(`Request succeeded`, {
          method,
          status: response.status,
          attempts: attempt + 1,
          durationMs: timer(),
        });

        return {
          response,
          attempts: attempt + 1,
          totalTimeMs: timer(),
        };
      }

      // Non-OK response - check if retryable
      lastResponse = response;
      lastError = new Error(`HTTP ${response.status}: ${response.statusText}`);

      if (!shouldRetry(lastError, response, attempt) || attempt === maxRetries) {
        // Don't retry - return the response as-is
        requestLogger.debug(`Request returned non-OK status`, {
          method,
          status: response.status,
          attempts: attempt + 1,
          willRetry: false,
        });

        return {
          response,
          attempts: attempt + 1,
          totalTimeMs: timer(),
        };
      }

      // Will retry - log and continue
      requestLogger.warn(`Request failed, will retry`, {
        method,
        status: response.status,
        attempt: attempt + 1,
        maxRetries,
      });
    } catch (err) {
      clearTimeout(timeoutId);

      // Handle abort (timeout)
      if (err instanceof Error && err.name === "AbortError") {
        lastError = new FetchTimeoutError(timeoutMs);
      } else {
        lastError = err instanceof Error ? err : new Error(String(err));
      }

      // Check if should retry
      if (!shouldRetry(lastError, undefined, attempt) || attempt === maxRetries) {
        requestLogger.error(`Request failed`, {
          method,
          error: lastError.message,
          attempts: attempt + 1,
          willRetry: false,
        });
        throw new FetchRetryExhaustedError(lastError, attempt + 1);
      }

      requestLogger.warn(`Request error, will retry`, {
        method,
        error: lastError.message,
        attempt: attempt + 1,
        maxRetries,
      });
    }

    // Calculate and wait for backoff delay
    if (attempt < maxRetries) {
      const delay = calculateBackoffDelay(attempt, baseDelayMs, maxDelayMs);
      requestLogger.debug(`Waiting before retry`, { delayMs: Math.round(delay) });
      await sleep(delay);
    }
  }

  // Should not reach here, but just in case
  throw new FetchRetryExhaustedError(lastError, maxRetries + 1);
}

// --- Convenience Functions ---

/**
 * Simple fetch wrapper that respects retry config but returns just the Response
 */
export async function robustFetch(
  input: string | URL | Request,
  init?: RequestInit,
  options?: RetryOptions
): Promise<Response> {
  if (!config.network.retryEnabled) {
    // Retry disabled - use standard fetch with timeout only
    const timeoutMs = options?.timeoutMs ?? config.network.requestTimeoutMs;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(input, { ...init, signal: controller.signal });
      clearTimeout(timeoutId);
      return response;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof Error && err.name === "AbortError") {
        throw new FetchTimeoutError(timeoutMs);
      }
      throw err;
    }
  }

  const { response } = await fetchWithRetry(input, init, options);
  return response;
}

/**
 * Fetch JSON with retry support
 */
export async function fetchJson<T>(
  input: string | URL | Request,
  init?: RequestInit,
  options?: RetryOptions
): Promise<T> {
  const response = await robustFetch(input, init, options);

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }

  return response.json() as Promise<T>;
}
