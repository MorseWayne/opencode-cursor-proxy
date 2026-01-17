import { describe, expect, test } from "bun:test";
import {
  detectModelProvider,
  countOpenAITokens,
  countAnthropicTokens,
  countTokens,
  calculateTokenUsage,
  isWithinTokenLimit,
} from "../../src/lib/utils/tokenizer";

describe("detectModelProvider", () => {
  test("detects OpenAI models", () => {
    expect(detectModelProvider("gpt-4")).toBe("openai");
    expect(detectModelProvider("gpt-4o")).toBe("openai");
    expect(detectModelProvider("gpt-4o-mini")).toBe("openai");
    expect(detectModelProvider("gpt-3.5-turbo")).toBe("openai");
    expect(detectModelProvider("o1-preview")).toBe("openai");
    expect(detectModelProvider("o3-mini")).toBe("openai");
    expect(detectModelProvider("text-davinci-003")).toBe("openai");
  });

  test("detects Anthropic models", () => {
    expect(detectModelProvider("claude-3-opus")).toBe("anthropic");
    expect(detectModelProvider("claude-3-sonnet")).toBe("anthropic");
    expect(detectModelProvider("claude-3-haiku")).toBe("anthropic");
    expect(detectModelProvider("sonnet-4.5")).toBe("anthropic");
    expect(detectModelProvider("opus-4.5")).toBe("anthropic");
    expect(detectModelProvider("haiku-3")).toBe("anthropic");
  });

  test("detects Gemini models", () => {
    expect(detectModelProvider("gemini-pro")).toBe("gemini");
    expect(detectModelProvider("gemini-1.5-pro")).toBe("gemini");
    expect(detectModelProvider("gemini-3-pro")).toBe("gemini");
  });

  test("returns unknown for unrecognized models", () => {
    expect(detectModelProvider("random-model")).toBe("unknown");
    expect(detectModelProvider("custom-llm")).toBe("unknown");
  });

  test("is case insensitive", () => {
    expect(detectModelProvider("GPT-4O")).toBe("openai");
    expect(detectModelProvider("CLAUDE-3-OPUS")).toBe("anthropic");
    expect(detectModelProvider("Gemini-Pro")).toBe("gemini");
  });
});

describe("countOpenAITokens", () => {
  test("counts tokens for simple text", () => {
    const tokens = countOpenAITokens("Hello, world!");
    expect(tokens).toBeGreaterThan(0);
    expect(typeof tokens).toBe("number");
  });

  test("returns consistent results for same input", () => {
    const text = "This is a test sentence.";
    const count1 = countOpenAITokens(text);
    const count2 = countOpenAITokens(text);
    expect(count1).toBe(count2);
  });

  test("handles empty string", () => {
    expect(countOpenAITokens("")).toBe(0);
  });

  test("handles unicode", () => {
    const tokens = countOpenAITokens("Hello 世界 🌍");
    expect(tokens).toBeGreaterThan(0);
  });
});

describe("countAnthropicTokens", () => {
  test("counts tokens for simple text", () => {
    const tokens = countAnthropicTokens("Hello, world!");
    expect(tokens).toBeGreaterThan(0);
    expect(typeof tokens).toBe("number");
  });

  test("returns consistent results for same input", () => {
    const text = "This is a test sentence.";
    const count1 = countAnthropicTokens(text);
    const count2 = countAnthropicTokens(text);
    expect(count1).toBe(count2);
  });

  test("handles empty string", () => {
    expect(countAnthropicTokens("")).toBe(0);
  });
});

describe("countTokens", () => {
  test("uses OpenAI tokenizer for GPT models", () => {
    const text = "Hello, world!";
    const tokens = countTokens(text, "gpt-4o");
    const openaiTokens = countOpenAITokens(text);
    expect(tokens).toBe(openaiTokens);
  });

  test("uses Anthropic tokenizer for Claude models", () => {
    const text = "Hello, world!";
    const tokens = countTokens(text, "claude-3-opus");
    const anthropicTokens = countAnthropicTokens(text);
    expect(tokens).toBe(anthropicTokens);
  });

  test("uses OpenAI tokenizer as fallback for unknown models", () => {
    const text = "Hello, world!";
    const tokens = countTokens(text, "unknown-model");
    const openaiTokens = countOpenAITokens(text);
    expect(tokens).toBe(openaiTokens);
  });
});

describe("calculateTokenUsage", () => {
  test("calculates usage for OpenAI model", () => {
    const usage = calculateTokenUsage("What is AI?", "AI is artificial intelligence.", "gpt-4o");
    expect(usage.prompt_tokens).toBeGreaterThan(0);
    expect(usage.completion_tokens).toBeGreaterThan(0);
    expect(usage.total_tokens).toBe(usage.prompt_tokens + usage.completion_tokens);
  });

  test("calculates usage for Claude model", () => {
    const usage = calculateTokenUsage("What is AI?", "AI is artificial intelligence.", "claude-3-opus");
    expect(usage.prompt_tokens).toBeGreaterThan(0);
    expect(usage.completion_tokens).toBeGreaterThan(0);
    expect(usage.total_tokens).toBe(usage.prompt_tokens + usage.completion_tokens);
  });

  test("handles empty strings", () => {
    const usage = calculateTokenUsage("", "", "gpt-4o");
    expect(usage.prompt_tokens).toBe(0);
    expect(usage.completion_tokens).toBe(0);
    expect(usage.total_tokens).toBe(0);
  });
});

describe("isWithinTokenLimit", () => {
  test("returns token count when within limit", () => {
    const result = isWithinTokenLimit("Hello", 100, "gpt-4o");
    expect(result).not.toBe(false);
    expect(typeof result).toBe("number");
  });

  test("returns false when exceeding limit", () => {
    const result = isWithinTokenLimit("This is a longer text that should exceed a tiny limit", 1, "gpt-4o");
    expect(result).toBe(false);
  });

  test("works with Anthropic models", () => {
    const result = isWithinTokenLimit("Hello", 100, "claude-3-opus");
    expect(result).not.toBe(false);
  });
});
