import { encode as encodeGpt, isWithinTokenLimit as gptIsWithinLimit } from "gpt-tokenizer";
import { countTokens as countClaudeTokens } from "@anthropic-ai/tokenizer";

const OPENAI_PATTERNS = [
  /^gpt-/i,
  /^o[1-4]-/i,
  /^text-davinci/i,
  /^davinci/i,
  /^curie/i,
  /^babbage/i,
  /^ada/i,
];

const ANTHROPIC_PATTERNS = [
  /claude/i,
  /sonnet/i,
  /opus/i,
  /haiku/i,
];

const GEMINI_PATTERNS = [
  /gemini/i,
];

export type ModelProvider = "openai" | "anthropic" | "gemini" | "unknown";

export function detectModelProvider(model: string): ModelProvider {
  const normalizedModel = model.toLowerCase();
  
  if (ANTHROPIC_PATTERNS.some(p => p.test(normalizedModel))) {
    return "anthropic";
  }
  
  if (OPENAI_PATTERNS.some(p => p.test(normalizedModel))) {
    return "openai";
  }
  
  if (GEMINI_PATTERNS.some(p => p.test(normalizedModel))) {
    return "gemini";
  }
  
  return "unknown";
}

export function countOpenAITokens(text: string): number {
  return encodeGpt(text).length;
}

export function countAnthropicTokens(text: string): number {
  return countClaudeTokens(text);
}

export function countGeminiTokens(text: string): number {
  return encodeGpt(text).length;
}

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function countTokens(text: string, model: string): number {
  const provider = detectModelProvider(model);
  
  switch (provider) {
    case "openai":
      return countOpenAITokens(text);
    case "anthropic":
      return countAnthropicTokens(text);
    case "gemini":
      return countGeminiTokens(text);
    default:
      return countOpenAITokens(text);
  }
}

export function isWithinTokenLimit(text: string, limit: number, model: string): number | false {
  const provider = detectModelProvider(model);
  
  if (provider === "openai" || provider === "gemini") {
    return gptIsWithinLimit(text, limit);
  }
  
  const count = countTokens(text, model);
  return count <= limit ? count : false;
}

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export function calculateTokenUsage(
  prompt: string,
  completion: string,
  model: string
): TokenUsage {
  const promptTokens = countTokens(prompt, model);
  const completionTokens = countTokens(completion, model);
  
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}
