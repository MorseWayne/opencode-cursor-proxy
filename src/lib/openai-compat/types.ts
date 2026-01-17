/**
 * OpenAI-Compatible API Types
 * 
 * Shared type definitions for OpenAI API compatibility layer.
 */

// --- Tool Call Types ---

export interface OpenAIToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

export interface OpenAITool {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
}

// --- Message Types ---

export interface OpenAITextContentPart {
  type: "text";
  text: string;
}

export interface OpenAIImageContentPart {
  type: "image_url";
  image_url: {
    url: string;
    detail?: "auto" | "low" | "high";
  };
}

export type OpenAIMessageContent = string | null | (OpenAITextContentPart | OpenAIImageContentPart)[];

export interface OpenAIMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: OpenAIMessageContent;
  tool_calls?: OpenAIToolCall[];
  tool_call_id?: string;
}

// --- Request Types ---

export interface OpenAIChatRequest {
  model: string;
  messages: OpenAIMessage[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  frequency_penalty?: number;
  presence_penalty?: number;
  stop?: string | string[];
  user?: string;
  tools?: OpenAITool[];
  tool_choice?: "auto" | "none" | { type: "function"; function: { name: string } };
}

// --- Response Types ---

export interface OpenAIChatChoice {
  index: number;
  message: {
    role: "assistant";
    content: string | null;
    tool_calls?: OpenAIToolCall[];
  };
  finish_reason: "stop" | "length" | "content_filter" | "tool_calls" | null;
}

export interface OpenAIChatResponse {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: OpenAIChatChoice[];
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

// --- Streaming Types ---

export interface OpenAIStreamToolCallDelta {
  index: number;
  id?: string;
  type?: "function";
  function?: {
    name?: string;
    arguments?: string;
  };
}

export interface OpenAIStreamChoice {
  index: number;
  delta: {
    role?: "assistant";
    content?: string | null;
    tool_calls?: OpenAIStreamToolCallDelta[];
  };
  finish_reason: "stop" | "length" | "content_filter" | "tool_calls" | null;
}

export interface OpenAIStreamChunk {
  id: string;
  object: "chat.completion.chunk";
  created: number;
  model: string;
  choices: OpenAIStreamChoice[];
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

// --- Model Types ---

export interface OpenAIModel {
  id: string;
  object: "model";
  created: number;
  owned_by: string;
}

export interface OpenAIModelsResponse {
  object: "list";
  data: OpenAIModel[];
}

// --- Error Types ---

export interface OpenAIError {
  error: {
    message: string;
    type: string;
    param: string | null;
    code: string | null;
  };
}
