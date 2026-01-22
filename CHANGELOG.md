# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-01-22

### Added

- **Enhanced Debug Logging**: Comprehensive logging for session and network operations
  - Debug logging for bidi communication and session management
  - Network error logging with distinct error categorization
  - Consistent debug logging across agent service and session reuse modules

- **Retry Logic for Network Operations**: Improved reliability for transient network errors
  - Automatic retry mechanism in bidiAppend method for failed network requests
  - Better error handling and recovery for network-related issues
  - Enhanced error messages for debugging network connectivity problems

### Changed

- Refactor console.log statements to use centralized debugLog function for consistency
- Update error handling patterns across agent service and plugin components

## [1.0.1] - 2026-01-18

### Added

- **Request Transformer Layer**: Filter AI SDK constructs and strip message IDs for Cursor API compatibility
  - Filter `item_reference` type messages (AI SDK server state lookup)
  - Strip message IDs to prevent "item not found" errors in stateless mode
  - Validate messages for model capabilities

- **Enhanced Multimodal Support**: Process and handle image content in messages
  - Extract text and images from mixed content arrays
  - Detect base64 and URL image formats
  - Add image references for non-vision models
  - New `messagesToPromptWithImages()` function for vision-aware prompt generation

- **Expanded Model Presets**: 70+ model aliases and 25+ model configurations
  - Claude 4 series (claude-sonnet-4, claude-opus-4)
  - GPT-5 series (future-proofing)
  - Gemini 2.5 series with 2M context window
  - DeepSeek R1 reasoning model
  - Mistral, Llama, and Grok families
  - New model config fields: `supportsStreaming`, `maxOutputTokens`, `family`, `isReasoningModel`

- **Enhanced Debug Logging**: More detailed request/response logging
  - `CURSOR_REQUEST_LOGGING` - Enable request/response logging
  - `CURSOR_LOG_FILTERED_IDS` - Log filtered message IDs during transformation
  - `CURSOR_LOG_MULTIMODAL` - Log multimodal content detection
  - New logging functions: `logRequestTransform()`, `logMultimodalContent()`, `logRequest()`, `logResponse()`

### Changed

- `messagesToPrompt()` now accepts options for vision support and image reference inclusion
- Handler now applies request transformation before processing messages
- Updated existing tests to account for new multimodal behavior

### Tests

- Added 70 new unit tests across 3 test files:
  - `request-transformer.test.ts` - Request transformation tests
  - `multimodal.test.ts` - Multimodal content processing tests
  - `model-presets.test.ts` - Model configuration and resolution tests

## [0.2.0] - 2026-01-18

### Added

- OpenCode plugin integration with OAuth authentication
- Full tool-calling support (bash, read, write, ls, glob, grep, etc.)
- Dynamic model discovery from Cursor APIs
- Streaming support via SSE
- Session reuse for improved tool-calling performance
- Standalone proxy server for development and debugging
- Unit tests and integration tests
- Bilingual documentation (English and Chinese)

### Features

- **OAuth Authentication**: Browser-based OAuth flow with PKCE for secure authentication
- **Token Refresh**: Automatic access token refresh using refresh tokens
- **Model Mapping**: Intelligent mapping between Cursor models and llm-info for accurate token limits
- **OpenAI Compatibility**: Full OpenAI API compatibility layer for seamless integration

## [0.1.0] - 2026-01-15

### Added

- Initial project setup
- Basic Cursor API client implementation
- Protobuf-based Agent Service communication
- Core authentication flow

[Unreleased]: https://github.com/MorseWayne/opencode-cursor-proxy/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/MorseWayne/opencode-cursor-proxy/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/MorseWayne/opencode-cursor-proxy/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/MorseWayne/opencode-cursor-proxy/compare/v0.2.0...v1.0.1
[0.2.0]: https://github.com/MorseWayne/opencode-cursor-proxy/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MorseWayne/opencode-cursor-proxy/releases/tag/v0.1.0
