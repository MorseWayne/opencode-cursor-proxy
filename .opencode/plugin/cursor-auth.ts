/**
 * OpenCode Cursor Auth Plugin - Local Development Wrapper
 *
 * This file re-exports the Cursor OAuth plugin for local testing with OpenCode.
 * OpenCode automatically discovers plugins in .opencode/plugin/*.ts
 *
 * Usage:
 *   1. Run `opencode` in this directory
 *   2. The plugin will be auto-loaded
 *   3. Configure a provider with id "cursor" to use this auth
 */

export { CursorOAuthPlugin } from "../../src/plugin/index.ts";
