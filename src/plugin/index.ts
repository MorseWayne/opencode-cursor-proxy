/**
 * OpenCode Cursor Auth Plugin
 *
 * Entry point for the OpenCode plugin interface.
 */

export {
  CursorOAuthPlugin,
  CURSOR_PROVIDER_ID,
} from "./plugin.js";

export type {
  PluginContext,
  PluginResult,
  PluginClient,
  GetAuth,
  Provider,
  ProviderModel,
  LoaderResult,
  AuthDetails,
  OAuthAuthDetails,
  ApiKeyAuthDetails,
  TokenAuthDetails,
  AuthMethod,
  OAuthAuthMethod,
  ApiKeyAuthMethod,
  TokenExchangeResult,
  TokenExchangeSuccess,
  TokenExchangeFailure,
  CursorAuthRecord,
} from "./types";

// Default export is the main plugin factory
export { CursorOAuthPlugin as default } from "./plugin.js";
