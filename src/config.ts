/**
 * Inkog MCP Server Configuration
 *
 * All configuration is externalized - no hardcoded values.
 * Uses environment variables with sensible defaults.
 */

import { z } from 'zod';

/**
 * Configuration schema with validation
 */
const ConfigSchema = z.object({
  // API Configuration
  apiBaseUrl: z.string().url().default('https://api.inkog.io'),
  apiVersion: z.string().default('v1'),
  apiTimeout: z.number().positive().default(30000),
  apiRetryAttempts: z.number().int().min(0).max(10).default(3),
  apiRetryDelay: z.number().positive().default(1000),

  // MCP Server Configuration
  serverName: z.string().default('inkog'),
  serverVersion: z.string().default('1.0.0'),

  // Feature Flags
  enableMcpAudit: z.boolean().default(true),
  enableMlbom: z.boolean().default(true),
  enableA2a: z.boolean().default(true),

  // Logging
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  logFormat: z.enum(['json', 'text']).default('json'),
});

export type Config = z.infer<typeof ConfigSchema>;

/**
 * Load configuration from environment variables
 */
function loadFromEnvironment(): Record<string, unknown> {
  const config: Record<string, unknown> = {};

  const apiUrl = process.env.INKOG_API_URL;
  if (apiUrl !== undefined) {
    config.apiBaseUrl = apiUrl;
  }

  const apiVersion = process.env.INKOG_API_VERSION;
  if (apiVersion !== undefined) {
    config.apiVersion = apiVersion;
  }

  const apiTimeout = process.env.INKOG_API_TIMEOUT;
  if (apiTimeout !== undefined) {
    config.apiTimeout = parseInt(apiTimeout, 10);
  }

  const retryAttempts = process.env.INKOG_API_RETRY_ATTEMPTS;
  if (retryAttempts !== undefined) {
    config.apiRetryAttempts = parseInt(retryAttempts, 10);
  }

  const retryDelay = process.env.INKOG_API_RETRY_DELAY;
  if (retryDelay !== undefined) {
    config.apiRetryDelay = parseInt(retryDelay, 10);
  }

  const serverName = process.env.INKOG_SERVER_NAME;
  if (serverName !== undefined) {
    config.serverName = serverName;
  }

  const serverVersion = process.env.INKOG_SERVER_VERSION;
  if (serverVersion !== undefined) {
    config.serverVersion = serverVersion;
  }

  const enableMcpAudit = process.env.INKOG_ENABLE_MCP_AUDIT;
  if (enableMcpAudit !== undefined) {
    config.enableMcpAudit = enableMcpAudit === 'true';
  }

  const enableMlbom = process.env.INKOG_ENABLE_MLBOM;
  if (enableMlbom !== undefined) {
    config.enableMlbom = enableMlbom === 'true';
  }

  const enableA2a = process.env.INKOG_ENABLE_A2A;
  if (enableA2a !== undefined) {
    config.enableA2a = enableA2a === 'true';
  }

  const logLevel = process.env.INKOG_LOG_LEVEL;
  if (logLevel !== undefined) {
    config.logLevel = logLevel as Config['logLevel'];
  }

  const logFormat = process.env.INKOG_LOG_FORMAT;
  if (logFormat !== undefined) {
    config.logFormat = logFormat as Config['logFormat'];
  }

  return config;
}

/**
 * Remove undefined values from object
 */
function filterDefined<T extends Record<string, unknown>>(obj: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== undefined)
  ) as Partial<T>;
}

/**
 * Create configuration with defaults and environment overrides
 */
export function createConfig(overrides?: Partial<Config>): Config {
  const envConfig = loadFromEnvironment();
  const overrideConfig = overrides !== undefined ? filterDefined(overrides) : {};
  const merged = { ...envConfig, ...overrideConfig };

  const result = ConfigSchema.safeParse(merged);
  if (!result.success) {
    throw new Error(`Invalid configuration: ${result.error.message}`);
  }

  return result.data;
}

/**
 * Get the API key from environment
 * Returns undefined if not set (API client will handle the error)
 */
export function getApiKey(): string | undefined {
  return process.env.INKOG_API_KEY;
}

/**
 * Build full API endpoint URL
 */
export function buildApiUrl(config: Config, path: string): string {
  const baseUrl = config.apiBaseUrl.replace(/\/$/, '');
  const version = config.apiVersion;
  const cleanPath = path.replace(/^\//, '');
  return `${baseUrl}/${version}/${cleanPath}`;
}

/**
 * Default configuration singleton
 */
let defaultConfig: Config | null = null;

export function getConfig(): Config {
  defaultConfig ??= createConfig();
  return defaultConfig;
}

export function resetConfig(): void {
  defaultConfig = null;
}
