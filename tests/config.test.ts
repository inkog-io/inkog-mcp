import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { getConfig, getApiKey, resetConfig, createConfig, buildApiUrl } from '../src/config.js';
import type { Config } from '../src/config.js';

describe('config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
    resetConfig();
  });

  afterEach(() => {
    process.env = originalEnv;
    resetConfig();
  });

  describe('getConfig', () => {
    it('returns default configuration when no env vars set', () => {
      const config = getConfig();

      expect(config.apiBaseUrl).toBe('https://api.inkog.io');
      expect(config.apiVersion).toBe('v1');
      expect(config.serverName).toBe('inkog');
      expect(config.serverVersion).toBe('1.0.0');
      expect(config.logLevel).toBe('info');
      expect(config.logFormat).toBe('json');
      expect(config.apiTimeout).toBe(180000); // 3 minutes to match backend
      expect(config.apiRetryAttempts).toBe(3);
    });

    it('uses INKOG_API_URL environment variable', () => {
      process.env['INKOG_API_URL'] = 'https://custom.api.io';
      resetConfig();

      const config = getConfig();
      expect(config.apiBaseUrl).toBe('https://custom.api.io');
    });

    it('uses INKOG_LOG_LEVEL environment variable', () => {
      process.env['INKOG_LOG_LEVEL'] = 'debug';
      resetConfig();

      const config = getConfig();
      expect(config.logLevel).toBe('debug');
    });

    it('uses INKOG_API_TIMEOUT environment variable', () => {
      process.env['INKOG_API_TIMEOUT'] = '60000';
      resetConfig();

      const config = getConfig();
      expect(config.apiTimeout).toBe(60000);
    });

    it('caches configuration after first call', () => {
      const config1 = getConfig();
      const config2 = getConfig();

      expect(config1).toBe(config2);
    });
  });

  describe('createConfig', () => {
    it('applies overrides correctly', () => {
      const config = createConfig({
        apiBaseUrl: 'https://custom.api.io',
        logLevel: 'debug',
      });

      expect(config.apiBaseUrl).toBe('https://custom.api.io');
      expect(config.logLevel).toBe('debug');
      // Defaults should still apply
      expect(config.serverName).toBe('inkog');
    });

    it('throws on invalid configuration', () => {
      expect(() => createConfig({ apiBaseUrl: 'not-a-url' } as Partial<Config>))
        .toThrow('Invalid configuration');
    });
  });

  describe('getApiKey', () => {
    it('returns undefined when no API key is set', () => {
      delete process.env['INKOG_API_KEY'];

      const apiKey = getApiKey();
      expect(apiKey).toBeUndefined();
    });

    it('returns API key from environment variable', () => {
      process.env['INKOG_API_KEY'] = 'sk_live_test123';

      const apiKey = getApiKey();
      expect(apiKey).toBe('sk_live_test123');
    });
  });

  describe('buildApiUrl', () => {
    it('builds correct URL from config and path', () => {
      const config = createConfig({
        apiBaseUrl: 'https://api.inkog.io',
        apiVersion: 'v1',
      });

      const url = buildApiUrl(config, 'scan');
      expect(url).toBe('https://api.inkog.io/v1/scan');
    });

    it('handles trailing slash in base URL', () => {
      const config = createConfig({
        apiBaseUrl: 'https://api.inkog.io/',
        apiVersion: 'v1',
      });

      const url = buildApiUrl(config, 'scan');
      expect(url).toBe('https://api.inkog.io/v1/scan');
    });

    it('handles leading slash in path', () => {
      const config = createConfig({
        apiBaseUrl: 'https://api.inkog.io',
        apiVersion: 'v1',
      });

      const url = buildApiUrl(config, '/scan');
      expect(url).toBe('https://api.inkog.io/v1/scan');
    });
  });
});
