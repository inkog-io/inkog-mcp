/**
 * Inkog API Client
 *
 * Enterprise-grade HTTP client for communicating with the Inkog API.
 * Features:
 * - Automatic retry with exponential backoff
 * - Request/response validation
 * - Structured error handling
 * - Configurable timeouts
 * - API key authentication
 */

import {
  buildApiUrl,
  type Config,
  getApiKey,
  getConfig,
} from '../config.js';
import type {
  A2AAuditResponse,
  A2AProtocol,
  ApiError,
  ComplianceFramework,
  ComplianceReportResponse,
  ExplainResponse,
  GovernanceVerifyResponse,
  McpAuditResponse,
  MlbomFormat,
  MlbomResponse,
  ScanResponse,
  SecurityPolicy,
} from './types.js';

// =============================================================================
// Error Classes
// =============================================================================

export class InkogApiError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'InkogApiError';
  }
}

export class InkogAuthError extends InkogApiError {
  constructor(message = 'API key is required. Get your free key at https://app.inkog.io') {
    super(message, 'AUTH_REQUIRED', 401);
    this.name = 'InkogAuthError';
  }
}

export class InkogRateLimitError extends InkogApiError {
  constructor(
    public readonly retryAfter: number,
    message = 'Rate limit exceeded'
  ) {
    super(message, 'RATE_LIMIT', 429);
    this.name = 'InkogRateLimitError';
  }
}

export class InkogNetworkError extends Error {
  constructor(
    message: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'InkogNetworkError';
  }
}

// =============================================================================
// Client Types
// =============================================================================

interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
  timeout?: number;
  retries?: number;
}

interface FileInput {
  path: string;
  content: string;
}

// =============================================================================
// Inkog API Client
// =============================================================================

export class InkogClient {
  private readonly config: Config;
  private readonly apiKey: string | undefined;

  constructor(config?: Partial<Config>, apiKey?: string) {
    this.config = config ? { ...getConfig(), ...config } : getConfig();
    this.apiKey = apiKey ?? getApiKey();
  }

  /**
   * Check if client has valid API key
   */
  hasApiKey(): boolean {
    return this.apiKey !== undefined && this.apiKey.length > 0;
  }

  /**
   * Make authenticated API request with retry logic
   */
  private async request<T>(options: RequestOptions): Promise<T> {
    if (!this.hasApiKey()) {
      throw new InkogAuthError();
    }

    const url = buildApiUrl(this.config, options.path);
    const timeout = options.timeout ?? this.config.apiTimeout;
    const maxRetries = options.retries ?? this.config.apiRetryAttempts;

    let lastError: Error | null = null;
    let attempt = 0;

    while (attempt <= maxRetries) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => { controller.abort(); }, timeout);

        const fetchOptions: RequestInit = {
          method: options.method,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.apiKey}`,
            'User-Agent': `inkog-mcp/${this.config.serverVersion}`,
            ...options.headers,
          },
          signal: controller.signal,
        };

        if (options.body !== undefined) {
          fetchOptions.body = JSON.stringify(options.body);
        }

        const response = await fetch(url, fetchOptions);

        clearTimeout(timeoutId);

        // Handle rate limiting
        if (response.status === 429) {
          const retryAfter = parseInt(response.headers.get('Retry-After') ?? '60', 10);
          throw new InkogRateLimitError(retryAfter);
        }

        // Handle authentication errors
        if (response.status === 401) {
          throw new InkogAuthError();
        }

        // Handle other errors
        if (!response.ok) {
          const errorBody = (await response.json().catch(() => ({}))) as { error?: ApiError };
          throw new InkogApiError(
            errorBody.error?.message ?? `Request failed with status ${response.status}`,
            errorBody.error?.code ?? 'API_ERROR',
            response.status,
            errorBody.error?.details
          );
        }

        return (await response.json()) as T;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry auth errors or rate limits
        if (error instanceof InkogAuthError) {
          throw error;
        }

        if (error instanceof InkogRateLimitError) {
          throw error;
        }

        // Don't retry client errors (4xx except rate limit)
        if (error instanceof InkogApiError && error.statusCode >= 400 && error.statusCode < 500) {
          throw error;
        }

        // Retry on network errors or server errors
        if (attempt < maxRetries) {
          const delay = this.config.apiRetryDelay * Math.pow(2, attempt);
          await this.sleep(delay);
          attempt++;
          continue;
        }

        // Wrap network errors
        if (lastError.name === 'AbortError') {
          throw new InkogNetworkError('Request timed out', lastError);
        }

        if (lastError.name === 'TypeError' && lastError.message.includes('fetch')) {
          throw new InkogNetworkError('Network request failed', lastError);
        }

        throw lastError;
      }
    }

    throw lastError ?? new Error('Request failed after retries');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ===========================================================================
  // API Methods
  // ===========================================================================

  /**
   * Scan files for AI agent vulnerabilities
   */
  async scan(
    files: FileInput[],
    options?: {
      policy?: SecurityPolicy;
      output?: 'summary' | 'detailed' | 'sarif';
    }
  ): Promise<ScanResponse> {
    return this.request<ScanResponse>({
      method: 'POST',
      path: 'scan',
      body: {
        files,
        policy: options?.policy ?? 'balanced',
        output: options?.output ?? 'summary',
      },
    });
  }

  /**
   * Verify AGENTS.md governance declarations against actual code
   */
  async verifyGovernance(files: FileInput[]): Promise<GovernanceVerifyResponse> {
    return this.request<GovernanceVerifyResponse>({
      method: 'POST',
      path: 'governance/verify',
      body: { files },
    });
  }

  /**
   * Generate compliance report for a regulatory framework
   */
  async generateComplianceReport(
    files: FileInput[],
    options?: {
      framework?: ComplianceFramework | 'all';
      format?: 'markdown' | 'json' | 'pdf';
    }
  ): Promise<ComplianceReportResponse> {
    return this.request<ComplianceReportResponse>({
      method: 'POST',
      path: 'compliance/report',
      body: {
        files,
        framework: options?.framework ?? 'eu-ai-act',
        format: options?.format ?? 'markdown',
      },
    });
  }

  /**
   * Get detailed explanation and remediation for a finding or pattern
   */
  async explainFinding(options: {
    findingId?: string;
    pattern?: string;
  }): Promise<ExplainResponse> {
    if (options.findingId === undefined && options.pattern === undefined) {
      throw new Error('Either findingId or pattern must be provided');
    }

    const params = new URLSearchParams();
    if (options.findingId !== undefined) {
      params.set('finding_id', options.findingId);
    }
    if (options.pattern !== undefined) {
      params.set('pattern', options.pattern);
    }

    return this.request<ExplainResponse>({
      method: 'GET',
      path: `findings/explain?${params.toString()}`,
    });
  }

  /**
   * Security audit an MCP server from the registry or GitHub
   */
  async auditMcpServer(options: {
    serverName?: string;
    repositoryUrl?: string;
  }): Promise<McpAuditResponse> {
    if (options.serverName === undefined && options.repositoryUrl === undefined) {
      throw new Error('Either serverName or repositoryUrl must be provided');
    }

    return this.request<McpAuditResponse>({
      method: 'POST',
      path: 'mcp/audit',
      body: options,
    });
  }

  /**
   * Generate ML Bill of Materials (MLBOM)
   */
  async generateMlbom(
    files: FileInput[],
    options?: {
      format?: MlbomFormat;
      includeVulnerabilities?: boolean;
    }
  ): Promise<MlbomResponse> {
    return this.request<MlbomResponse>({
      method: 'POST',
      path: 'mlbom/generate',
      body: {
        files,
        format: options?.format ?? 'cyclonedx',
        include_vulnerabilities: options?.includeVulnerabilities ?? true,
      },
    });
  }

  /**
   * Audit Agent-to-Agent (A2A) communications
   */
  async auditA2A(
    files: FileInput[],
    options?: {
      protocol?: A2AProtocol;
      checkDelegationChains?: boolean;
    }
  ): Promise<A2AAuditResponse> {
    return this.request<A2AAuditResponse>({
      method: 'POST',
      path: 'a2a/audit',
      body: {
        files,
        protocol: options?.protocol ?? 'auto-detect',
        check_delegation_chains: options?.checkDelegationChains ?? true,
      },
    });
  }
}

// =============================================================================
// Default Client Instance
// =============================================================================

let defaultClient: InkogClient | null = null;

export function getClient(): InkogClient {
  defaultClient ??= new InkogClient();
  return defaultClient;
}

export function createClient(config?: Partial<Config>, apiKey?: string): InkogClient {
  return new InkogClient(config, apiKey);
}

export function resetClient(): void {
  defaultClient = null;
}
