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
          const retryAfterRaw = parseInt(response.headers.get('Retry-After') ?? '60', 10);
          const retryAfter = Number.isNaN(retryAfterRaw) ? 60 : retryAfterRaw;
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
   * Verify AGENTS.md governance declarations against actual code.
   * IMPORTANT: Requires a scanId from a previous scan. Direct file upload is only
   * supported via multipart form with an AGENTS.md file.
   */
  async verifyGovernance(options: {
    scanId: string;
  }): Promise<GovernanceVerifyResponse> {
    if (!options.scanId) {
      throw new Error('scanId is required. Run a scan first, then verify governance.');
    }

    return this.request<GovernanceVerifyResponse>({
      method: 'POST',
      path: 'governance/verify',
      body: {
        scan_id: options.scanId,
      },
    });
  }

  /**
   * Generate compliance report for a regulatory framework.
   * IMPORTANT: Requires a scanId from a previous scan.
   */
  async generateComplianceReport(options: {
    scanId: string;
    framework?: ComplianceFramework | 'all';
    format?: 'markdown' | 'json' | 'pdf';
  }): Promise<ComplianceReportResponse> {
    if (!options.scanId) {
      throw new Error('scanId is required. Run a scan first, then generate compliance report.');
    }

    return this.request<ComplianceReportResponse>({
      method: 'POST',
      path: 'compliance/report',
      body: {
        scan_id: options.scanId,
        framework: options.framework ?? 'eu-ai-act',
        format: options.format ?? 'markdown',
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

    // Backend expects: /v1/findings/{pattern_id}/explain
    const patternId = options.pattern ?? options.findingId;

    return this.request<ExplainResponse>({
      method: 'GET',
      path: `findings/${patternId}/explain`,
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

    // Convert to snake_case for backend API
    const body: Record<string, unknown> = {};
    if (options.serverName) {
      body.server_name = options.serverName;
    }
    if (options.repositoryUrl) {
      body.repository_url = options.repositoryUrl;
    }

    return this.request<McpAuditResponse>({
      method: 'POST',
      path: 'mcp/audit',
      body,
    });
  }

  /**
   * Generate ML Bill of Materials (MLBOM).
   * Either provide files directly, or reference a previous scan by scanId.
   */
  async generateMlbom(
    files: FileInput[],
    options?: {
      format?: MlbomFormat;
      includeVulnerabilities?: boolean;
      scanId?: string;
    }
  ): Promise<MlbomResponse> {
    const body: Record<string, unknown> = {
      format: options?.format ?? 'cyclonedx',
      include_vulnerabilities: options?.includeVulnerabilities ?? true,
    };

    if (options?.scanId) {
      body.scan_id = options.scanId;
    } else if (files.length > 0) {
      body.files = files;
    }

    return this.request<MlbomResponse>({
      method: 'POST',
      path: 'mlbom/generate',
      body,
    });
  }

  /**
   * Audit Agent-to-Agent (A2A) communications.
   * Either provide files directly, or reference a previous scan by scanId.
   */
  async auditA2A(
    files: FileInput[],
    options?: {
      protocol?: A2AProtocol;
      checkDelegationChains?: boolean;
      scanId?: string;
    }
  ): Promise<A2AAuditResponse> {
    const body: Record<string, unknown> = {
      protocol: options?.protocol ?? 'auto-detect',
      check_delegation_chains: options?.checkDelegationChains ?? true,
    };

    if (options?.scanId) {
      body.scan_id = options.scanId;
    } else if (files.length > 0) {
      body.files = files;
    }

    return this.request<A2AAuditResponse>({
      method: 'POST',
      path: 'a2a/audit',
      body,
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
