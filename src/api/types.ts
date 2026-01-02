/**
 * Inkog API Types
 *
 * Type definitions for all Inkog API requests and responses.
 * These types mirror the backend contract types.
 */

import { z } from 'zod';

// =============================================================================
// Common Types
// =============================================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type RiskTier = 'vulnerability' | 'risk_pattern' | 'hardening';
export type ComplianceFramework =
  | 'eu-ai-act'
  | 'nist-ai-rmf'
  | 'iso-42001'
  | 'owasp-llm-top-10'
  | 'gdpr';
export type OutputFormat = 'summary' | 'detailed' | 'sarif' | 'json' | 'markdown';
export type MlbomFormat = 'cyclonedx' | 'spdx' | 'json';
export type SecurityPolicy =
  | 'low-noise'
  | 'balanced'
  | 'comprehensive'
  | 'governance'
  | 'eu-ai-act';

// =============================================================================
// Finding Types
// =============================================================================

export interface ComplianceMapping {
  euAiActArticles: string[];
  nistCategories: string[];
  owaspItems: string[];
  cweIds: string[];
  iso42001Clauses: string[];
  gdprArticles: string[];
}

export interface Finding {
  id: string;
  patternId: string;
  file: string;
  line: number;
  column: number;
  endLine?: number;
  endColumn?: number;
  severity: Severity;
  confidence: number;
  calibratedConfidence?: number;
  message: string;
  cwe?: string;
  category: string;
  riskTier: RiskTier;
  inputTainted: boolean;
  taintSource?: string;
  remediation?: string;
  complianceMapping?: ComplianceMapping;
  codeSnippet?: string;
}

// =============================================================================
// Scan Types
// =============================================================================

export const ScanRequestSchema = z.object({
  files: z.array(
    z.object({
      path: z.string(),
      content: z.string(),
    })
  ),
  policy: z
    .enum(['low-noise', 'balanced', 'comprehensive', 'governance', 'eu-ai-act'])
    .default('balanced'),
  output: z.enum(['summary', 'detailed', 'sarif']).default('summary'),
});

export type ScanRequest = z.infer<typeof ScanRequestSchema>;

export interface ScanResponse {
  success: boolean;
  scanId: string;
  riskScore: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: Finding[];
  filesScanned: number;
  scanDuration: string;
  governance?: GovernanceResult;
}

// =============================================================================
// Governance Types
// =============================================================================

export interface ArticleStatus {
  article: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  description: string;
  findingCount: number;
}

export interface FrameworkStatus {
  framework: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL';
  items: string[];
  findingCount: number;
}

export interface GovernanceResult {
  governanceScore: number;
  euAiActReadiness: 'READY' | 'PARTIAL' | 'NOT_READY';
  articleMapping: Record<string, ArticleStatus>;
  frameworkMapping: Record<string, FrameworkStatus>;
}

export interface GovernanceMismatch {
  declared: string;
  actual: string;
  file: string;
  line: number;
  severity: Severity;
  description: string;
}

export interface GovernanceVerifyResponse {
  success: boolean;
  hasAgentsMd: boolean;
  agentsMdPath?: string;
  mismatches: GovernanceMismatch[];
  declaredCapabilities: string[];
  declaredLimitations: string[];
  declaredTools: string[];
  complianceScore: number;
  recommendation?: string;
}

// =============================================================================
// Compliance Report Types
// =============================================================================

export interface ComplianceReportRequest {
  files: { path: string; content: string }[];
  framework: ComplianceFramework | 'all';
  format: 'markdown' | 'json' | 'pdf';
}

export interface ComplianceArticle {
  id: string;
  title: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL' | 'NOT_APPLICABLE';
  findings: Finding[];
  recommendations: string[];
}

export interface ComplianceReportResponse {
  success: boolean;
  framework: ComplianceFramework;
  overallStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
  complianceScore: number;
  articles: ComplianceArticle[];
  executiveSummary: string;
  generatedAt: string;
  reportContent?: string; // For markdown/pdf format
}

// =============================================================================
// Finding Explanation Types
// =============================================================================

export interface ExplainRequest {
  findingId?: string;
  pattern?: string;
}

export interface RemediationStep {
  order: number;
  description: string;
  codeExample?: string;
  language?: string;
}

export interface ExplainResponse {
  success: boolean;
  pattern: string;
  title: string;
  description: string;
  severity: Severity;
  cwe?: string;
  owaspLlm?: string;
  riskTier: RiskTier;
  explanation: string;
  impact: string;
  remediationSteps: RemediationStep[];
  references: string[];
  codeExamples?: {
    vulnerable: string;
    secure: string;
    language: string;
  };
}

// =============================================================================
// MCP Server Audit Types
// =============================================================================

export interface McpServerInfo {
  name: string;
  displayName?: string;
  description?: string;
  repository: string;
  homepage?: string;
  license?: string;
  tools: string[];
  resources?: string[];
}

export interface McpSecurityIssue {
  severity: Severity;
  category: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation: string;
}

export interface McpAuditResponse {
  success: boolean;
  serverInfo: McpServerInfo;
  securityScore: number;
  issues: McpSecurityIssue[];
  toolPermissions: Record<
    string,
    {
      reads: string[];
      writes: string[];
      executes: string[];
      network: string[];
    }
  >;
  dataFlowRisks: string[];
  recommendations: string[];
}

// =============================================================================
// MLBOM Types (Machine Learning Bill of Materials)
// =============================================================================

export interface MlComponent {
  type: 'model' | 'tool' | 'data-source' | 'framework' | 'dependency';
  name: string;
  version?: string;
  provider?: string;
  license?: string;
  location: string;
  line?: number;
  properties?: Record<string, string>;
  vulnerabilities?: MlVulnerability[];
}

export interface MlVulnerability {
  id: string;
  severity: Severity;
  description: string;
  cve?: string;
  advisory?: string;
}

export interface MlbomResponse {
  success: boolean;
  format: MlbomFormat;
  version: string;
  generatedAt: string;
  components: MlComponent[];
  vulnerabilityCount: number;
  riskScore: number;
  bomContent?: string; // For CycloneDX/SPDX format
}

// =============================================================================
// A2A (Agent-to-Agent) Audit Types
// =============================================================================

export type A2AProtocol = 'a2a' | 'crewai' | 'langgraph' | 'auto-detect';

export interface AgentDefinition {
  id: string;
  name: string;
  role?: string;
  tools: string[];
  permissions: string[];
  file: string;
  line: number;
}

export interface DelegationEdge {
  from: string;
  to: string;
  type: 'delegate' | 'handoff' | 'spawn';
  file: string;
  line: number;
  hasGuards: boolean;
}

export interface A2ASecurityIssue {
  severity: Severity;
  category:
    | 'infinite-delegation'
    | 'privilege-escalation'
    | 'data-leakage'
    | 'unauthorized-handoff'
    | 'missing-guards';
  title: string;
  description: string;
  agents: string[];
  file: string;
  line: number;
  recommendation: string;
}

export interface A2AAuditResponse {
  success: boolean;
  protocol: A2AProtocol;
  agents: AgentDefinition[];
  delegationGraph: DelegationEdge[];
  issues: A2ASecurityIssue[];
  securityScore: number;
  hasCycles: boolean;
  maxDelegationDepth: number;
  recommendations: string[];
}

// =============================================================================
// Error Types
// =============================================================================

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiError;
}
