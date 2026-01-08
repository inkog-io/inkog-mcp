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
  scan_id: string;
  risk_score: number;
  files_scanned: number;
  scan_duration?: string;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings?: Finding[];
  governance?: GovernanceVerifyResponse;
}

// =============================================================================
// Governance Types
// =============================================================================

export interface DeclaredCapability {
  name: string;
  constraint_type: string; // e.g., "ConstraintNoWrite", "ConstraintReadOnly"
  status: string; // "valid", "violated", "unverified"
  line?: number;
  description?: string;
}

export interface GovernanceMismatch {
  capability: string;
  expected: string;
  actual: string;
  severity: string;
  file: string;
  line: number;
  evidence?: string;
}

export interface GovernanceVerifySummary {
  total_declarations: number;
  valid_declarations: number;
  violated_constraints: number;
  unverified_items: number;
  files_analyzed: number;
}

export interface GovernanceVerifyResponse {
  success: boolean;
  overall_status: string; // "valid", "invalid", "partial"
  score: number; // 0-100 governance alignment score
  declared_capabilities: DeclaredCapability[];
  mismatches: GovernanceMismatch[];
  recommendations: string[];
  summary?: GovernanceVerifySummary;

  // Legacy compatibility aliases (computed from above fields)
  hasAgentsMd?: boolean;
  complianceScore?: number;
}

// =============================================================================
// Compliance Report Types
// =============================================================================

export interface ComplianceReportRequest {
  scan_id?: string;
  frameworks: ComplianceFramework[];
  format?: 'markdown' | 'json' | 'pdf';
  organization?: string;
  path?: string;
}

export interface ComplianceArticle {
  id: string;
  title: string;
  status: string; // "compliant", "partial", "non-compliant"
  score: number; // 0-100
  requirements: string[];
  findings: string[]; // Finding IDs
  evidence?: string;
  remediation?: string;
}

export interface ComplianceCategory {
  id: string;
  name: string;
  status: string; // "pass", "partial", "fail"
  finding_ids: string[];
  description: string;
  impact?: string;
}

export interface ComplianceFindingsSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ComplianceRecommendation {
  priority: string;
  category: string;
  title: string;
  description: string;
  article?: string;
  effort?: string;
}

export interface ComplianceReportResponse {
  success: boolean;
  framework: ComplianceFramework;
  overall_score: number; // 0-100
  risk_level: string; // "low", "medium", "high", "critical"
  report_id: string;
  generated_at: string;
  organization?: string;
  scan_id?: string;
  articles?: ComplianceArticle[];
  categories?: ComplianceCategory[];
  findings_summary: ComplianceFindingsSummary;
  recommendations: ComplianceRecommendation[];
  markdown_report?: string;

  // Legacy compatibility
  complianceScore?: number;
  overallStatus?: string;
}

// =============================================================================
// Finding Explanation Types
// =============================================================================

export interface ExplainRequest {
  findingId?: string;
  pattern?: string;
}

export interface CodeExamples {
  vulnerable: string;
  secure: string;
}

export interface ExplainReference {
  title: string;
  url: string;
}

export interface ExplainComplianceMapping {
  eu_ai_act?: string[];
  nist_ai_rmf?: string[];
  owasp_llm_top_10?: string[];
  iso_42001?: string[];
  soc2?: string[];
  owasp_agentic?: string[];
  palo_alto?: string[];
  mitre_attack?: string[];
}

export interface ExplainResponse {
  success: boolean;
  pattern_id: string;
  title: string;
  severity: string;
  category: string;
  description: string;
  impact: string;
  financial_risk?: string;
  examples?: CodeExamples;
  remediation: string;
  remediation_steps: string[];
  cwe: string[];
  cvss: number;
  owasp?: string[];
  compliance_frameworks?: ExplainComplianceMapping;
  references?: ExplainReference[];

  // Legacy compatibility aliases
  pattern?: string;
  cweId?: string;
  riskTier?: RiskTier;
}

// =============================================================================
// MCP Server Audit Types
// =============================================================================

export interface McpServerInfo {
  name: string;
  version?: string;
  description?: string;
  repository?: string;
  author?: string;
  license?: string;
  registry_url?: string;
  verified?: boolean;
}

export interface McpAuditResults {
  overall_risk: string; // "critical", "high", "medium", "low"
  security_score: number; // 0-100
  tool_count: number;
  resource_count: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  files_analyzed: number;
  lines_of_code: number;
  analysis_duration: string;
}

export interface McpFinding {
  id: string;
  pattern_id: string;
  title: string;
  severity: string;
  description: string;
  file?: string;
  line?: number;
  code_snippet?: string;
  remediation: string;
  tool_name?: string;
  resource_name?: string;
}

export interface McpPermissions {
  file_access: boolean;
  network_access: boolean;
  code_execution: boolean;
  database_access: boolean;
  environment_access: boolean;
  file_system_paths?: string[];
  network_hosts?: string[];
  execution_types?: string[];
  scope: string; // "minimal", "moderate", "extensive", "unrestricted"
}

export interface McpToolAnalysis {
  name: string;
  description?: string;
  risk_level: string; // "safe", "moderate", "dangerous"
  risk_reasons?: string[];
  input_schema?: unknown;
  output_schema?: unknown;
  has_input_validation: boolean;
  has_rate_limiting: boolean;
  has_access_control: boolean;
  attack_vectors?: string[];
  finding_ids?: string[];
}

export interface McpAuditResponse {
  success: boolean;
  server: McpServerInfo;
  audit_results: McpAuditResults;
  findings: McpFinding[];
  permissions: McpPermissions;
  tools: McpToolAnalysis[];
  recommendations: string[];
  report_id?: string;
  generated_at: string;

  // Data source transparency
  data_source?: 'registry' | 'known_servers';
  cache_warning?: string;

  // Legacy compatibility
  serverInfo?: McpServerInfo;
  securityScore?: number;
  issues?: McpFinding[];
}

// =============================================================================
// MLBOM Types (Machine Learning Bill of Materials)
// =============================================================================

export interface MLBOMSummary {
  total_components: number;
  models: number;
  frameworks: number;
  tools: number;
  dependencies: number;
  data_sources: number;
}

export interface MLBOMSupplier {
  name: string;
  url?: string;
  contact?: string;
}

export interface MLBOMExternalRef {
  type: string; // "purl", "website", "documentation"
  url: string;
}

export interface MLBOMComponent {
  type: string; // "model", "framework", "tool", "dependency", "data-source"
  name: string;
  version?: string;
  supplier?: MLBOMSupplier;
  description?: string;
  licenses?: string[];
  external_refs?: MLBOMExternalRef[];
  properties?: Record<string, string>;
}

export interface MlbomCompleteness {
  from_topology: number;
  from_findings: number;
  topology_nodes: number;
  findings_count: number;
}

export interface MlbomResponse {
  success: boolean;
  format: MlbomFormat;
  bom: unknown; // CycloneDX or SPDX structure
  summary: MLBOMSummary;
  report_id?: string;
  generated_at: string;

  // Completeness tracking
  completeness?: MlbomCompleteness;
  warning?: string;

  // Legacy compatibility
  components?: MLBOMComponent[];
  version?: string;
  generatedAt?: string;
}

// =============================================================================
// A2A (Agent-to-Agent) Audit Types
// =============================================================================

export type A2AProtocol = 'a2a' | 'crewai' | 'langgraph' | 'autogen' | 'custom' | 'unknown';

export interface A2AAgent {
  id: string;
  name: string;
  role?: string;
  description?: string;
  /** Tools available to this agent. May be null from API - use safeArray() */
  tools: string[] | null;
  /** Agents this agent can delegate to. May be null from API - use safeArray() */
  delegation_targets: string[] | null;
  file?: string;
  line?: number;
  can_delegate: boolean;
  can_receive_message: boolean;
  has_memory: boolean;
  has_auth_check: boolean;
  has_rate_limiting: boolean;
  trust_level?: string;
}

export interface A2ACommunication {
  from: string;
  to: string;
  type: string; // "delegation", "message", "task", "broadcast"
  has_guards: boolean;
  has_auth: boolean;
  is_async: boolean;
  max_depth?: number;
  file?: string;
  line?: number;
}

export interface A2AFinding {
  id: string;
  type: string; // "infinite-delegation", "missing-auth", "privilege-escalation"
  severity: string;
  description: string;
  /** Agents involved in this finding. May be null from API - use safeArray() */
  agents_involved: string[] | null;
  file?: string;
  line?: number;
  remediation: string;
}

export interface A2ATrustBoundary {
  id: string;
  name: string;
  trust_level: string;
  /** Agents within this trust boundary. May be null from API - use safeArray() */
  agent_ids: string[] | null;
  description?: string;
}

export interface A2ATrustAnalysis {
  /** Trust boundaries in the system. May be null from API - use safeArray() */
  trust_boundaries: A2ATrustBoundary[] | null;
  cross_boundary_flows: number;
  unguarded_delegations: number;
  privilege_escalations: number;
  circular_delegations?: string[][];
}

export interface A2ARiskAssessment {
  overall_risk: string;
  trust_boundary_violations: number;
  unguarded_delegations: number;
  critical_findings: number;
  high_findings: number;
  summary: string;
  /** Recommendations for improving security. May be null from API - use safeArray() */
  recommendations: string[] | null;
}

export interface A2AAuditResponse {
  success: boolean;
  protocol: A2AProtocol;
  /** Detected agents. May be null from API - use safeArray() */
  agents: A2AAgent[] | null;
  /** Communication channels between agents. May be null from API - use safeArray() */
  communications: A2ACommunication[] | null;
  /** Security findings. May be null from API - use safeArray() */
  findings: A2AFinding[] | null;
  trust_analysis: A2ATrustAnalysis | null;
  risk_assessment: A2ARiskAssessment | null;
  report_id?: string;
  generated_at: string;

  // Warnings for incomplete analysis
  warning?: string;

  // Legacy compatibility
  delegationGraph?: A2ACommunication[];
  issues?: A2AFinding[];
  securityScore?: number;
  hasCycles?: boolean;
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
