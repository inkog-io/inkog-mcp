/**
 * inkog_scan Tool
 *
 * P0 - Core vulnerability scanning tool
 *
 * Scans AI agent code for security vulnerabilities including:
 * - Prompt injection
 * - Infinite loops / token bombing
 * - SQL injection via LLM
 * - Hardcoded credentials
 * - Missing governance controls
 */

import { z } from 'zod';

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type { Finding, SecurityPolicy } from '../api/types.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const ScanArgsSchema = z.object({
  path: z.string().describe('File or directory path to scan'),
  policy: z
    .enum(['low-noise', 'balanced', 'comprehensive', 'governance', 'eu-ai-act'])
    .optional()
    .default('balanced')
    .describe(
      'Security policy: low-noise (proven vulnerabilities only), balanced (default), comprehensive (all findings), governance (Article 14 focused), eu-ai-act (compliance mode)'
    ),
  output: z
    .enum(['summary', 'detailed', 'sarif'])
    .optional()
    .default('summary')
    .describe('Output format: summary (default), detailed (full findings), sarif (for CI/CD)'),
});

type ScanArgs = z.infer<typeof ScanArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function formatSeverityIcon(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return '🔴';
    case 'HIGH':
      return '🟠';
    case 'MEDIUM':
      return '🟡';
    case 'LOW':
      return '🟢';
    default:
      return '⚪';
  }
}

function formatRiskTier(tier: string): string {
  switch (tier) {
    case 'vulnerability':
      return 'Exploitable Vulnerability';
    case 'risk_pattern':
      return 'Risk Pattern';
    case 'hardening':
      return 'Hardening Recommendation';
    default:
      return tier;
  }
}

function formatFinding(finding: Finding, detailed: boolean): string {
  const icon = formatSeverityIcon(finding.severity);
  const tierLabel = formatRiskTier(finding.riskTier);
  const location = `${finding.file}:${finding.line}`;

  let output = `${icon} [${finding.severity}] ${finding.message}\n`;
  output += `   📍 ${location}\n`;
  output += `   📊 ${tierLabel}`;

  if (finding.cwe !== undefined) {
    output += ` | ${finding.cwe}`;
  }

  if (finding.inputTainted && finding.taintSource !== undefined) {
    output += `\n   ⚠️  Taint source: ${finding.taintSource}`;
  }

  if (detailed && finding.remediation !== undefined) {
    output += `\n   💡 ${finding.remediation}`;
  }

  if (detailed && finding.codeSnippet !== undefined) {
    output += `\n   \`\`\`\n   ${finding.codeSnippet}\n   \`\`\``;
  }

  return output;
}

function formatSummary(
  findings: Finding[],
  riskScore: number,
  filesScanned: number,
  policy: SecurityPolicy
): string {
  const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const medium = findings.filter((f) => f.severity === 'MEDIUM').length;
  const low = findings.filter((f) => f.severity === 'LOW').length;

  const vulnerabilities = findings.filter((f) => f.riskTier === 'vulnerability').length;
  const riskPatterns = findings.filter((f) => f.riskTier === 'risk_pattern').length;
  const hardening = findings.filter((f) => f.riskTier === 'hardening').length;

  let output = '╔══════════════════════════════════════════════════════╗\n';
  output += '║           🔍 AI Agent Risk Assessment                ║\n';
  output += '╚══════════════════════════════════════════════════════╝\n\n';

  output += `📁 Files scanned: ${filesScanned}\n`;
  output += `📊 Risk score: ${riskScore}/100\n`;
  output += `🔒 Policy: ${policy}\n\n`;

  if (findings.length === 0) {
    output += '✅ No security findings detected!\n';
    return output;
  }

  output += `📋 Total findings: ${findings.length}\n`;
  output += `   🔴 Critical: ${critical} | 🟠 High: ${high} | 🟡 Medium: ${medium} | 🟢 Low: ${low}\n\n`;

  if (vulnerabilities > 0) {
    output += `🔴 EXPLOITABLE VULNERABILITIES (${vulnerabilities})\n`;
    output +=
      '   Require immediate attention - proven attack paths\n\n';
  }

  if (riskPatterns > 0) {
    output += `🟠 RISK PATTERNS (${riskPatterns})\n`;
    output += '   Structural issues that could become vulnerabilities\n\n';
  }

  if (hardening > 0) {
    output += `🟡 HARDENING RECOMMENDATIONS (${hardening})\n`;
    output += '   Best practices for improved security posture\n\n';
  }

  return output;
}

// =============================================================================
// Handler
// =============================================================================

async function scanHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = ScanArgsSchema.safeParse(rawArgs);
  if (!parseResult.success) {
    return {
      content: [
        {
          type: 'text',
          text: `Invalid arguments: ${parseResult.error.message}`,
        },
      ],
      isError: true,
    };
  }

  const args: ScanArgs = parseResult.data;

  try {
    // Read files from path
    const readResult = readDirectory(args.path);

    if (readResult.files.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No scannable files found in: ${args.path}\n\nSupported file types: .py, .js, .ts, .go, .java, .rb, .yaml, .json, .md`,
          },
        ],
      };
    }

    // Get relative paths for cleaner output
    const files = getRelativePaths(readResult.files, args.path);

    // Call Inkog API
    const client = getClient();
    const response = await client.scan(files, {
      policy: args.policy,
      output: args.output,
    });

    // Format output based on requested format
    if (args.output === 'sarif') {
      // Return raw SARIF for CI/CD integration
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(response, null, 2),
          },
        ],
      };
    }

    // Build human-readable output
    const findings = response.findings ?? [];
    let output = formatSummary(
      findings,
      response.risk_score,
      response.files_scanned,
      args.policy
    );

    // Add findings
    if (findings.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';

      // Group by tier
      const vulnerabilities = findings.filter((f) => f.riskTier === 'vulnerability');
      const riskPatterns = findings.filter((f) => f.riskTier === 'risk_pattern');
      const hardening = findings.filter((f) => f.riskTier === 'hardening');

      if (vulnerabilities.length > 0) {
        output += '🔴 EXPLOITABLE VULNERABILITIES:\n\n';
        for (const finding of vulnerabilities) {
          output += formatFinding(finding, args.output === 'detailed') + '\n\n';
        }
      }

      if (riskPatterns.length > 0) {
        output += '🟠 RISK PATTERNS:\n\n';
        for (const finding of riskPatterns) {
          output += formatFinding(finding, args.output === 'detailed') + '\n\n';
        }
      }

      if (hardening.length > 0 && args.policy === 'comprehensive') {
        output += '🟡 HARDENING RECOMMENDATIONS:\n\n';
        for (const finding of hardening) {
          output += formatFinding(finding, args.output === 'detailed') + '\n\n';
        }
      }
    }

    // Add governance summary if available
    const governance = response.governance;
    if (governance !== undefined) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🏛️  GOVERNANCE STATUS\n\n';
      output += `   Governance Score: ${governance.governanceScore}/100\n`;
      output += `   EU AI Act Readiness: ${governance.euAiActReadiness}\n`;
    }

    return {
      content: [
        {
          type: 'text',
          text: output,
        },
      ],
    };
  } catch (error) {
    if (error instanceof InkogAuthError) {
      return {
        content: [
          {
            type: 'text',
            text: '🔐 API Key Required\n\nTo use Inkog, you need an API key.\n\n1. Sign up for free at https://app.inkog.io\n2. Set your API key: export INKOG_API_KEY=sk_live_...\n3. Try again!',
          },
        ],
        isError: true,
      };
    }

    if (error instanceof InkogRateLimitError) {
      return {
        content: [
          {
            type: 'text',
            text: `⏱️ Rate Limited\n\nToo many requests. Please retry after ${error.retryAfter} seconds.`,
          },
        ],
        isError: true,
      };
    }

    if (error instanceof InkogNetworkError) {
      return {
        content: [
          {
            type: 'text',
            text: `Network error: ${error.message}\n\nPlease check your internet connection and try again.`,
          },
        ],
        isError: true,
      };
    }

    if (error instanceof InkogApiError) {
      return {
        content: [
          {
            type: 'text',
            text: `API error: ${error.message}${error.details ? `\n\nDetails: ${JSON.stringify(error.details)}` : ''}`,
          },
        ],
        isError: true,
      };
    }

    const message = error instanceof Error ? error.message : 'Unknown error occurred';
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${message}`,
        },
      ],
      isError: true,
    };
  }
}

// =============================================================================
// Tool Definition
// =============================================================================

export const scanTool: ToolDefinition = {
  tool: {
    name: 'inkog_scan',
    description:
      'Scan AI agent code for security vulnerabilities including prompt injection, infinite loops, token bombing, SQL injection via LLM, and governance gaps. Supports LangChain, CrewAI, LangGraph, n8n, and other agent frameworks.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'File or directory path to scan',
        },
        policy: {
          type: 'string',
          enum: ['low-noise', 'balanced', 'comprehensive', 'governance', 'eu-ai-act'],
          default: 'balanced',
          description:
            'Security policy: low-noise (proven vulnerabilities only), balanced (default), comprehensive (all findings), governance (Article 14 focused), eu-ai-act (compliance mode)',
        },
        output: {
          type: 'string',
          enum: ['summary', 'detailed', 'sarif'],
          default: 'summary',
          description:
            'Output format: summary (default), detailed (full findings), sarif (for CI/CD)',
        },
      },
      required: ['path'],
    },
  },
  handler: scanHandler,
};
