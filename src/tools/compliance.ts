/**
 * inkog_compliance_report Tool
 *
 * P1 - Compliance Report Generation
 *
 * Generates compliance reports for regulatory frameworks:
 * - EU AI Act (Articles 12, 14, 15)
 * - NIST AI Risk Management Framework
 * - ISO 42001 AI Management System
 * - OWASP LLM Top 10
 */

import { z } from 'zod';

import { getClient, InkogAuthError, InkogNetworkError } from '../api/client.js';
import type { ComplianceArticle, ComplianceFramework } from '../api/types.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const ComplianceArgsSchema = z.object({
  path: z.string().describe('Path to scan for compliance analysis'),
  framework: z
    .enum(['eu-ai-act', 'nist-ai-rmf', 'iso-42001', 'owasp-llm-top-10', 'all'])
    .optional()
    .default('eu-ai-act')
    .describe(
      'Compliance framework: eu-ai-act (default), nist-ai-rmf, iso-42001, owasp-llm-top-10, or all'
    ),
  format: z
    .enum(['markdown', 'json', 'pdf'])
    .optional()
    .default('markdown')
    .describe('Output format: markdown (default), json, or pdf'),
});

type ComplianceArgs = z.infer<typeof ComplianceArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function getFrameworkDisplayName(framework: ComplianceFramework | 'all'): string {
  switch (framework) {
    case 'eu-ai-act':
      return 'EU AI Act';
    case 'nist-ai-rmf':
      return 'NIST AI Risk Management Framework';
    case 'iso-42001':
      return 'ISO 42001 AI Management System';
    case 'owasp-llm-top-10':
      return 'OWASP LLM Top 10';
    case 'all':
      return 'All Frameworks';
    default:
      return framework;
  }
}

function getStatusIcon(status: string): string {
  switch (status) {
    case 'COMPLIANT':
      return '✅';
    case 'NON_COMPLIANT':
      return '❌';
    case 'PARTIAL':
      return '⚠️';
    case 'NOT_APPLICABLE':
      return '➖';
    default:
      return '❓';
  }
}

function formatArticle(article: ComplianceArticle): string {
  const icon = getStatusIcon(article.status);
  let output = `${icon} ${article.id}: ${article.title}\n`;
  output += `   Status: ${article.status}\n`;

  if (article.findings.length > 0) {
    output += `   Findings: ${article.findings.length}\n`;
    for (const finding of article.findings.slice(0, 3)) {
      output += `     • ${finding.message} (${finding.file}:${finding.line})\n`;
    }
    if (article.findings.length > 3) {
      output += `     ... and ${article.findings.length - 3} more\n`;
    }
  }

  if (article.recommendations.length > 0) {
    output += `   Recommendations:\n`;
    for (const rec of article.recommendations) {
      output += `     💡 ${rec}\n`;
    }
  }

  return output;
}

// =============================================================================
// Handler
// =============================================================================

async function complianceHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = ComplianceArgsSchema.safeParse(rawArgs);
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

  const args: ComplianceArgs = parseResult.data;

  try {
    // Read files from path
    const readResult = readDirectory(args.path);

    if (readResult.files.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No scannable files found in: ${args.path}`,
          },
        ],
        isError: true,
      };
    }

    // Get relative paths
    const files = getRelativePaths(readResult.files, args.path);

    // Call Inkog API
    const client = getClient();
    const response = await client.generateComplianceReport(files, {
      framework: args.framework,
      format: args.format,
    });

    // If format is markdown or pdf, return the pre-formatted content
    if (args.format !== 'json' && response.reportContent !== undefined) {
      return {
        content: [
          {
            type: 'text',
            text: response.reportContent,
          },
        ],
      };
    }

    // Build formatted output
    const frameworkName = getFrameworkDisplayName(response.framework);
    const overallIcon = getStatusIcon(response.overallStatus);

    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           📋 Compliance Report                        ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    output += `🏛️  Framework: ${frameworkName}\n`;
    output += `📊 Compliance Score: ${response.complianceScore}/100\n`;
    output += `${overallIcon} Overall Status: ${response.overallStatus}\n`;
    output += `📅 Generated: ${response.generatedAt}\n\n`;

    // Executive Summary
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📝 EXECUTIVE SUMMARY\n\n';
    output += response.executiveSummary + '\n\n';

    // Article breakdown
    if (response.articles.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📑 ARTICLE BREAKDOWN\n\n';

      // Group by status
      const compliant = response.articles.filter((a) => a.status === 'COMPLIANT');
      const nonCompliant = response.articles.filter((a) => a.status === 'NON_COMPLIANT');
      const partial = response.articles.filter((a) => a.status === 'PARTIAL');

      if (nonCompliant.length > 0) {
        output += '❌ NON-COMPLIANT:\n\n';
        for (const article of nonCompliant) {
          output += formatArticle(article) + '\n';
        }
      }

      if (partial.length > 0) {
        output += '⚠️  PARTIAL COMPLIANCE:\n\n';
        for (const article of partial) {
          output += formatArticle(article) + '\n';
        }
      }

      if (compliant.length > 0) {
        output += '✅ COMPLIANT:\n\n';
        for (const article of compliant) {
          output += `   ${article.id}: ${article.title}\n`;
        }
        output += '\n';
      }
    }

    // EU AI Act specific note
    if (response.framework === 'eu-ai-act') {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📌 EU AI ACT NOTE\n\n';
      output += 'Article 14 (Human Oversight) deadline: August 2, 2026\n';
      output += 'Ensure all high-risk AI systems have:\n';
      output += '• Human-in-the-loop controls\n';
      output += '• Ability to interrupt operations\n';
      output += '• Audit logging of all actions\n';
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
            text: '🔐 API Key Required\n\nGet your free key at https://app.inkog.io',
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
            text: `Network error: ${error.message}`,
          },
        ],
        isError: true,
      };
    }

    throw error;
  }
}

// =============================================================================
// Tool Definition
// =============================================================================

export const complianceTool: ToolDefinition = {
  tool: {
    name: 'inkog_compliance_report',
    description:
      'Generate a compliance report for EU AI Act, NIST AI RMF, ISO 42001, or OWASP LLM Top 10. Analyzes agent code and maps findings to regulatory requirements.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to scan for compliance analysis',
        },
        framework: {
          type: 'string',
          enum: ['eu-ai-act', 'nist-ai-rmf', 'iso-42001', 'owasp-llm-top-10', 'all'],
          default: 'eu-ai-act',
          description:
            'Compliance framework: eu-ai-act (default), nist-ai-rmf, iso-42001, owasp-llm-top-10, or all',
        },
        format: {
          type: 'string',
          enum: ['markdown', 'json', 'pdf'],
          default: 'markdown',
          description: 'Output format: markdown (default), json, or pdf',
        },
      },
      required: ['path'],
    },
  },
  handler: complianceHandler,
};
