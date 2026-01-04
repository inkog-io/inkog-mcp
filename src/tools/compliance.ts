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

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type {
  ComplianceArticle,
  ComplianceCategory,
  ComplianceFramework,
  ComplianceRecommendation,
} from '../api/types.js';
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

function getFrameworkDisplayName(framework: ComplianceFramework | string): string {
  switch (framework) {
    case 'eu-ai-act':
      return 'EU AI Act';
    case 'nist-ai-rmf':
      return 'NIST AI Risk Management Framework';
    case 'iso-42001':
      return 'ISO 42001 AI Management System';
    case 'owasp-llm-top-10':
      return 'OWASP LLM Top 10';
    default:
      return framework;
  }
}

function getStatusIcon(status: string): string {
  const lower = status.toLowerCase();
  switch (lower) {
    case 'compliant':
    case 'pass':
      return '✅';
    case 'non-compliant':
    case 'non_compliant':
    case 'fail':
      return '❌';
    case 'partial':
      return '⚠️';
    case 'not_applicable':
    case 'n/a':
      return '➖';
    default:
      return '❓';
  }
}

function getRiskLevelIcon(level: string): string {
  const lower = level.toLowerCase();
  switch (lower) {
    case 'critical':
      return '🔴';
    case 'high':
      return '🟠';
    case 'medium':
      return '🟡';
    case 'low':
      return '🟢';
    default:
      return '⚪';
  }
}

function formatScore(score: number): string {
  if (score >= 90) {
    return `✅ ${score}/100 (Excellent)`;
  } else if (score >= 70) {
    return `🟢 ${score}/100 (Good)`;
  } else if (score >= 50) {
    return `🟡 ${score}/100 (Fair)`;
  } else if (score >= 30) {
    return `🟠 ${score}/100 (Poor)`;
  } else {
    return `🔴 ${score}/100 (Critical)`;
  }
}

function formatArticle(article: ComplianceArticle): string {
  const icon = getStatusIcon(article.status);
  let output = `${icon} ${article.id}: ${article.title}\n`;
  output += `   Status: ${article.status} | Score: ${article.score}/100\n`;

  if (article.requirements && article.requirements.length > 0) {
    output += `   Requirements:\n`;
    for (const req of article.requirements) {
      output += `     • ${req}\n`;
    }
  }

  // findings is an array of finding IDs (strings)
  if (article.findings && article.findings.length > 0) {
    output += `   Related Findings: ${article.findings.length}\n`;
    for (const findingId of article.findings.slice(0, 3)) {
      output += `     • ${findingId}\n`;
    }
    if (article.findings.length > 3) {
      output += `     ... and ${article.findings.length - 3} more\n`;
    }
  }

  if (article.remediation) {
    output += `   💡 Remediation: ${article.remediation}\n`;
  }

  return output;
}

function formatCategory(category: ComplianceCategory): string {
  const icon = getStatusIcon(category.status);
  let output = `${icon} ${category.id}: ${category.name}\n`;
  output += `   Status: ${category.status}\n`;

  if (category.description) {
    output += `   ${category.description}\n`;
  }

  if (category.finding_ids && category.finding_ids.length > 0) {
    output += `   Related Findings: ${category.finding_ids.length}\n`;
  }

  if (category.impact) {
    output += `   Impact: ${category.impact}\n`;
  }

  return output;
}

function formatRecommendation(rec: ComplianceRecommendation, index: number): string {
  let output = `${index + 1}. [${rec.priority.toUpperCase()}] ${rec.title}\n`;
  output += `   ${rec.description}\n`;
  if (rec.article) {
    output += `   Article: ${rec.article}\n`;
  }
  if (rec.effort) {
    output += `   Effort: ${rec.effort}\n`;
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

    // Call Inkog API - first scan, then generate compliance report
    const client = getClient();

    // Step 1: Run a scan to get a scan_id
    const scanResponse = await client.scan(files, { policy: 'balanced' });
    if (!scanResponse.success || !scanResponse.scan_id) {
      return {
        content: [
          {
            type: 'text',
            text: 'Scan failed: Unable to analyze files',
          },
        ],
        isError: true,
      };
    }

    // Step 2: Use scan_id to generate compliance report
    const response = await client.generateComplianceReport({
      scanId: scanResponse.scan_id,
      framework: args.framework,
      format: args.format,
    });

    // If format is markdown or pdf and there's a pre-formatted report, return it
    if (args.format !== 'json' && response.markdown_report) {
      return {
        content: [
          {
            type: 'text',
            text: response.markdown_report,
          },
        ],
      };
    }

    // Build formatted output
    const frameworkName = getFrameworkDisplayName(response.framework);

    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           📋 Compliance Report                        ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    output += `🏛️  Framework: ${frameworkName}\n`;
    output += `📊 Compliance Score: ${formatScore(response.overall_score ?? 0)}\n`;
    const riskLevel = response.risk_level ?? 'unknown';
    output += `${getRiskLevelIcon(riskLevel)} Risk Level: ${riskLevel.toUpperCase()}\n`;
    output += `📅 Generated: ${response.generated_at ?? new Date().toISOString()}\n`;
    if (response.report_id) {
      output += `🔗 Report ID: ${response.report_id}\n`;
    }
    output += '\n';

    // Findings summary
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📊 FINDINGS SUMMARY\n\n';
    const fs = response.findings_summary ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    output += `   Total: ${fs.total ?? 0}\n`;
    output += `   🔴 Critical: ${fs.critical ?? 0} | 🟠 High: ${fs.high ?? 0} | 🟡 Medium: ${fs.medium ?? 0} | 🟢 Low: ${fs.low ?? 0}\n\n`;

    // Article breakdown (for EU AI Act, NIST, ISO)
    const articles = response.articles ?? [];
    if (articles.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📑 ARTICLE BREAKDOWN\n\n';

      // Group by status
      const compliant = articles.filter((a) => a.status.toLowerCase() === 'compliant');
      const nonCompliant = articles.filter((a) =>
        a.status.toLowerCase() === 'non-compliant' || a.status.toLowerCase() === 'non_compliant'
      );
      const partial = articles.filter((a) => a.status.toLowerCase() === 'partial');

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
          output += `   ${article.id}: ${article.title} (${article.score}/100)\n`;
        }
        output += '\n';
      }
    }

    // Category breakdown (for OWASP)
    const categories = response.categories ?? [];
    if (categories.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📂 CATEGORY BREAKDOWN\n\n';

      const passing = categories.filter((c) => c.status.toLowerCase() === 'pass');
      const failing = categories.filter((c) => c.status.toLowerCase() === 'fail');
      const partialCats = categories.filter((c) => c.status.toLowerCase() === 'partial');

      if (failing.length > 0) {
        output += '❌ FAILING:\n\n';
        for (const cat of failing) {
          output += formatCategory(cat) + '\n';
        }
      }

      if (partialCats.length > 0) {
        output += '⚠️  PARTIAL:\n\n';
        for (const cat of partialCats) {
          output += formatCategory(cat) + '\n';
        }
      }

      if (passing.length > 0) {
        output += '✅ PASSING:\n\n';
        for (const cat of passing) {
          output += `   ${cat.id}: ${cat.name}\n`;
        }
        output += '\n';
      }
    }

    // Recommendations
    const recommendations = response.recommendations ?? [];
    if (recommendations.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💡 RECOMMENDATIONS\n\n';

      // Sort by priority
      const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...recommendations].sort((a, b) =>
        (priorityOrder[a.priority.toLowerCase()] ?? 4) - (priorityOrder[b.priority.toLowerCase()] ?? 4)
      );

      for (const [index, rec] of sorted.entries()) {
        output += formatRecommendation(rec, index) + '\n';
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
      output += '• Audit logging of all actions\n\n';
    }

    // Footer
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n';
    output += 'Compliance Report powered by Inkog AI Security Platform\n';
    output += 'Learn more: https://inkog.io/compliance\n';

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
            text: `Network error: ${error.message}`,
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
