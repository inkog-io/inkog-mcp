/**
 * inkog_explain_finding Tool
 *
 * P1 - Finding Explanation and Remediation Guidance
 *
 * Provides detailed explanations for security findings including:
 * - What the vulnerability is
 * - Why it's dangerous
 * - How to fix it
 * - Code examples (vulnerable vs secure)
 */

import { z } from 'zod';

import { getClient, InkogAuthError, InkogNetworkError } from '../api/client.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const ExplainArgsSchema = z
  .object({
    finding_id: z
      .string()
      .optional()
      .describe('Finding ID from scan results (e.g., "f8a3b2c1")'),
    pattern: z
      .string()
      .optional()
      .describe(
        'Pattern name: prompt-injection, infinite-loop, sql-injection-llm, token-bombing, hardcoded-credentials, missing-rate-limits, recursive-delegation, etc.'
      ),
  })
  .refine((data) => data.finding_id !== undefined || data.pattern !== undefined, {
    message: 'Either finding_id or pattern must be provided',
  });

type ExplainArgs = z.infer<typeof ExplainArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function formatSeverityBadge(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return '🔴 CRITICAL';
    case 'HIGH':
      return '🟠 HIGH';
    case 'MEDIUM':
      return '🟡 MEDIUM';
    case 'LOW':
      return '🟢 LOW';
    default:
      return severity;
  }
}

function formatRiskTier(tier: string): string {
  switch (tier) {
    case 'vulnerability':
      return '🔴 Exploitable Vulnerability';
    case 'risk_pattern':
      return '🟠 Risk Pattern';
    case 'hardening':
      return '🟡 Hardening Recommendation';
    default:
      return tier;
  }
}

// =============================================================================
// Handler
// =============================================================================

async function explainHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = ExplainArgsSchema.safeParse(rawArgs);
  if (!parseResult.success) {
    return {
      content: [
        {
          type: 'text',
          text: `Invalid arguments: ${parseResult.error.message}\n\nProvide either finding_id (from scan results) or pattern name.`,
        },
      ],
      isError: true,
    };
  }

  const args: ExplainArgs = parseResult.data;

  try {
    // Call Inkog API
    const client = getClient();
    const explainOptions: { findingId?: string; pattern?: string } = {};
    if (args.finding_id !== undefined) {
      explainOptions.findingId = args.finding_id;
    }
    if (args.pattern !== undefined) {
      explainOptions.pattern = args.pattern;
    }
    const response = await client.explainFinding(explainOptions);

    // Build formatted output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           📖 Security Finding Explanation             ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // Title and metadata
    output += `🔍 ${response.title}\n`;
    output += `   Pattern: ${response.pattern}\n`;
    output += `   Severity: ${formatSeverityBadge(response.severity)}\n`;
    output += `   Category: ${formatRiskTier(response.riskTier)}\n`;

    if (response.cwe !== undefined) {
      output += `   CWE: ${response.cwe}\n`;
    }
    if (response.owaspLlm !== undefined) {
      output += `   OWASP LLM: ${response.owaspLlm}\n`;
    }

    output += '\n';

    // Description
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📝 DESCRIPTION\n\n';
    output += response.description + '\n\n';

    // Explanation
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '🔬 WHY THIS IS DANGEROUS\n\n';
    output += response.explanation + '\n\n';

    // Impact
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '💥 POTENTIAL IMPACT\n\n';
    output += response.impact + '\n\n';

    // Remediation steps
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '🔧 HOW TO FIX\n\n';

    for (const step of response.remediationSteps) {
      output += `${step.order}. ${step.description}\n`;
      if (step.codeExample !== undefined) {
        const lang = step.language ?? '';
        output += `\n\`\`\`${lang}\n${step.codeExample}\n\`\`\`\n\n`;
      }
    }

    // Code examples
    if (response.codeExamples !== undefined) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📝 CODE EXAMPLES\n\n';

      output += '❌ Vulnerable:\n';
      output += `\`\`\`${response.codeExamples.language}\n${response.codeExamples.vulnerable}\n\`\`\`\n\n`;

      output += '✅ Secure:\n';
      output += `\`\`\`${response.codeExamples.language}\n${response.codeExamples.secure}\n\`\`\`\n\n`;
    }

    // References
    if (response.references.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📚 REFERENCES\n\n';
      for (const ref of response.references) {
        output += `• ${ref}\n`;
      }
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

export const explainTool: ToolDefinition = {
  tool: {
    name: 'inkog_explain_finding',
    description:
      'Get detailed explanation and remediation guidance for a security finding or pattern. Includes what the issue is, why it\'s dangerous, step-by-step fixes, and code examples.',
    inputSchema: {
      type: 'object',
      properties: {
        finding_id: {
          type: 'string',
          description: 'Finding ID from scan results (e.g., "f8a3b2c1")',
        },
        pattern: {
          type: 'string',
          description:
            'Pattern name: prompt-injection, infinite-loop, sql-injection-llm, token-bombing, hardcoded-credentials, missing-rate-limits, recursive-delegation, etc.',
        },
      },
    },
  },
  handler: explainHandler,
};
