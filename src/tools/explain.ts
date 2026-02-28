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

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
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

// formatRiskTier removed - now using response.category directly

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
    output += `   Pattern: ${response.pattern_id}\n`;
    output += `   Severity: ${formatSeverityBadge(response.severity)}\n`;
    output += `   Category: ${response.category}\n`;

    // CWE - backend sends as array
    if (response.cwe !== undefined && response.cwe.length > 0) {
      output += `   CWE: ${response.cwe.join(', ')}\n`;
    }
    // OWASP - backend sends as array
    if (response.owasp !== undefined && response.owasp.length > 0) {
      output += `   OWASP LLM: ${response.owasp.join(', ')}\n`;
    }

    output += '\n';

    // Description
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📝 DESCRIPTION\n\n';
    output += response.description + '\n\n';

    // Impact
    if (response.impact) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💥 POTENTIAL IMPACT\n\n';
      output += response.impact + '\n\n';
    }

    // Remediation
    if (response.remediation) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔧 HOW TO FIX\n\n';
      output += response.remediation + '\n\n';
    }

    // Remediation steps - backend sends as string[]
    if (response.remediation_steps && response.remediation_steps.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📋 REMEDIATION STEPS\n\n';
      for (let i = 0; i < response.remediation_steps.length; i++) {
        output += `${i + 1}. ${response.remediation_steps[i]}\n`;
      }
      output += '\n';
    }

    // Code examples - backend sends as examples: { vulnerable, secure }
    if (response.examples !== undefined) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📝 CODE EXAMPLES\n\n';

      output += '❌ Vulnerable:\n';
      output += `\`\`\`\n${response.examples.vulnerable}\n\`\`\`\n\n`;

      output += '✅ Secure:\n';
      output += `\`\`\`\n${response.examples.secure}\n\`\`\`\n\n`;
    }

    // References - backend sends as { title, url }[]
    if (response.references !== undefined && response.references.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📚 REFERENCES\n\n';
      for (const ref of response.references) {
        output += `• ${ref.title}: ${ref.url}\n`;
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

export const explainTool: ToolDefinition = {
  tool: {
    name: 'inkog_explain_finding',
    description:
      'Get detailed explanation and remediation guidance for a security finding or pattern. Includes what the issue is, why it\'s dangerous, step-by-step fixes, and code examples. Use this after scanning to understand how to fix security findings.',
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
