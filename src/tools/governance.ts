/**
 * inkog_verify_governance Tool
 *
 * P0 - AGENTS.md Governance Verification (THE MOAT)
 *
 * Validates that AGENTS.md declarations match actual code behavior.
 * Detects governance mismatches like:
 * - "Read-only" declared but code writes data
 * - "No external API" declared but code makes HTTP requests
 * - "Human approval required" declared but no approval gates in code
 *
 * This is Inkog's unique differentiator - no other tool does this.
 */

import { z } from 'zod';

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type { DeclaredCapability, GovernanceMismatch } from '../api/types.js';
import { findAgentsMd, getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const GovernanceArgsSchema = z.object({
  path: z.string().describe('Path to directory containing AGENTS.md and agent code'),
});

type GovernanceArgs = z.infer<typeof GovernanceArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function formatSeverityIcon(severity: string): string {
  const upper = severity.toUpperCase();
  switch (upper) {
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

function formatMismatch(mismatch: GovernanceMismatch): string {
  const icon = formatSeverityIcon(mismatch.severity);

  let output = `${icon} GOVERNANCE MISMATCH [${mismatch.severity.toUpperCase()}]\n`;
  output += `   📍 ${mismatch.file}:${mismatch.line}\n`;
  output += `   🎯 Capability: ${mismatch.capability}\n`;
  output += `   📜 Expected: "${mismatch.expected}"\n`;
  output += `   ⚠️  Actual: "${mismatch.actual}"\n`;

  if (mismatch.evidence) {
    output += `   📝 Evidence: ${mismatch.evidence}\n`;
  }

  return output;
}

function formatCapability(cap: DeclaredCapability): string {
  const statusIcon = cap.status === 'valid' ? '✅' :
                     cap.status === 'violated' ? '❌' : '⚪';

  let output = `${statusIcon} ${cap.name}`;
  if (cap.constraint_type) {
    output += ` [${cap.constraint_type}]`;
  }
  output += '\n';

  if (cap.description) {
    output += `      ${cap.description}\n`;
  }

  if (cap.line) {
    output += `      Line: ${cap.line}\n`;
  }

  return output;
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

function formatOverallStatus(status: string): string {
  switch (status.toLowerCase()) {
    case 'valid':
      return '✅ Valid';
    case 'invalid':
      return '❌ Invalid';
    case 'partial':
      return '⚠️  Partial';
    default:
      return status;
  }
}

// =============================================================================
// Handler
// =============================================================================

async function governanceHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = GovernanceArgsSchema.safeParse(rawArgs);
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

  const args: GovernanceArgs = parseResult.data;

  try {
    // Check for AGENTS.md
    const agentsMdPath = findAgentsMd(args.path);

    // Read files from path
    const readResult = readDirectory(args.path);

    if (readResult.files.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No files found in: ${args.path}`,
          },
        ],
        isError: true,
      };
    }

    // Get relative paths for cleaner output
    const files = getRelativePaths(readResult.files, args.path);

    // Call Inkog API - first scan, then verify governance
    const client = getClient();

    // Step 1: Run a scan to get a scan_id
    const scanResponse = await client.scan(files, { policy: 'governance' });
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

    // Step 2: Use scan_id to verify governance
    const response = await client.verifyGovernance({ scanId: scanResponse.scan_id });

    // Build output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║        🏛️  AGENTS.md Governance Verification          ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // AGENTS.md status
    const hasAgentsMd = response.hasAgentsMd ?? (agentsMdPath !== null);
    if (hasAgentsMd) {
      output += `✅ AGENTS.md found: ${agentsMdPath ?? 'AGENTS.md'}\n\n`;
    } else {
      output += '⚠️  No AGENTS.md file found\n\n';
      output +=
        'AGENTS.md is a governance declaration file that describes what your agent\n';
      output += 'can and cannot do. It helps ensure your agent behaves as documented.\n\n';
      output += 'To create one, add an AGENTS.md file to your project root with:\n';
      output += '- Capabilities: What the agent can do\n';
      output += '- Limitations: What the agent cannot do\n';
      output += '- Tools: What tools the agent has access to\n';
      output += '- Security: Required security controls\n\n';
      output +=
        'Learn more: https://docs.inkog.io/governance/agents-md\n\n';
    }

    // Overall status and score
    output += `📊 Status: ${formatOverallStatus(response.overall_status)}\n`;
    output += `📈 Governance Score: ${formatScore(response.score)}\n\n`;

    // Summary if available
    if (response.summary) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📊 SUMMARY\n\n';
      output += `   Total declarations: ${response.summary.total_declarations}\n`;
      output += `   ✅ Valid: ${response.summary.valid_declarations}\n`;
      output += `   ❌ Violated: ${response.summary.violated_constraints}\n`;
      output += `   ⚪ Unverified: ${response.summary.unverified_items}\n`;
      output += `   📁 Files analyzed: ${response.summary.files_analyzed}\n\n`;
    }

    // Declared capabilities
    const declaredCaps = response.declared_capabilities ?? [];
    if (declaredCaps.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📜 DECLARED CAPABILITIES\n\n';

      // Group by status
      const valid = declaredCaps.filter((c) => c.status === 'valid');
      const violated = declaredCaps.filter((c) => c.status === 'violated');
      const unverified = declaredCaps.filter((c) => c.status === 'unverified');

      if (violated.length > 0) {
        output += '❌ VIOLATED:\n\n';
        for (const cap of violated) {
          output += formatCapability(cap);
        }
        output += '\n';
      }

      if (unverified.length > 0) {
        output += '⚪ UNVERIFIED:\n\n';
        for (const cap of unverified) {
          output += formatCapability(cap);
        }
        output += '\n';
      }

      if (valid.length > 0) {
        output += '✅ VALID:\n\n';
        for (const cap of valid) {
          output += `   ${cap.name}`;
          if (cap.constraint_type) {
            output += ` [${cap.constraint_type}]`;
          }
          output += '\n';
        }
        output += '\n';
      }
    }

    // Mismatches
    const mismatches = response.mismatches ?? [];
    if (mismatches.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += `⚠️  GOVERNANCE MISMATCHES (${mismatches.length})\n\n`;
      output += 'The following code behaviors do not match AGENTS.md declarations:\n\n';

      for (const mismatch of mismatches) {
        output += formatMismatch(mismatch) + '\n';
      }
    } else if (hasAgentsMd) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '✅ No governance mismatches detected!\n\n';
      output += 'Your agent code aligns with its AGENTS.md declarations.\n\n';
    }

    // Recommendations
    const recommendations = response.recommendations ?? [];
    if (recommendations.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💡 RECOMMENDATIONS\n\n';
      for (let i = 0; i < recommendations.length; i++) {
        output += `${i + 1}. ${recommendations[i]}\n`;
      }
    }

    // Footer
    output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n';
    output += 'AGENTS.md verification powered by Inkog AI Security Platform\n';
    output += 'Learn more: https://inkog.io/governance\n';

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

export const governanceTool: ToolDefinition = {
  tool: {
    name: 'inkog_verify_governance',
    description:
      "Validate that AGENTS.md declarations match actual code behavior. Detects governance mismatches like 'read-only declared but code writes data' or 'human approval required but no approval gates in code'. Essential for EU AI Act Article 14 compliance.",
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to directory containing AGENTS.md and agent code',
        },
      },
      required: ['path'],
    },
  },
  handler: governanceHandler,
};
