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

import { getClient, InkogAuthError, InkogNetworkError } from '../api/client.js';
import type { GovernanceMismatch } from '../api/types.js';
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

function formatMismatch(mismatch: GovernanceMismatch): string {
  const icon =
    mismatch.severity === 'CRITICAL'
      ? '🔴'
      : mismatch.severity === 'HIGH'
        ? '🟠'
        : mismatch.severity === 'MEDIUM'
          ? '🟡'
          : '🟢';

  let output = `${icon} GOVERNANCE MISMATCH\n`;
  output += `   📍 ${mismatch.file}:${mismatch.line}\n`;
  output += `   📜 Declared: "${mismatch.declared}"\n`;
  output += `   ⚠️  Actual: "${mismatch.actual}"\n`;
  output += `   💬 ${mismatch.description}`;

  return output;
}

function formatCapabilityList(items: string[], title: string, icon: string): string {
  if (items.length === 0) {
    return '';
  }

  let output = `${icon} ${title}:\n`;
  for (const item of items) {
    output += `   • ${item}\n`;
  }
  return output + '\n';
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

    // Call Inkog API
    const client = getClient();
    const response = await client.verifyGovernance(files);

    // Build output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║        🏛️  AGENTS.md Governance Verification          ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // AGENTS.md status
    if (response.hasAgentsMd) {
      output += `✅ AGENTS.md found: ${response.agentsMdPath ?? agentsMdPath ?? 'AGENTS.md'}\n\n`;
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

    // Compliance score
    output += `📊 Governance Score: ${response.complianceScore}/100\n\n`;

    // Declared capabilities, limitations, tools
    if (response.hasAgentsMd) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '📜 DECLARED GOVERNANCE\n\n';

      output += formatCapabilityList(response.declaredCapabilities, 'Capabilities', '✅');
      output += formatCapabilityList(response.declaredLimitations, 'Limitations', '🚫');
      output += formatCapabilityList(response.declaredTools, 'Tools', '🔧');
    }

    // Mismatches
    if (response.mismatches.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += `⚠️  GOVERNANCE MISMATCHES (${response.mismatches.length})\n\n`;
      output += 'The following code behaviors do not match AGENTS.md declarations:\n\n';

      for (const mismatch of response.mismatches) {
        output += formatMismatch(mismatch) + '\n\n';
      }
    } else if (response.hasAgentsMd) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '✅ No governance mismatches detected!\n\n';
      output += 'Your agent code aligns with its AGENTS.md declarations.\n\n';
    }

    // Recommendations
    if (response.recommendation !== undefined) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💡 RECOMMENDATION\n\n';
      output += response.recommendation + '\n';
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

    throw error;
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
