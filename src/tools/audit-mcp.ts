/**
 * inkog_audit_mcp_server Tool
 *
 * P1 - MCP Server Security Auditing (THE ECOSYSTEM PLAY)
 *
 * Security audit any MCP server from the registry or GitHub repository.
 * Checks for:
 * - Excessive permissions (file system, network, exec)
 * - Data exfiltration risks
 * - Input validation gaps
 * - Credential handling issues
 * - Tool permission boundaries
 */

import { z } from 'zod';

import { getClient, InkogAuthError, InkogNetworkError } from '../api/client.js';
import type { McpSecurityIssue, Severity } from '../api/types.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const AuditMcpArgsSchema = z
  .object({
    server_name: z
      .string()
      .optional()
      .describe('MCP server name from registry (e.g., "github", "slack", "postgres")'),
    repository_url: z
      .string()
      .url()
      .optional()
      .describe('Direct GitHub repository URL to audit'),
  })
  .refine((data) => data.server_name !== undefined || data.repository_url !== undefined, {
    message: 'Either server_name or repository_url must be provided',
  });

type AuditMcpArgs = z.infer<typeof AuditMcpArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function formatSeverityIcon(severity: Severity): string {
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

function formatSecurityScore(score: number): string {
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

function formatIssue(issue: McpSecurityIssue): string {
  const icon = formatSeverityIcon(issue.severity);
  let output = `${icon} [${issue.severity}] ${issue.title}\n`;
  output += `   Category: ${issue.category}\n`;
  output += `   ${issue.description}\n`;

  if (issue.file !== undefined) {
    const location = issue.line !== undefined ? `${issue.file}:${issue.line}` : issue.file;
    output += `   📍 ${location}\n`;
  }

  output += `   💡 ${issue.recommendation}`;
  return output;
}

function formatToolPermissions(
  permissions: Record<
    string,
    {
      reads: string[];
      writes: string[];
      executes: string[];
      network: string[];
    }
  >
): string {
  let output = '';

  for (const [tool, perms] of Object.entries(permissions)) {
    output += `\n🔧 ${tool}:\n`;

    if (perms.reads.length > 0) {
      output += `   📖 Reads: ${perms.reads.join(', ')}\n`;
    }
    if (perms.writes.length > 0) {
      output += `   ✏️  Writes: ${perms.writes.join(', ')}\n`;
    }
    if (perms.executes.length > 0) {
      output += `   ⚡ Executes: ${perms.executes.join(', ')}\n`;
    }
    if (perms.network.length > 0) {
      output += `   🌐 Network: ${perms.network.join(', ')}\n`;
    }
  }

  return output;
}

// =============================================================================
// Handler
// =============================================================================

async function auditMcpHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = AuditMcpArgsSchema.safeParse(rawArgs);
  if (!parseResult.success) {
    return {
      content: [
        {
          type: 'text',
          text: `Invalid arguments: ${parseResult.error.message}\n\nProvide either server_name (from MCP registry) or repository_url (GitHub URL).`,
        },
      ],
      isError: true,
    };
  }

  const args: AuditMcpArgs = parseResult.data;

  try {
    // Call Inkog API
    const client = getClient();
    const auditOptions: { serverName?: string; repositoryUrl?: string } = {};
    if (args.server_name !== undefined) {
      auditOptions.serverName = args.server_name;
    }
    if (args.repository_url !== undefined) {
      auditOptions.repositoryUrl = args.repository_url;
    }
    const response = await client.auditMcpServer(auditOptions);

    // Build formatted output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           🔒 MCP Server Security Audit                ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // Server info
    output += `📦 Server: ${response.serverInfo.displayName ?? response.serverInfo.name}\n`;
    if (response.serverInfo.description !== undefined) {
      output += `   ${response.serverInfo.description}\n`;
    }
    output += `🔗 Repository: ${response.serverInfo.repository}\n`;
    if (response.serverInfo.license !== undefined) {
      output += `📄 License: ${response.serverInfo.license}\n`;
    }
    output += `🔧 Tools: ${response.serverInfo.tools.join(', ')}\n\n`;

    // Security score
    output += `📊 Security Score: ${formatSecurityScore(response.securityScore)}\n\n`;

    // Issues summary
    const critical = response.issues.filter((i) => i.severity === 'CRITICAL').length;
    const high = response.issues.filter((i) => i.severity === 'HIGH').length;
    const medium = response.issues.filter((i) => i.severity === 'MEDIUM').length;
    const low = response.issues.filter((i) => i.severity === 'LOW').length;

    if (response.issues.length === 0) {
      output += '✅ No security issues detected!\n\n';
    } else {
      output += `📋 Security Issues: ${response.issues.length}\n`;
      output += `   🔴 Critical: ${critical} | 🟠 High: ${high} | 🟡 Medium: ${medium} | 🟢 Low: ${low}\n\n`;
    }

    // Data flow risks
    if (response.dataFlowRisks.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '⚠️  DATA FLOW RISKS\n\n';
      for (const risk of response.dataFlowRisks) {
        output += `   • ${risk}\n`;
      }
      output += '\n';
    }

    // Tool permissions
    if (Object.keys(response.toolPermissions).length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔐 TOOL PERMISSIONS ANALYSIS\n';
      output += formatToolPermissions(response.toolPermissions);
      output += '\n';
    }

    // Detailed issues
    if (response.issues.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔍 SECURITY ISSUES\n\n';

      // Critical and high first
      const criticalHigh = response.issues.filter(
        (i) => i.severity === 'CRITICAL' || i.severity === 'HIGH'
      );
      const mediumLow = response.issues.filter(
        (i) => i.severity === 'MEDIUM' || i.severity === 'LOW'
      );

      for (const issue of criticalHigh) {
        output += formatIssue(issue) + '\n\n';
      }

      if (mediumLow.length > 0 && criticalHigh.length > 0) {
        output += '--- Lower Severity ---\n\n';
      }

      for (const issue of mediumLow) {
        output += formatIssue(issue) + '\n\n';
      }
    }

    // Recommendations
    if (response.recommendations.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💡 RECOMMENDATIONS\n\n';
      for (let i = 0; i < response.recommendations.length; i++) {
        output += `${i + 1}. ${response.recommendations[i]}\n`;
      }
    }

    // Footer
    output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n';
    output += 'MCP Server Audit powered by Inkog AI Security Platform\n';
    output += 'Learn more: https://inkog.io/mcp-security\n';

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

export const auditMcpTool: ToolDefinition = {
  tool: {
    name: 'inkog_audit_mcp_server',
    description:
      'Security audit any MCP server from the registry or GitHub. Analyzes tool permissions, data flow risks, input validation, and potential vulnerabilities. Essential for vetting third-party MCP servers before installation.',
    inputSchema: {
      type: 'object',
      properties: {
        server_name: {
          type: 'string',
          description: 'MCP server name from registry (e.g., "github", "slack", "postgres")',
        },
        repository_url: {
          type: 'string',
          description: 'Direct GitHub repository URL to audit',
        },
      },
    },
  },
  handler: auditMcpHandler,
};
