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

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type { Severity } from '../api/types.js';
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

    // Show cache warning if using offline data
    if (response.cache_warning) {
      output += `⚠️  ${response.cache_warning}\n\n`;
    }

    // Get data using new field names (with fallbacks for legacy compatibility)
    const serverInfo = response.server ?? response.serverInfo;
    const auditResults = response.audit_results;
    const findings = response.findings ?? response.issues ?? [];
    const securityScore = auditResults?.security_score ?? response.securityScore ?? 0;

    // Server info
    if (serverInfo) {
      output += `📦 Server: ${serverInfo.name}\n`;
      if (serverInfo.description) {
        output += `   ${serverInfo.description}\n`;
      }
      if (serverInfo.repository) {
        output += `🔗 Repository: ${serverInfo.repository}\n`;
      }
      if (serverInfo.license) {
        output += `📄 License: ${serverInfo.license}\n`;
      }
      output += '\n';
    }

    // Security score
    output += `📊 Security Score: ${formatSecurityScore(securityScore)}\n`;
    if (auditResults?.overall_risk) {
      output += `📈 Overall Risk: ${auditResults.overall_risk.toUpperCase()}\n`;
    }
    output += '\n';

    // Findings summary
    const critical = findings.filter((i) => i.severity === 'CRITICAL' || i.severity === 'critical').length;
    const high = findings.filter((i) => i.severity === 'HIGH' || i.severity === 'high').length;
    const medium = findings.filter((i) => i.severity === 'MEDIUM' || i.severity === 'medium').length;
    const low = findings.filter((i) => i.severity === 'LOW' || i.severity === 'low').length;

    if (findings.length === 0) {
      output += '✅ No security issues detected!\n\n';
    } else {
      output += `📋 Security Issues: ${findings.length}\n`;
      output += `   🔴 Critical: ${critical} | 🟠 High: ${high} | 🟡 Medium: ${medium} | 🟢 Low: ${low}\n\n`;
    }

    // Permissions analysis
    if (response.permissions) {
      const perms = response.permissions;
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔐 PERMISSIONS ANALYSIS\n\n';
      output += `   Scope: ${perms.scope}\n`;
      if (perms.file_access) output += '   📁 File System Access\n';
      if (perms.network_access) output += '   🌐 Network Access\n';
      if (perms.code_execution) output += '   ⚡ Code Execution\n';
      if (perms.database_access) output += '   🗄️  Database Access\n';
      if (perms.environment_access) output += '   🔧 Environment Access\n';
      output += '\n';
    }

    // Tools analysis
    if (response.tools && response.tools.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔧 TOOLS ANALYSIS\n\n';
      for (const tool of response.tools) {
        const riskIcon = tool.risk_level === 'dangerous' ? '🔴' : tool.risk_level === 'moderate' ? '🟡' : '🟢';
        output += `   ${riskIcon} ${tool.name} (${tool.risk_level})\n`;
        if (tool.risk_reasons && tool.risk_reasons.length > 0) {
          for (const reason of tool.risk_reasons) {
            output += `      • ${reason}\n`;
          }
        }
      }
      output += '\n';
    }

    // Detailed findings
    if (findings.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔍 SECURITY FINDINGS\n\n';

      // Critical and high first
      const criticalHigh = findings.filter(
        (i) => i.severity === 'CRITICAL' || i.severity === 'critical' ||
               i.severity === 'HIGH' || i.severity === 'high'
      );
      const mediumLow = findings.filter(
        (i) => i.severity === 'MEDIUM' || i.severity === 'medium' ||
               i.severity === 'LOW' || i.severity === 'low'
      );

      for (const finding of criticalHigh) {
        output += `${formatSeverityIcon(finding.severity.toUpperCase() as Severity)} [${finding.severity.toUpperCase()}] ${finding.title}\n`;
        output += `   ${finding.description}\n`;
        if (finding.remediation) {
          output += `   💡 ${finding.remediation}\n`;
        }
        output += '\n';
      }

      if (mediumLow.length > 0 && criticalHigh.length > 0) {
        output += '--- Lower Severity ---\n\n';
      }

      for (const finding of mediumLow) {
        output += `${formatSeverityIcon(finding.severity.toUpperCase() as Severity)} [${finding.severity.toUpperCase()}] ${finding.title}\n`;
        output += `   ${finding.description}\n`;
        if (finding.remediation) {
          output += `   💡 ${finding.remediation}\n`;
        }
        output += '\n';
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
