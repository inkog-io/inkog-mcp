/**
 * inkog_mcp_scan Tool
 *
 * Scan MCP servers from registry or by repository URL for security vulnerabilities.
 * Detects tool poisoning, command injection, data exfiltration, excessive permissions, and more.
 *
 * For skill package scanning, use inkog_skill_scan instead.
 */

import { z } from 'zod';

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type { SkillScanDetailResponse, SkillScanResponse } from '../api/types.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const MCPScanArgsSchema = z
  .object({
    server_name: z
      .string()
      .optional()
      .describe('MCP server name from registry (e.g., "github", "filesystem", "postgres")'),
    repository_url: z
      .string()
      .url()
      .optional()
      .describe('GitHub repository URL of the MCP server to scan'),
    deep: z
      .boolean()
      .optional()
      .default(false)
      .describe('Enable AI deep analysis (slower but catches novel threats)'),
  })
  .refine(
    (data) =>
      data.server_name !== undefined ||
      data.repository_url !== undefined,
    {
      message: 'Either server_name or repository_url must be provided',
    }
  );

// =============================================================================
// Formatters
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

function formatRiskBadge(risk: string): string {
  switch (risk) {
    case 'critical':
      return '🔴 CRITICAL';
    case 'high':
      return '🟠 HIGH';
    case 'medium':
      return '🟡 MEDIUM';
    case 'low':
      return '🟢 LOW';
    default:
      return risk.toUpperCase();
  }
}

function formatPermission(name: string, enabled: boolean): string {
  return enabled ? `⚠️ ${name}` : `✅ ${name} (not used)`;
}

// =============================================================================
// Deep Scan Helpers
// =============================================================================

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatDeepFindings(scan: Record<string, unknown>): string {
  const aiFindings = scan.ai_findings;
  if (!aiFindings) return '';

  let parsed: unknown = aiFindings;
  if (typeof parsed === 'string') {
    try { parsed = JSON.parse(parsed); } catch { return ''; }
  }

  let findings: Record<string, unknown>[] = [];
  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;
    if (Array.isArray(obj.findings)) findings = obj.findings as Record<string, unknown>[];
  } else if (Array.isArray(parsed)) {
    findings = parsed as Record<string, unknown>[];
  }

  if (findings.length === 0) return '';

  const lines: string[] = [];
  lines.push('## Deep Analysis Findings');
  for (const f of findings) {
    const sev = typeof f.severity === 'string' ? f.severity : 'LOW';
    const severity = sev.toUpperCase();
    const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🟢';
    const title = typeof f.title === 'string' ? f.title : typeof f.description === 'string' ? f.description : 'Finding';
    lines.push(`### ${icon} ${title}`);
    if (typeof f.file === 'string') {
      lines.push(`📁 ${f.file}${typeof f.line === 'number' ? `:${f.line.toString()}` : ''}`);
    }
    if (typeof f.description === 'string') lines.push(f.description);
    if (typeof f.remediation === 'string') lines.push(`💡 ${f.remediation}`);
    lines.push('');
  }
  return lines.join('\n');
}

// =============================================================================
// Handler
// =============================================================================

async function handleMCPScan(args: Record<string, unknown>): Promise<ToolResult> {
  const parsed = MCPScanArgsSchema.parse(args);

  try {
    const client = getClient();
    let response: SkillScanResponse;

    if (parsed.server_name) {
      // Scan MCP server from registry (optionally with repo URL for deep)
      const mcpOpts: { serverName: string; url?: string } = {
        serverName: parsed.server_name,
      };
      if (parsed.repository_url) {
        mcpOpts.url = parsed.repository_url;
      }
      response = await client.scanMCPServer(mcpOpts);
    } else if (parsed.repository_url) {
      // Scan MCP server from repository URL
      response = await client.scanSkill({
        repositoryUrl: parsed.repository_url,
      });
    } else {
      return {
        content: [
          {
            type: 'text',
            text: 'Please provide either server_name or repository_url.',
          },
        ],
        isError: true,
      };
    }

    if (!response.success || !response.result) {
      return {
        content: [
          {
            type: 'text',
            text: `MCP scan failed: ${response.error ?? 'Unknown error'}`,
          },
        ],
        isError: true,
      };
    }

    // Format the results
    const result = response.result;
    const lines: string[] = [];

    lines.push(`# MCP Server Security Scan: ${result.name || 'Unknown'}`);
    lines.push('');
    lines.push(`**Overall Risk:** ${formatRiskBadge(result.overall_risk)}`);
    lines.push(`**Security Score:** ${result.security_score}/100`);
    lines.push(`**Files Scanned:** ${result.files_scanned} | **Lines:** ${result.lines_of_code}`);
    lines.push('');

    // Permissions
    if (result.permissions) {
      const p = result.permissions;
      lines.push('## Permissions');
      lines.push(formatPermission('File Access', p.file_access));
      lines.push(formatPermission('Network Access', p.network_access));
      lines.push(formatPermission('Code Execution', p.code_execution));
      lines.push(formatPermission('Database Access', p.database_access));
      lines.push(formatPermission('Environment Access', p.environment_access));
      lines.push(`**Scope:** ${p.scope}`);

      if (p.code_execution && p.network_access && (p.file_access || p.environment_access)) {
        lines.push('');
        lines.push('⚠️ **LETHAL TRIFECTA DETECTED:** Code Execution + Network + File/Env Access');
      }
      lines.push('');
    }

    // Tools
    if (result.tool_analyses?.length > 0) {
      lines.push(`## Tools (${result.tool_analyses.length})`);
      for (const tool of result.tool_analyses) {
        const riskIcon = tool.risk_level === 'dangerous' ? '🔴' :
                         tool.risk_level === 'moderate' ? '🟡' : '🟢';
        lines.push(`- ${riskIcon} **${tool.name}** [${tool.risk_level}]`);
        if (tool.attack_vectors?.length) {
          for (const v of tool.attack_vectors) {
            lines.push(`  - Attack vector: ${v}`);
          }
        }
      }
      lines.push('');
    }

    // Findings
    if (result.findings.length > 0) {
      lines.push(`## Findings (${result.findings.length})`);
      lines.push(`🔴 Critical: ${result.critical_count} | 🟠 High: ${result.high_count} | 🟡 Medium: ${result.medium_count} | 🟢 Low: ${result.low_count}`);
      lines.push('');

      for (let i = 0; i < result.findings.length; i++) {
        const f = result.findings[i]!;
        lines.push(`### ${formatSeverityIcon(f.severity)} #${i + 1}: ${f.title}`);
        if (f.file) {
          lines.push(`📁 ${f.file}${f.line ? `:${f.line}` : ''}`);
        }
        if (f.tool_name) {
          lines.push(`🔧 Tool: ${f.tool_name}`);
        }
        lines.push(f.description);
        if (f.owasp_agentic || f.owasp_mcp) {
          const refs: string[] = [];
          if (f.owasp_agentic) refs.push(`OWASP Agentic: ${f.owasp_agentic}`);
          if (f.owasp_mcp) refs.push(`OWASP MCP: ${f.owasp_mcp}`);
          lines.push(`📋 ${refs.join(' | ')}`);
        }
        lines.push(`💡 ${f.remediation}`);
        lines.push('');
      }
    } else {
      lines.push('## ✅ No security findings detected');
    }

    // Deep scan flow
    if (parsed.deep && response.scan_id) {
      lines.push('');
      lines.push('---');
      lines.push('## 🔬 Deep Analysis');
      lines.push('Triggering AI deep analysis...');

      try {
        await client.triggerSkillDeepScan(response.scan_id);
      } catch {
        lines.push('⚠️ Could not trigger deep analysis. Returning standard results.');
        return {
          content: [{ type: 'text', text: lines.join('\n') }],
        };
      }

      const deadline = Date.now() + 15 * 60 * 1000;
      let deepDone = false;

      while (Date.now() < deadline) {
        await sleep(5000);
        try {
          const detail: SkillScanDetailResponse = await client.getSkillScan(response.scan_id);
          const status = detail.scan?.ai_scan_status as string | undefined;

          if (status === 'completed') {
            const deepOutput = formatDeepFindings(detail.scan);
            if (deepOutput) {
              lines.push(deepOutput);
            } else {
              lines.push('✅ Deep analysis completed — no additional findings.');
            }
            deepDone = true;
            break;
          }
          if (status === 'failed') {
            lines.push('⚠️ Deep analysis failed. Standard scan results are shown above.');
            deepDone = true;
            break;
          }
        } catch {
          // Polling error — continue waiting
        }
      }

      if (!deepDone) {
        lines.push('⏱️ Deep analysis timed out (15 min). Check the dashboard for results.');
      }
    }

    return {
      content: [
        {
          type: 'text',
          text: lines.join('\n'),
        },
      ],
    };
  } catch (err) {
    if (err instanceof InkogAuthError) {
      return {
        content: [{ type: 'text', text: '🔐 Authentication required. Set INKOG_API_KEY environment variable.' }],
        isError: true,
      };
    }
    if (err instanceof InkogRateLimitError) {
      return {
        content: [{ type: 'text', text: '⏳ Rate limited. Please wait and try again.' }],
        isError: true,
      };
    }
    if (err instanceof InkogNetworkError) {
      return {
        content: [{ type: 'text', text: '🌐 Network error. Check your connection and try again.' }],
        isError: true,
      };
    }
    if (err instanceof InkogApiError) {
      return {
        content: [{ type: 'text', text: `❌ API error: ${err.message}` }],
        isError: true,
      };
    }
    throw err;
  }
}

// =============================================================================
// Tool Definition
// =============================================================================

export const mcpScanTool: ToolDefinition = {
  tool: {
    name: 'inkog_mcp_scan',
    description:
      'Scan MCP servers from registry or by repository URL for security vulnerabilities. ' +
      'Detects tool poisoning, command injection, data exfiltration, prompt injection, excessive permissions, ' +
      'obfuscation, supply chain risks, and more. Maps findings to OWASP Agentic Top 10 and OWASP MCP Top 10. ' +
      'Set deep=true for AI-powered deep analysis (~10 min, catches novel threats). ' +
      'For skill package scanning, use inkog_skill_scan instead.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        server_name: {
          type: 'string',
          description: 'MCP server name from registry (e.g., "github", "filesystem", "postgres")',
        },
        repository_url: {
          type: 'string',
          description: 'GitHub repository URL of the MCP server',
        },
        deep: {
          type: 'boolean',
          description: 'Enable AI deep analysis',
          default: false,
        },
      },
    },
  },
  handler: handleMCPScan,
};
