/**
 * inkog_audit_a2a Tool
 *
 * P2 - Agent-to-Agent (A2A) Security Auditing (MULTI-AGENT SECURITY)
 *
 * Audits communication patterns in multi-agent systems for:
 * - Infinite delegation loops
 * - Privilege escalation via delegation
 * - Data leakage between agents
 * - Unauthorized agent handoffs
 * - Missing permission guards
 *
 * Supports: Google A2A protocol, CrewAI, LangGraph, auto-detection
 *
 * Aligned with Google Cloud AI Agent Trends 2026:
 * "Multi-agent orchestration is the future of enterprise AI"
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
  A2ASecurityIssue,
  AgentDefinition,
  DelegationEdge,
  Severity,
} from '../api/types.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const A2AArgsSchema = z.object({
  path: z.string().describe('Path to multi-agent system codebase'),
  protocol: z
    .enum(['a2a', 'crewai', 'langgraph', 'auto-detect'])
    .optional()
    .default('auto-detect')
    .describe('Multi-agent protocol: a2a (Google), crewai, langgraph, or auto-detect'),
  check_delegation_chains: z
    .boolean()
    .optional()
    .default(true)
    .describe('Check for infinite delegation loops and unauthorized handoffs'),
});

type A2AArgs = z.infer<typeof A2AArgsSchema>;

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

function formatProtocol(protocol: string): string {
  switch (protocol) {
    case 'a2a':
      return 'Google A2A Protocol';
    case 'crewai':
      return 'CrewAI';
    case 'langgraph':
      return 'LangGraph';
    case 'auto-detect':
      return 'Auto-detected';
    default:
      return protocol;
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

function formatAgent(agent: AgentDefinition): string {
  let output = `🤖 ${agent.name}`;
  if (agent.role !== undefined) {
    output += ` (${agent.role})`;
  }
  output += '\n';
  output += `   📍 ${agent.file}:${agent.line}\n`;

  if (agent.tools.length > 0) {
    output += `   🔧 Tools: ${agent.tools.join(', ')}\n`;
  }

  if (agent.permissions.length > 0) {
    output += `   🔐 Permissions: ${agent.permissions.join(', ')}\n`;
  }

  return output;
}

function formatDelegationEdge(edge: DelegationEdge): string {
  const arrow = edge.type === 'spawn' ? '⟹' : edge.type === 'handoff' ? '→' : '⇢';
  const guards = edge.hasGuards ? '🛡️' : '⚠️';
  return `   ${edge.from} ${arrow} ${edge.to} [${edge.type}] ${guards}`;
}

function formatIssue(issue: A2ASecurityIssue): string {
  const icon = formatSeverityIcon(issue.severity);
  let output = `${icon} [${issue.severity}] ${issue.title}\n`;
  output += `   Category: ${formatIssueCategory(issue.category)}\n`;
  output += `   ${issue.description}\n`;
  output += `   Agents: ${issue.agents.join(', ')}\n`;
  output += `   📍 ${issue.file}:${issue.line}\n`;
  output += `   💡 ${issue.recommendation}`;
  return output;
}

function formatIssueCategory(category: A2ASecurityIssue['category']): string {
  switch (category) {
    case 'infinite-delegation':
      return '♾️  Infinite Delegation';
    case 'privilege-escalation':
      return '⬆️  Privilege Escalation';
    case 'data-leakage':
      return '💧 Data Leakage';
    case 'unauthorized-handoff':
      return '🚫 Unauthorized Handoff';
    case 'missing-guards':
      return '🛡️  Missing Guards';
    default:
      return category;
  }
}

function renderDelegationGraph(agents: AgentDefinition[], edges: DelegationEdge[]): string {
  if (agents.length === 0 || edges.length === 0) {
    return 'No delegation relationships detected.\n';
  }

  let output = '\n';

  // Simple ASCII graph representation
  const agentMap = new Map(agents.map((a) => [a.id, a.name]));

  // Group edges by source agent
  const edgesBySource = new Map<string, DelegationEdge[]>();
  for (const edge of edges) {
    if (!edgesBySource.has(edge.from)) {
      edgesBySource.set(edge.from, []);
    }
    edgesBySource.get(edge.from)!.push(edge);
  }

  // Render each agent and its outgoing edges
  for (const agent of agents) {
    const agentEdges = edgesBySource.get(agent.id) ?? [];
    const name = agentMap.get(agent.id) ?? agent.id;

    if (agentEdges.length === 0) {
      output += `   ┌──────────────┐\n`;
      output += `   │ ${name.padEnd(12)} │\n`;
      output += `   └──────────────┘\n`;
    } else {
      output += `   ┌──────────────┐\n`;
      output += `   │ ${name.padEnd(12)} │`;

      agentEdges.forEach((edge, i) => {
        const targetName = agentMap.get(edge.to) ?? edge.to;
        const arrow = edge.hasGuards ? '──🛡️──>' : '──⚠️──>';

        if (i === 0) {
          output += `${arrow} ${targetName}`;
        } else {
          output += `\n   │              │${arrow} ${targetName}`;
        }
      });

      output += `\n   └──────────────┘\n`;
    }
  }

  return output;
}

// =============================================================================
// Handler
// =============================================================================

async function auditA2AHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = A2AArgsSchema.safeParse(rawArgs);
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

  const args: A2AArgs = parseResult.data;

  try {
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

    // Get relative paths
    const files = getRelativePaths(readResult.files, args.path);

    // Call Inkog API - first scan, then audit A2A
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

    // Step 2: Use scan_id to audit A2A
    const response = await client.auditA2A([], {
      protocol: args.protocol,
      checkDelegationChains: args.check_delegation_chains,
      scanId: scanResponse.scan_id,
    });

    // Build formatted output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║        🤖 Agent-to-Agent Security Audit               ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // Overview
    output += `📡 Protocol: ${formatProtocol(response.protocol)}\n`;
    output += `🤖 Agents Detected: ${response.agents.length}\n`;
    output += `🔗 Delegation Edges: ${response.delegationGraph.length}\n`;
    output += `📊 Security Score: ${formatSecurityScore(response.securityScore)}\n\n`;

    // Topology warnings
    if (response.hasCycles) {
      output += '⚠️  WARNING: Delegation cycles detected (potential infinite loops)\n';
    }
    if (response.maxDelegationDepth > 5) {
      output += `⚠️  WARNING: Deep delegation chain detected (depth: ${response.maxDelegationDepth})\n`;
    }
    output += '\n';

    // Issues summary
    const critical = response.issues.filter((i) => i.severity === 'CRITICAL').length;
    const high = response.issues.filter((i) => i.severity === 'HIGH').length;
    const medium = response.issues.filter((i) => i.severity === 'MEDIUM').length;
    const low = response.issues.filter((i) => i.severity === 'LOW').length;

    if (response.issues.length === 0) {
      output += '✅ No multi-agent security issues detected!\n\n';
    } else {
      output += `📋 Security Issues: ${response.issues.length}\n`;
      output += `   🔴 Critical: ${critical} | 🟠 High: ${high} | 🟡 Medium: ${medium} | 🟢 Low: ${low}\n\n`;
    }

    // Agent inventory
    if (response.agents.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🤖 AGENT INVENTORY\n\n';
      for (const agent of response.agents) {
        output += formatAgent(agent) + '\n';
      }
    }

    // Delegation graph visualization
    if (response.delegationGraph.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔗 DELEGATION GRAPH\n';
      output += renderDelegationGraph(response.agents, response.delegationGraph);
      output += '\n';

      output += 'Delegation Edges:\n';
      for (const edge of response.delegationGraph) {
        output += formatDelegationEdge(edge) + '\n';
      }
      output += '\n';
      output += 'Legend: 🛡️  = has permission guards, ⚠️  = no guards\n\n';
    }

    // Detailed issues
    if (response.issues.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔍 SECURITY ISSUES\n\n';

      // Group by category
      const infiniteDelegation = response.issues.filter(
        (i) => i.category === 'infinite-delegation'
      );
      const privilegeEscalation = response.issues.filter(
        (i) => i.category === 'privilege-escalation'
      );
      const dataLeakage = response.issues.filter((i) => i.category === 'data-leakage');
      const unauthorizedHandoff = response.issues.filter(
        (i) => i.category === 'unauthorized-handoff'
      );
      const missingGuards = response.issues.filter((i) => i.category === 'missing-guards');

      if (infiniteDelegation.length > 0) {
        output += '♾️  INFINITE DELEGATION RISKS\n\n';
        for (const issue of infiniteDelegation) {
          output += formatIssue(issue) + '\n\n';
        }
      }

      if (privilegeEscalation.length > 0) {
        output += '⬆️  PRIVILEGE ESCALATION RISKS\n\n';
        for (const issue of privilegeEscalation) {
          output += formatIssue(issue) + '\n\n';
        }
      }

      if (dataLeakage.length > 0) {
        output += '💧 DATA LEAKAGE RISKS\n\n';
        for (const issue of dataLeakage) {
          output += formatIssue(issue) + '\n\n';
        }
      }

      if (unauthorizedHandoff.length > 0) {
        output += '🚫 UNAUTHORIZED HANDOFF RISKS\n\n';
        for (const issue of unauthorizedHandoff) {
          output += formatIssue(issue) + '\n\n';
        }
      }

      if (missingGuards.length > 0) {
        output += '🛡️  MISSING GUARDS\n\n';
        for (const issue of missingGuards) {
          output += formatIssue(issue) + '\n\n';
        }
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
    output += 'Multi-Agent Security Audit powered by Inkog AI Security Platform\n';
    output += 'Learn more: https://inkog.io/multi-agent-security\n';

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

export const auditA2aTool: ToolDefinition = {
  tool: {
    name: 'inkog_audit_a2a',
    description:
      'Audit Agent-to-Agent (A2A) communications in multi-agent systems. Detects infinite delegation loops, privilege escalation, data leakage between agents, and unauthorized handoffs. Supports Google A2A protocol, CrewAI, and LangGraph.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to multi-agent system codebase',
        },
        protocol: {
          type: 'string',
          enum: ['a2a', 'crewai', 'langgraph', 'auto-detect'],
          default: 'auto-detect',
          description: 'Multi-agent protocol: a2a (Google), crewai, langgraph, or auto-detect',
        },
        check_delegation_chains: {
          type: 'boolean',
          default: true,
          description: 'Check for infinite delegation loops and unauthorized handoffs',
        },
      },
      required: ['path'],
    },
  },
  handler: auditA2AHandler,
};
