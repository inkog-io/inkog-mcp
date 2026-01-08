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
  A2AAgent,
  A2ACommunication,
  A2AFinding,
  A2AProtocol,
} from '../api/types.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import { hasElements, safeArray, safeJoin, safeLength } from '../utils/array-utils.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const A2AArgsSchema = z.object({
  path: z.string().describe('Path to multi-agent system codebase'),
  protocol: z
    .enum(['a2a', 'crewai', 'langgraph', 'autogen', 'custom', 'unknown'])
    .optional()
    .describe('Multi-agent protocol hint: a2a (Google), crewai, langgraph, autogen, or leave empty for auto-detect'),
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

function formatProtocol(protocol: A2AProtocol | string): string {
  switch (protocol) {
    case 'a2a':
      return 'Google A2A Protocol';
    case 'crewai':
      return 'CrewAI';
    case 'langgraph':
      return 'LangGraph';
    case 'autogen':
      return 'Microsoft AutoGen';
    case 'custom':
      return 'Custom Protocol';
    case 'unknown':
      return 'Unknown (auto-detect failed)';
    default:
      return protocol;
  }
}

function formatRiskLevel(risk: string): string {
  switch (risk.toLowerCase()) {
    case 'critical':
      return '🔴 Critical';
    case 'high':
      return '🟠 High';
    case 'medium':
      return '🟡 Medium';
    case 'low':
      return '🟢 Low';
    case 'not_applicable':
      return '⚪ N/A';
    default:
      return risk;
  }
}

function formatAgent(agent: A2AAgent): string {
  let output = `🤖 ${agent.name}`;
  if (agent.role) {
    output += ` (${agent.role})`;
  }
  output += '\n';

  if (agent.file) {
    output += `   📍 ${agent.file}${agent.line ? `:${agent.line}` : ''}\n`;
  }

  if (hasElements(agent.tools)) {
    output += `   🔧 Tools: ${safeJoin(agent.tools)}\n`;
  }

  if (hasElements(agent.delegation_targets)) {
    output += `   🔗 Can delegate to: ${safeJoin(agent.delegation_targets)}\n`;
  }

  // Security properties
  const securityProps: string[] = [];
  if (agent.has_auth_check) securityProps.push('auth ✓');
  if (agent.has_rate_limiting) securityProps.push('rate-limit ✓');
  if (agent.has_memory) securityProps.push('memory');
  if (securityProps.length > 0) {
    output += `   🔐 Security: ${securityProps.join(', ')}\n`;
  }

  if (agent.trust_level) {
    output += `   🛡️  Trust: ${agent.trust_level}\n`;
  }

  return output;
}

function formatCommunication(comm: A2ACommunication): string {
  const arrow = comm.type === 'delegation' ? '⟹' : comm.type === 'task' ? '→' : '⇢';
  const guards = comm.has_guards ? '🛡️' : '⚠️';
  const auth = comm.has_auth ? '🔐' : '';
  return `   ${comm.from} ${arrow} ${comm.to} [${comm.type}] ${guards}${auth}`;
}

function formatFinding(finding: A2AFinding): string {
  const icon = formatSeverityIcon(finding.severity);
  let output = `${icon} [${finding.severity.toUpperCase()}] ${finding.type}\n`;
  output += `   ${finding.description}\n`;

  if (hasElements(finding.agents_involved)) {
    output += `   Agents: ${safeJoin(finding.agents_involved)}\n`;
  }

  if (finding.file) {
    output += `   📍 ${finding.file}${finding.line ? `:${finding.line}` : ''}\n`;
  }

  if (finding.remediation) {
    output += `   💡 ${finding.remediation}`;
  }

  return output;
}

function formatFindingType(type: string): string {
  switch (type) {
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
    case 'missing-auth':
      return '🔐 Missing Authentication';
    default:
      return type;
  }
}

function renderDelegationGraph(agents: A2AAgent[] | null, communications: A2ACommunication[] | null): string {
  const safeAgents = safeArray(agents);
  const safeComms = safeArray(communications);

  if (safeAgents.length === 0 || safeComms.length === 0) {
    return 'No delegation relationships detected.\n';
  }

  let output = '\n';

  // Simple ASCII graph representation
  const agentMap = new Map(safeAgents.map((a) => [a.id, a.name]));

  // Group communications by source agent
  const commsBySource = new Map<string, A2ACommunication[]>();
  for (const comm of safeComms) {
    if (!commsBySource.has(comm.from)) {
      commsBySource.set(comm.from, []);
    }
    commsBySource.get(comm.from)!.push(comm);
  }

  // Render each agent and its outgoing communications
  for (const agent of safeAgents) {
    const agentComms = commsBySource.get(agent.id) ?? [];
    const name = agentMap.get(agent.id) ?? agent.id;
    const displayName = name.length > 12 ? name.substring(0, 10) + '..' : name;

    if (agentComms.length === 0) {
      output += `   ┌──────────────┐\n`;
      output += `   │ ${displayName.padEnd(12)} │\n`;
      output += `   └──────────────┘\n`;
    } else {
      output += `   ┌──────────────┐\n`;
      output += `   │ ${displayName.padEnd(12)} │`;

      agentComms.forEach((comm, i) => {
        const targetName = agentMap.get(comm.to) ?? comm.to;
        const arrow = comm.has_guards ? '──🛡️──>' : '──⚠️──>';

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
    const a2aOptions: { protocol?: A2AProtocol; checkDelegationChains?: boolean; scanId?: string } = {
      checkDelegationChains: args.check_delegation_chains,
      scanId: scanResponse.scan_id,
    };
    if (args.protocol) {
      a2aOptions.protocol = args.protocol;
    }
    const response = await client.auditA2A([], a2aOptions);

    // Build formatted output
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║        🤖 Agent-to-Agent Security Audit               ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    // Warning if topology is incomplete
    if (response.warning) {
      output += `⚠️  ${response.warning}\n\n`;
    }

    // Overview
    output += `📡 Protocol: ${formatProtocol(response.protocol)}\n`;
    output += `🤖 Agents Detected: ${safeLength(response.agents)}\n`;
    output += `🔗 Communication Channels: ${safeLength(response.communications)}\n`;

    // Risk assessment
    if (response.risk_assessment) {
      output += `📊 Overall Risk: ${formatRiskLevel(response.risk_assessment.overall_risk)}\n`;
    }
    output += '\n';

    // Trust analysis warnings
    if (response.trust_analysis) {
      const ta = response.trust_analysis;
      if (ta.circular_delegations && ta.circular_delegations.length > 0) {
        output += '⚠️  WARNING: Circular delegation chains detected (potential infinite loops)\n';
        for (const cycle of ta.circular_delegations) {
          output += `   Cycle: ${cycle.join(' → ')}\n`;
        }
        output += '\n';
      }
      if (ta.unguarded_delegations > 0) {
        output += `⚠️  WARNING: ${ta.unguarded_delegations} unguarded delegation(s) detected\n`;
      }
      if (ta.privilege_escalations > 0) {
        output += `⚠️  WARNING: ${ta.privilege_escalations} potential privilege escalation(s)\n`;
      }
      if (ta.cross_boundary_flows > 0) {
        output += `ℹ️  ${ta.cross_boundary_flows} cross-trust-boundary flow(s) detected\n`;
      }
      output += '\n';
    }

    // Findings summary
    const findings = safeArray(response.findings);
    if (findings.length === 0) {
      output += '✅ No multi-agent security issues detected!\n\n';
    } else {
      const critical = findings.filter((f) => f.severity.toUpperCase() === 'CRITICAL').length;
      const high = findings.filter((f) => f.severity.toUpperCase() === 'HIGH').length;
      const medium = findings.filter((f) => f.severity.toUpperCase() === 'MEDIUM').length;
      const low = findings.filter((f) => f.severity.toUpperCase() === 'LOW').length;

      output += `📋 Security Issues: ${findings.length}\n`;
      output += `   🔴 Critical: ${critical} | 🟠 High: ${high} | 🟡 Medium: ${medium} | 🟢 Low: ${low}\n\n`;
    }

    // Agent inventory
    const agents = safeArray(response.agents);
    if (agents.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🤖 AGENT INVENTORY\n\n';
      for (const agent of agents) {
        output += formatAgent(agent) + '\n';
      }
    }

    // Delegation graph visualization
    const communications = safeArray(response.communications);
    if (communications.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔗 DELEGATION GRAPH\n';
      output += renderDelegationGraph(agents, communications);
      output += '\n';

      output += 'Communication Channels:\n';
      for (const comm of communications) {
        output += formatCommunication(comm) + '\n';
      }
      output += '\n';
      output += 'Legend: 🛡️  = has permission guards, ⚠️  = no guards, 🔐 = authenticated\n\n';
    }

    // Detailed findings
    if (findings.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🔍 SECURITY FINDINGS\n\n';

      // Group by type
      const groupedFindings = new Map<string, A2AFinding[]>();
      for (const finding of findings) {
        const type = finding.type;
        if (!groupedFindings.has(type)) {
          groupedFindings.set(type, []);
        }
        groupedFindings.get(type)!.push(finding);
      }

      for (const [type, typeFindings] of groupedFindings) {
        output += `${formatFindingType(type)}\n\n`;
        for (const finding of typeFindings) {
          output += formatFinding(finding) + '\n\n';
        }
      }
    }

    // Trust boundaries
    const trustBoundaries = safeArray(response.trust_analysis?.trust_boundaries);
    if (trustBoundaries.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '🛡️  TRUST BOUNDARIES\n\n';
      for (const boundary of trustBoundaries) {
        output += `📦 ${boundary.name} [${boundary.trust_level}]\n`;
        if (boundary.description) {
          output += `   ${boundary.description}\n`;
        }
        output += `   Agents: ${safeJoin(boundary.agent_ids)}\n\n`;
      }
    }

    // Recommendations
    const recommendations = safeArray(response.risk_assessment?.recommendations);
    if (recommendations.length > 0) {
      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += '💡 RECOMMENDATIONS\n\n';
      for (let i = 0; i < recommendations.length; i++) {
        output += `${i + 1}. ${recommendations[i]}\n`;
      }
    }

    // Risk summary
    if (response.risk_assessment?.summary) {
      output += '\n📊 SUMMARY\n';
      output += `   ${response.risk_assessment.summary}\n`;
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
      'Audit Agent-to-Agent (A2A) communications in multi-agent systems. Detects infinite delegation loops, privilege escalation, data leakage between agents, and unauthorized handoffs. Supports Google A2A protocol, CrewAI, LangGraph, and AutoGen.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to multi-agent system codebase',
        },
        protocol: {
          type: 'string',
          enum: ['a2a', 'crewai', 'langgraph', 'autogen', 'custom'],
          description: 'Multi-agent protocol hint (optional, will auto-detect if not specified)',
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
