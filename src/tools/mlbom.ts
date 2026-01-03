/**
 * inkog_generate_mlbom Tool
 *
 * P1 - Machine Learning Bill of Materials (MLBOM) Generation
 *
 * Generates a comprehensive inventory of all ML/AI components in an agent system:
 * - Models (OpenAI, Anthropic, local models, etc.)
 * - Tools (function calls, APIs, integrations)
 * - Data sources (databases, vector stores, file systems)
 * - Frameworks (LangChain, CrewAI, LangGraph, etc.)
 * - Dependencies (pip, npm packages)
 *
 * Output formats: CycloneDX (recommended), SPDX, JSON
 * Gartner-recommended capability for AI supply chain visibility.
 */

import { z } from 'zod';

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import type { MlComponent, Severity } from '../api/types.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

// =============================================================================
// Schema
// =============================================================================

const MlbomArgsSchema = z.object({
  path: z.string().describe('Path to agent codebase to analyze'),
  format: z
    .enum(['cyclonedx', 'spdx', 'json'])
    .optional()
    .default('cyclonedx')
    .describe('Output format: cyclonedx (recommended), spdx, or json'),
  include_vulnerabilities: z
    .boolean()
    .optional()
    .default(true)
    .describe('Include known vulnerabilities for detected components'),
});

type MlbomArgs = z.infer<typeof MlbomArgsSchema>;

// =============================================================================
// Helpers
// =============================================================================

function formatComponentType(type: MlComponent['type']): string {
  switch (type) {
    case 'model':
      return '🧠 Model';
    case 'tool':
      return '🔧 Tool';
    case 'data-source':
      return '💾 Data Source';
    case 'framework':
      return '📦 Framework';
    case 'dependency':
      return '📚 Dependency';
    default:
      return type;
  }
}

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

function formatRiskScore(score: number): string {
  if (score >= 90) {
    return `✅ ${score}/100 (Low Risk)`;
  } else if (score >= 70) {
    return `🟢 ${score}/100 (Moderate Risk)`;
  } else if (score >= 50) {
    return `🟡 ${score}/100 (Elevated Risk)`;
  } else if (score >= 30) {
    return `🟠 ${score}/100 (High Risk)`;
  } else {
    return `🔴 ${score}/100 (Critical Risk)`;
  }
}

function formatComponent(component: MlComponent, detailed: boolean): string {
  const typeLabel = formatComponentType(component.type);
  let output = `${typeLabel}: ${component.name}`;

  if (component.version !== undefined) {
    output += ` v${component.version}`;
  }

  output += '\n';

  if (component.provider !== undefined) {
    output += `   Provider: ${component.provider}\n`;
  }

  if (component.license !== undefined) {
    output += `   License: ${component.license}\n`;
  }

  output += `   📍 ${component.location}`;
  if (component.line !== undefined) {
    output += `:${component.line}`;
  }
  output += '\n';

  if (detailed && component.properties !== undefined && Object.keys(component.properties).length > 0) {
    output += '   Properties:\n';
    for (const [key, value] of Object.entries(component.properties)) {
      output += `     • ${key}: ${value}\n`;
    }
  }

  if (component.vulnerabilities !== undefined && component.vulnerabilities.length > 0) {
    output += '   ⚠️  Vulnerabilities:\n';
    for (const vuln of component.vulnerabilities) {
      const icon = formatSeverityIcon(vuln.severity);
      output += `     ${icon} ${vuln.id}: ${vuln.description}\n`;
      if (vuln.cve !== undefined) {
        output += `        CVE: ${vuln.cve}\n`;
      }
    }
  }

  return output;
}

function groupComponentsByType(components: MlComponent[]): Record<string, MlComponent[]> {
  const groups: Record<string, MlComponent[]> = {};

  for (const component of components) {
    const existing = groups[component.type];
    if (existing === undefined) {
      groups[component.type] = [component];
    } else {
      existing.push(component);
    }
  }

  return groups;
}

// =============================================================================
// Handler
// =============================================================================

async function mlbomHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  // Validate arguments
  const parseResult = MlbomArgsSchema.safeParse(rawArgs);
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

  const args: MlbomArgs = parseResult.data;

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

    // Call Inkog API - first scan, then generate MLBOM
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

    // Step 2: Use scan_id to generate MLBOM
    const response = await client.generateMlbom([], {
      format: args.format,
      includeVulnerabilities: args.include_vulnerabilities,
      scanId: scanResponse.scan_id,
    });

    // If format is CycloneDX or SPDX, return the pre-formatted content
    if (args.format !== 'json' && response.bomContent !== undefined) {
      let output = '╔══════════════════════════════════════════════════════╗\n';
      output += '║           📋 ML Bill of Materials (MLBOM)             ║\n';
      output += '╚══════════════════════════════════════════════════════╝\n\n';

      output += `📦 Format: ${args.format.toUpperCase()}\n`;
      output += `📅 Generated: ${response.generatedAt}\n`;
      output += `📊 Components: ${response.components.length}\n`;
      output += `⚠️  Vulnerabilities: ${response.vulnerabilityCount}\n`;
      output += `🔒 Risk Score: ${formatRiskScore(response.riskScore)}\n\n`;

      output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += `${args.format.toUpperCase()} Output:\n\n`;
      output += '```' + (args.format === 'cyclonedx' ? 'json' : 'xml') + '\n';
      output += response.bomContent + '\n';
      output += '```\n';

      return {
        content: [
          {
            type: 'text',
            text: output,
          },
        ],
      };
    }

    // Build human-readable output for JSON format
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           📋 ML Bill of Materials (MLBOM)             ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    output += `📦 Version: ${response.version}\n`;
    output += `📅 Generated: ${response.generatedAt}\n`;
    output += `📊 Total Components: ${response.components.length}\n`;
    output += `⚠️  Total Vulnerabilities: ${response.vulnerabilityCount}\n`;
    output += `🔒 Supply Chain Risk Score: ${formatRiskScore(response.riskScore)}\n\n`;

    // Component summary by type
    const groups = groupComponentsByType(response.components);
    output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📊 COMPONENT SUMMARY\n\n';

    const typeOrder: MlComponent['type'][] = ['model', 'tool', 'data-source', 'framework', 'dependency'];
    for (const type of typeOrder) {
      const components = groups[type];
      if (components !== undefined && components.length > 0) {
        output += `${formatComponentType(type)}: ${components.length}\n`;
      }
    }
    output += '\n';

    // Detailed component list
    if (response.components.length > 0) {
      // Models first (most important)
      if (groups.model !== undefined && groups.model.length > 0) {
        output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
        output += '🧠 MODELS\n\n';
        for (const component of groups.model) {
          output += formatComponent(component, true) + '\n';
        }
      }

      // Tools
      if (groups.tool !== undefined && groups.tool.length > 0) {
        output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
        output += '🔧 TOOLS\n\n';
        for (const component of groups.tool) {
          output += formatComponent(component, true) + '\n';
        }
      }

      // Data sources
      if (groups['data-source'] !== undefined && groups['data-source'].length > 0) {
        output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
        output += '💾 DATA SOURCES\n\n';
        for (const component of groups['data-source']) {
          output += formatComponent(component, true) + '\n';
        }
      }

      // Frameworks
      if (groups.framework !== undefined && groups.framework.length > 0) {
        output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
        output += '📦 FRAMEWORKS\n\n';
        for (const component of groups.framework) {
          output += formatComponent(component, false) + '\n';
        }
      }

      // Dependencies (less detailed)
      if (groups.dependency !== undefined && groups.dependency.length > 0) {
        output += '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
        output += '📚 DEPENDENCIES\n\n';

        // Only show vulnerable dependencies in detail
        const vulnerableDeps = groups.dependency.filter(
          (d) => d.vulnerabilities !== undefined && d.vulnerabilities.length > 0
        );
        const safeDeps = groups.dependency.filter(
          (d) => d.vulnerabilities === undefined || d.vulnerabilities.length === 0
        );

        if (vulnerableDeps.length > 0) {
          output += '⚠️  Vulnerable Dependencies:\n\n';
          for (const component of vulnerableDeps) {
            output += formatComponent(component, true) + '\n';
          }
        }

        if (safeDeps.length > 0) {
          output += 'Other Dependencies: ';
          output += safeDeps.map((d) => `${d.name}${d.version !== undefined ? `@${d.version}` : ''}`).join(', ');
          output += '\n';
        }
      }
    }

    // Footer with export hint
    output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n';
    output += '💡 TIP: Use format="cyclonedx" or format="spdx" for standard export\n';
    output += 'MLBOM generation powered by Inkog AI Security Platform\n';
    output += 'Learn more: https://inkog.io/mlbom\n';

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

export const mlbomTool: ToolDefinition = {
  tool: {
    name: 'inkog_generate_mlbom',
    description:
      'Generate a Machine Learning Bill of Materials (MLBOM) for AI agents. Lists all models, tools, data sources, frameworks, and dependencies with known vulnerabilities. Supports CycloneDX and SPDX formats for supply chain compliance.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to agent codebase to analyze',
        },
        format: {
          type: 'string',
          enum: ['cyclonedx', 'spdx', 'json'],
          default: 'cyclonedx',
          description: 'Output format: cyclonedx (recommended), spdx, or json',
        },
        include_vulnerabilities: {
          type: 'boolean',
          default: true,
          description: 'Include known vulnerabilities for detected components',
        },
      },
      required: ['path'],
    },
  },
  handler: mlbomHandler,
};
