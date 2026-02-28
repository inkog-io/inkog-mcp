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
import type {
  MLBOMComponent,
  MlbomCompleteness,
  MlbomResponse,
  MLBOMSummary,
} from '../api/types.js';
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

type ComponentType = 'model' | 'tool' | 'data-source' | 'framework' | 'dependency';

function formatComponentType(type: string): string {
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
      return `📋 ${type}`;
  }
}

function formatSummaryScore(summary: MLBOMSummary): string {
  const total = summary.total_components;
  if (total === 0) {
    return '⚪ No components detected';
  }
  if (total <= 5) {
    return `✅ ${total} components (minimal footprint)`;
  }
  if (total <= 15) {
    return `🟢 ${total} components (moderate complexity)`;
  }
  if (total <= 30) {
    return `🟡 ${total} components (elevated complexity)`;
  }
  return `🟠 ${total} components (high complexity)`;
}

function formatComponent(component: MLBOMComponent, detailed: boolean): string {
  const typeLabel = formatComponentType(component.type);
  let output = `${typeLabel}: ${component.name}`;

  if (component.version) {
    output += ` v${component.version}`;
  }

  output += '\n';

  if (detailed) {
    if (component.supplier) {
      output += `   Supplier: ${component.supplier.name}`;
      if (component.supplier.url) {
        output += ` (${component.supplier.url})`;
      }
      output += '\n';
    }

    if (component.licenses && component.licenses.length > 0) {
      output += `   License: ${component.licenses.join(', ')}\n`;
    }

    if (component.description) {
      output += `   Description: ${component.description}\n`;
    }

    if (component.properties && Object.keys(component.properties).length > 0) {
      output += '   Properties:\n';
      for (const [key, value] of Object.entries(component.properties)) {
        output += `     • ${key}: ${value}\n`;
      }
    }

    if (component.external_refs && component.external_refs.length > 0) {
      output += '   References:\n';
      for (const ref of component.external_refs) {
        output += `     • ${ref.type}: ${ref.url}\n`;
      }
    }
  }

  return output;
}

function groupComponentsByType(components: MLBOMComponent[]): Record<string, MLBOMComponent[]> {
  const groups: Record<string, MLBOMComponent[]> = {};

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

function formatCompleteness(completeness: MlbomCompleteness): string {
  let output = '📊 Data Sources:\n';
  output += `   From topology analysis: ${completeness.from_topology}\n`;
  output += `   From findings analysis: ${completeness.from_findings}\n`;
  output += `   Topology nodes scanned: ${completeness.topology_nodes}\n`;
  output += `   Security findings: ${completeness.findings_count}\n`;
  return output;
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
    const response: MlbomResponse = await client.generateMlbom([], {
      format: args.format,
      includeVulnerabilities: args.include_vulnerabilities,
      scanId: scanResponse.scan_id,
    });

    // Build header
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           📋 ML Bill of Materials (MLBOM)             ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';

    output += `📦 Format: ${response.format.toUpperCase()}\n`;
    output += `📅 Generated: ${response.generated_at}\n`;

    if (response.report_id) {
      output += `🔗 Report ID: ${response.report_id}\n`;
    }

    // Summary statistics
    output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
    output += '📊 COMPONENT SUMMARY\n\n';
    output += formatSummaryScore(response.summary) + '\n\n';

    if (response.summary.total_components > 0) {
      if (response.summary.models > 0) {
        output += `   🧠 Models: ${response.summary.models}\n`;
      }
      if (response.summary.frameworks > 0) {
        output += `   📦 Frameworks: ${response.summary.frameworks}\n`;
      }
      if (response.summary.tools > 0) {
        output += `   🔧 Tools: ${response.summary.tools}\n`;
      }
      if (response.summary.data_sources > 0) {
        output += `   💾 Data Sources: ${response.summary.data_sources}\n`;
      }
      if (response.summary.dependencies > 0) {
        output += `   📚 Dependencies: ${response.summary.dependencies}\n`;
      }
    }

    // Warning if applicable
    if (response.warning) {
      output += '\n⚠️  WARNING: ' + response.warning + '\n';
    }

    // Completeness metrics if available
    if (response.completeness) {
      output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += formatCompleteness(response.completeness);
    }

    // Handle different output formats
    if (args.format !== 'json' && response.bom) {
      // CycloneDX or SPDX format - show the structured BOM
      output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';
      output += `${args.format.toUpperCase()} Output:\n\n`;
      output += '```json\n';
      output += typeof response.bom === 'string'
        ? response.bom
        : JSON.stringify(response.bom, null, 2);
      output += '\n```\n';
    } else if (response.components && response.components.length > 0) {
      // JSON format with detailed component list
      const groups = groupComponentsByType(response.components);
      const typeOrder: ComponentType[] = ['model', 'tool', 'data-source', 'framework', 'dependency'];

      for (const type of typeOrder) {
        const components = groups[type];
        if (components && components.length > 0) {
          output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';

          switch (type) {
            case 'model':
              output += '🧠 MODELS\n\n';
              break;
            case 'tool':
              output += '🔧 TOOLS\n\n';
              break;
            case 'data-source':
              output += '💾 DATA SOURCES\n\n';
              break;
            case 'framework':
              output += '📦 FRAMEWORKS\n\n';
              break;
            case 'dependency':
              output += '📚 DEPENDENCIES\n\n';
              break;
          }

          // Show detailed info for models/tools, compact for dependencies
          const showDetailed = type === 'model' || type === 'tool' || type === 'data-source';
          for (const component of components) {
            output += formatComponent(component, showDetailed) + '\n';
          }
        }
      }
    }

    // Footer
    output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n';
    output += '💡 TIP: Use format="cyclonedx" for SBOM compliance tooling\n';
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
      'Generate a Machine Learning Bill of Materials (MLBOM) for AI agents. Lists all models, tools, data sources, frameworks, and dependencies. Supports CycloneDX and SPDX formats. Use this when documenting AI agent dependencies for supply chain compliance.',
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
