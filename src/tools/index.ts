/**
 * Tool Registry
 *
 * Central registry for all Inkog MCP tools.
 * Each tool is a self-contained module that registers itself here.
 *
 * Architecture:
 * - Tools are lazy-loaded to improve startup time
 * - Each tool defines its own schema and handler
 * - Registry provides a unified interface for the MCP server
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';

// =============================================================================
// Tool Types
// =============================================================================

export interface ToolDefinition {
  /** Tool metadata for MCP */
  tool: Tool;
  /** Handler function that processes tool calls */
  handler: ToolHandler;
}

export type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

export interface ToolResult {
  content: {
    type: 'text' | 'image' | 'resource';
    text?: string;
    data?: string;
    mimeType?: string;
  }[];
  isError?: boolean;
}

// =============================================================================
// Registry
// =============================================================================

const toolRegistry = new Map<string, ToolDefinition>();

/**
 * Register a tool with the registry
 */
export function registerTool(definition: ToolDefinition): void {
  toolRegistry.set(definition.tool.name, definition);
}

/**
 * Get a tool by name
 */
export function getTool(name: string): ToolDefinition | undefined {
  return toolRegistry.get(name);
}

/**
 * Get all registered tools
 */
export function getAllTools(): ToolDefinition[] {
  return Array.from(toolRegistry.values());
}

/**
 * Get tool metadata for MCP ListTools
 */
export function getToolList(): Tool[] {
  return getAllTools().map((def) => def.tool);
}

/**
 * Call a tool by name
 */
export async function callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
  const tool = getTool(name);

  if (tool === undefined) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: Unknown tool "${name}"`,
        },
      ],
      isError: true,
    };
  }

  try {
    return await tool.handler(args);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
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
// Tool Registration
// =============================================================================

// Import and register all tools
// This is done at module load time to ensure all tools are available

import { scanTool } from './scan.js';
import { governanceTool } from './governance.js';
import { complianceTool } from './compliance.js';
import { explainTool } from './explain.js';
import { auditMcpTool } from './audit-mcp.js';
import { mlbomTool } from './mlbom.js';
import { auditA2aTool } from './audit-a2a.js';

// Register all tools
registerTool(scanTool);
registerTool(governanceTool);
registerTool(complianceTool);
registerTool(explainTool);
registerTool(auditMcpTool);
registerTool(mlbomTool);
registerTool(auditA2aTool);

// Export tool count for debugging
export const registeredToolCount = toolRegistry.size;
