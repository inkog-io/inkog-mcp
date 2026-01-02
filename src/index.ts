#!/usr/bin/env node
/**
 * Inkog MCP Server
 *
 * AI Security Platform for the Agentic Era
 *
 * This MCP server provides AI agent security capabilities:
 * - Vulnerability scanning (prompt injection, infinite loops, token bombing)
 * - AGENTS.md governance verification
 * - Compliance reporting (EU AI Act, NIST, OWASP)
 * - MCP server security auditing
 * - ML Bill of Materials (MLBOM) generation
 * - Agent-to-Agent communication security
 *
 * @author Inkog.io
 * @license Apache-2.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { getConfig, getApiKey } from './config.js';
import { callTool, getToolList, registeredToolCount } from './tools/index.js';

// =============================================================================
// Server Setup
// =============================================================================

const config = getConfig();

/**
 * Create and configure the MCP server
 * Note: Using Server (not McpServer) for advanced request handling capabilities
 */
// eslint-disable-next-line @typescript-eslint/no-deprecated
function createServer(): Server {
  // eslint-disable-next-line @typescript-eslint/no-deprecated
  const server = new Server(
    {
      name: config.serverName,
      version: config.serverVersion,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // ---------------------------------------------------------------------------
  // Request Handlers
  // ---------------------------------------------------------------------------

  /**
   * Handle tool listing requests
   */
  server.setRequestHandler(ListToolsRequestSchema, () => {
    const tools = getToolList();

    // Log tool count in debug mode
    if (config.logLevel === 'debug') {
      logDebug('ListTools', `Returning ${tools.length} tools`);
    }

    return { tools };
  });

  /**
   * Handle tool execution requests
   */
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // Log tool call in debug mode
    if (config.logLevel === 'debug') {
      logDebug('CallTool', `Executing tool: ${name}`);
    }

    // Execute the tool
    const result = await callTool(name, args ?? {});

    // Convert our internal result format to MCP format
    return {
      content: result.content.map((item) => {
        if (item.type === 'text') {
          return {
            type: 'text' as const,
            text: item.text ?? '',
          };
        }
        if (item.type === 'image') {
          return {
            type: 'image' as const,
            data: item.data ?? '',
            mimeType: item.mimeType ?? 'image/png',
          };
        }
        // Resource type - convert to text for now
        return {
          type: 'text' as const,
          text: item.text ?? '',
        };
      }),
      isError: result.isError,
    };
  });

  return server;
}

// =============================================================================
// Logging Utilities
// =============================================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const logLevelOrder: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function shouldLog(level: LogLevel): boolean {
  return logLevelOrder[level] >= logLevelOrder[config.logLevel];
}

function formatLogMessage(level: LogLevel, context: string, message: string): string {
  const timestamp = new Date().toISOString();

  if (config.logFormat === 'json') {
    return JSON.stringify({
      timestamp,
      level,
      context,
      message,
      server: config.serverName,
      version: config.serverVersion,
    });
  }

  return `[${timestamp}] [${level.toUpperCase()}] [${context}] ${message}`;
}

function log(level: LogLevel, context: string, message: string): void {
  if (shouldLog(level)) {
    console.error(formatLogMessage(level, context, message));
  }
}

function logDebug(context: string, message: string): void {
  log('debug', context, message);
}

function logInfo(context: string, message: string): void {
  log('info', context, message);
}

function logError(context: string, message: string): void {
  log('error', context, message);
}

// =============================================================================
// Startup Banner
// =============================================================================

function printBanner(): void {
  if (config.logLevel === 'debug' || config.logLevel === 'info') {
    const banner = `
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗███╗   ██╗██╗  ██╗ ██████╗  ██████╗                         ║
║   ██║████╗  ██║██║ ██╔╝██╔═══██╗██╔════╝                         ║
║   ██║██╔██╗ ██║█████╔╝ ██║   ██║██║  ███╗                        ║
║   ██║██║╚██╗██║██╔═██╗ ██║   ██║██║   ██║                        ║
║   ██║██║ ╚████║██║  ██╗╚██████╔╝╚██████╔╝                        ║
║   ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝                         ║
║                                                                  ║
║   AI Security Platform for the Agentic Era                       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
`;
    console.error(banner);
  }
}

// =============================================================================
// Main Entry Point
// =============================================================================

async function main(): Promise<void> {
  printBanner();

  // Check for API key
  const apiKey = getApiKey();
  if (apiKey === undefined) {
    logInfo('Startup', 'No API key configured. Set INKOG_API_KEY environment variable.');
    logInfo('Startup', 'Get your free API key at https://app.inkog.io');
  } else {
    logDebug('Startup', 'API key configured');
  }

  // Create and start server
  logInfo('Startup', `Starting Inkog MCP Server v${config.serverVersion}`);
  logInfo('Startup', `Registered ${registeredToolCount} tools`);
  logDebug('Startup', `API endpoint: ${config.apiBaseUrl}/${config.apiVersion}`);

  const server = createServer();
  const transport = new StdioServerTransport();

  // Handle graceful shutdown
  const handleShutdown = (signal: string): void => {
    logInfo('Shutdown', `Received ${signal}, shutting down...`);
    server.close().then(() => {
      process.exit(0);
    }).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      logError('Shutdown', `Error during shutdown: ${message}`);
      process.exit(1);
    });
  };

  process.on('SIGINT', () => { handleShutdown('SIGINT'); });
  process.on('SIGTERM', () => { handleShutdown('SIGTERM'); });

  // Connect and run
  try {
    await server.connect(transport);
    logInfo('Startup', 'MCP Server connected and ready');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logError('Startup', `Failed to start server: ${message}`);
    process.exit(1);
  }
}

// Run the server
main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  logError('Fatal', message);
  process.exit(1);
});
