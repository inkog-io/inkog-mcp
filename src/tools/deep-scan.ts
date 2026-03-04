import path from 'node:path';

import { z } from 'zod';

import {
  getClient,
  InkogApiError,
  InkogAuthError,
  InkogNetworkError,
  InkogRateLimitError,
} from '../api/client.js';
import { getRelativePaths, readDirectory } from '../utils/file-reader.js';
import type { ToolDefinition, ToolResult } from './index.js';

const DeepScanArgsSchema = z.object({
  path: z.string().describe('File or directory path to scan'),
  agent_name: z
    .string()
    .optional()
    .describe('Agent name for dashboard identification (auto-detected from path if not provided)'),
});

type DeepScanArgs = z.infer<typeof DeepScanArgsSchema>;

const POLL_INTERVAL_MS = 5000;
const MAX_POLL_DURATION_MS = 30 * 60 * 1000; // 30 minutes

async function deepScanHandler(rawArgs: Record<string, unknown>): Promise<ToolResult> {
  const parseResult = DeepScanArgsSchema.safeParse(rawArgs);
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

  const args: DeepScanArgs = parseResult.data;

  try {
    const readResult = readDirectory(args.path);

    if (readResult.files.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No scannable files found in: ${args.path}\n\nSupported file types: .py, .js, .ts, .go, .java, .rb, .yaml, .json, .md`,
          },
        ],
      };
    }

    const files = getRelativePaths(readResult.files, args.path);
    const agentName = args.agent_name ?? path.basename(args.path).replace(/\.[^.]+$/, '') ?? undefined;

    const client = getClient();
    const triggerResponse = await client.triggerDeepScan(files, {
      agentName,
    });

    const startTime = Date.now();
    const deadline = startTime + MAX_POLL_DURATION_MS;
    let statusResponse;

    while (Date.now() < deadline) {
      await sleep(POLL_INTERVAL_MS);

      try {
        statusResponse = await client.getDeepScanStatus(triggerResponse.scan_id);
      } catch {
        continue;
      }

      if (statusResponse.status === 'completed') {
        break;
      }

      if (statusResponse.status === 'failed') {
        let errorMsg = 'Unknown error';
        if (statusResponse.scan?.error) {
          errorMsg = typeof statusResponse.scan.error === 'string'
            ? statusResponse.scan.error
            : JSON.stringify(statusResponse.scan.error);
        } else if (statusResponse.scan?.user_agent && typeof statusResponse.scan.user_agent === 'string') {
          const ua = statusResponse.scan.user_agent;
          if (ua.startsWith('deep-checks-error: ')) {
            errorMsg = ua.replace('deep-checks-error: ', '');
          }
        }
        return {
          content: [
            {
              type: 'text',
              text: `Deep scan failed: ${errorMsg}`,
            },
          ],
          isError: true,
        };
      }
    }

    if (statusResponse?.status !== 'completed') {
      return {
        content: [
          {
            type: 'text',
            text: `Deep scan timed out after 30 minutes. The scan may still be running — check results at:\nhttps://app.inkog.io/dashboard/results/${triggerResponse.scan_id}`,
          },
        ],
        isError: true,
      };
    }

    const elapsedSecs = Math.round((Date.now() - startTime) / 1000);
    const elapsedMin = Math.floor(elapsedSecs / 60);
    const elapsedSecRem = elapsedSecs % 60;
    const elapsedStr = `${elapsedMin}m${String(elapsedSecRem).padStart(2, '0')}s`;

    const scan = statusResponse.scan;
    let output = '╔══════════════════════════════════════════════════════╗\n';
    output += '║           🔬 Inkog Deep Scan Results                ║\n';
    output += '╚══════════════════════════════════════════════════════╝\n\n';
    output += `Completed in ${elapsedStr}\n\n`;

    if (scan) {
      const filesScanned = asNumber(scan.files_scanned);
      const riskScore = asNumber(scan.risk_score);
      const findingsCount = asNumber(scan.findings_count);
      const criticalCount = asNumber(scan.critical_count);
      const highCount = asNumber(scan.high_count);
      const mediumCount = asNumber(scan.medium_count);
      const lowCount = asNumber(scan.low_count);

      output += `📁 Files scanned: ${filesScanned}\n`;
      output += `📊 Risk score: ${riskScore}/100\n`;

      if (scan.governance_score !== undefined && scan.governance_score !== null) {
        output += `🏛️  Governance score: ${asNumber(scan.governance_score)}/100\n`;
      }

      output += '\n';

      if (findingsCount === 0) {
        output += '✅ No security findings detected!\n';
      } else {
        output += `📋 Total findings: ${findingsCount}\n`;
        output += `   🔴 Critical: ${criticalCount} | 🟠 High: ${highCount} | 🟡 Medium: ${mediumCount} | 🟢 Low: ${lowCount}\n`;
      }

      const findings = extractDeepFindings(scan);
      if (findings.length > 0) {
        output += '\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n';

        for (const f of findings) {
          const severity = asString(f.severity).toUpperCase();
          const title = asString(f.title) || asString(f.description) || 'Unknown finding';
          const file = f.file ? asString(f.file) : undefined;
          const line = f.line ? Number(f.line) : undefined;
          const category = f.category ? asString(f.category) : undefined;
          const remediation = f.remediation ? asString(f.remediation) : undefined;

          const icon = severityIcon(severity);
          output += `${icon} [${severity}] ${title}\n`;
          if (file) {
            output += line ? `   📍 ${file}:${line}\n` : `   📍 ${file}\n`;
          }
          if (category) {
            output += `   📊 ${category}\n`;
          }
          if (remediation) {
            output += `   💡 ${remediation}\n`;
          }
          output += '\n';
        }
      }
    }

    output += `View full results: https://app.inkog.io/dashboard/results/${statusResponse.scan_id}\n`;

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

    if (error instanceof InkogApiError && error.statusCode === 403) {
      return {
        content: [
          {
            type: 'text',
            text: '🔒 Deep scan requires the Inkog Deep role.\n\nContact your admin to enable it at https://app.inkog.io',
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
            text: `Network error: ${error.message}\n\nPlease check your internet connection and try again.`,
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function severityIcon(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '🔴';
    case 'HIGH': return '🟠';
    case 'MEDIUM': return '🟡';
    case 'LOW': return '🟢';
    default: return '⚪';
  }
}

function asNumber(v: unknown): number {
  if (typeof v === 'number') return v;
  return 0;
}

function asString(v: unknown): string {
  if (typeof v === 'string') return v;
  return '';
}

function extractDeepFindings(scan: Record<string, unknown>): Record<string, unknown>[] {
  const findingsRaw = scan.findings;
  if (findingsRaw === undefined || findingsRaw === null) return [];

  let reportData: unknown = findingsRaw;

  if (typeof findingsRaw === 'string') {
    try {
      reportData = JSON.parse(findingsRaw);
    } catch {
      return [];
    }
  }

  if (typeof reportData === 'object' && reportData !== null && !Array.isArray(reportData)) {
    const report = reportData as Record<string, unknown>;
    if (Array.isArray(report.findings)) {
      return report.findings.filter((f): f is Record<string, unknown> => typeof f === 'object' && f !== null);
    }
    return [];
  }

  if (Array.isArray(reportData)) {
    return reportData.filter((f): f is Record<string, unknown> => typeof f === 'object' && f !== null);
  }

  return [];
}

export const deepScanTool: ToolDefinition = {
  tool: {
    name: 'inkog_deep_scan',
    description:
      'Inkog Deep scan for AI agents. Uses advanced analysis to detect complex vulnerabilities, logic flaws, and security issues that pattern-based scanning may miss. Requires the Inkog Deep role. IMPORTANT: Deep scans typically take around 10 minutes — inform the user before starting and let them know the scan is running.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'File or directory path to scan',
        },
        agent_name: {
          type: 'string',
          description: 'Agent name for dashboard identification (auto-detected from path if not provided)',
        },
      },
      required: ['path'],
    },
  },
  handler: deepScanHandler,
};
