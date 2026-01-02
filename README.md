# Inkog MCP Server

AI Security Platform for the Agentic Era - Available in Claude, ChatGPT, Cursor, and any MCP-compatible client.

[![npm version](https://img.shields.io/npm/v/@inkog-io/mcp)](https://www.npmjs.com/package/@inkog-io/mcp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-brightgreen.svg)](https://modelcontextprotocol.io)

## What is Inkog?

Inkog is the **AI Security Platform (AISP)** for securing AI agents. It provides:

- **Vulnerability Scanning**: Detect prompt injection, infinite loops, token bombing, SQL injection via LLM
- **AGENTS.md Governance**: Validate that code behavior matches governance declarations
- **Compliance Reporting**: Generate reports for EU AI Act, NIST AI RMF, ISO 42001, OWASP LLM Top 10
- **MCP Server Auditing**: Security audit any MCP server from the registry
- **MLBOM Generation**: Create Machine Learning Bill of Materials for supply chain visibility
- **Multi-Agent Security**: Audit Agent-to-Agent communications for security risks

## Installation

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "inkog": {
      "command": "npx",
      "args": ["-y", "@inkog-io/mcp"],
      "env": {
        "INKOG_API_KEY": "sk_live_your_api_key"
      }
    }
  }
}
```

### Cursor

Add to your Cursor MCP settings:

```json
{
  "mcpServers": {
    "inkog": {
      "command": "npx",
      "args": ["-y", "@inkog-io/mcp"],
      "env": {
        "INKOG_API_KEY": "sk_live_your_api_key"
      }
    }
  }
}
```

### Global Installation

```bash
npm install -g @inkog-io/mcp
```

## Getting Your API Key

1. Sign up for free at [app.inkog.io](https://app.inkog.io)
2. Copy your API key from the dashboard
3. Set it as `INKOG_API_KEY` environment variable

## Available Tools

### P0 - Core Security (Essential)

| Tool | Description |
|------|-------------|
| `inkog_scan` | Scan AI agent code for security vulnerabilities |
| `inkog_verify_governance` | Validate AGENTS.md declarations match actual code behavior |

### P1 - Enterprise Features

| Tool | Description |
|------|-------------|
| `inkog_compliance_report` | Generate EU AI Act, NIST, OWASP compliance reports |
| `inkog_explain_finding` | Get detailed remediation guidance for findings |
| `inkog_audit_mcp_server` | Security audit any MCP server |
| `inkog_generate_mlbom` | Generate ML Bill of Materials (CycloneDX, SPDX) |

### P2 - Multi-Agent Security

| Tool | Description |
|------|-------------|
| `inkog_audit_a2a` | Audit Agent-to-Agent communications |

## Tool Details

### inkog_scan

Scan AI agent code for security vulnerabilities.

```
Arguments:
  path     (required) File or directory path to scan
  policy   (optional) Security policy: low-noise, balanced, comprehensive, governance, eu-ai-act
  output   (optional) Output format: summary, detailed, sarif
```

**Example**: "Scan my LangChain agent for vulnerabilities"

### inkog_verify_governance

Validate that AGENTS.md declarations match actual code behavior. **This is Inkog's unique differentiator** - no other tool does governance verification.

```
Arguments:
  path     (required) Path to directory containing AGENTS.md and agent code
```

**Example**: "Verify my agent's governance declarations"

### inkog_compliance_report

Generate compliance reports for regulatory frameworks.

```
Arguments:
  path      (required) Path to scan
  framework (optional) eu-ai-act, nist-ai-rmf, iso-42001, owasp-llm-top-10, all
  format    (optional) markdown, json, pdf
```

**Example**: "Generate an EU AI Act compliance report for my agent"

### inkog_explain_finding

Get detailed explanation and remediation guidance for a security finding.

```
Arguments:
  finding_id (optional) Finding ID from scan results
  pattern    (optional) Pattern name (e.g., prompt-injection, infinite-loop)
```

**Example**: "Explain how to fix prompt injection vulnerabilities"

### inkog_audit_mcp_server

Security audit any MCP server from the registry or GitHub.

```
Arguments:
  server_name    (optional) MCP server name from registry (e.g., "github", "slack")
  repository_url (optional) Direct GitHub repository URL
```

**Example**: "Audit the GitHub MCP server for security issues"

### inkog_generate_mlbom

Generate a Machine Learning Bill of Materials listing all AI components.

```
Arguments:
  path                     (required) Path to agent codebase
  format                   (optional) cyclonedx, spdx, json
  include_vulnerabilities  (optional) Include known CVEs (default: true)
```

**Example**: "Generate an MLBOM for my AI project"

### inkog_audit_a2a

Audit Agent-to-Agent communications for security risks.

```
Arguments:
  path                    (required) Path to multi-agent codebase
  protocol                (optional) a2a, crewai, langgraph, auto-detect
  check_delegation_chains (optional) Check for infinite loops (default: true)
```

**Example**: "Audit my CrewAI multi-agent system for security risks"

## Supported Frameworks

Inkog works with all major AI agent frameworks:

- LangChain / LangGraph
- CrewAI
- AutoGen
- n8n
- Flowise
- Dify
- Microsoft Copilot Studio
- Custom implementations

## Configuration

All configuration is done via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `INKOG_API_KEY` | Your API key (required) | - |
| `INKOG_API_URL` | API base URL | `https://api.inkog.io` |
| `INKOG_API_VERSION` | API version | `v1` |
| `INKOG_API_TIMEOUT` | Request timeout (ms) | `30000` |
| `INKOG_LOG_LEVEL` | Log level | `info` |
| `INKOG_LOG_FORMAT` | Log format (json/text) | `json` |

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run in development mode
npm run dev

# Run tests
npm test

# Lint
npm run lint
```

## Why Inkog?

### The Only Tool with AGENTS.md Verification

Inkog is the **only security tool** that can validate your agent's governance declarations against its actual code behavior. This is essential for:

- **EU AI Act Article 14** compliance (human oversight)
- **Enterprise governance** requirements
- **Preventing governance drift** as code evolves

### Purpose-Built for AI Agents

Unlike traditional security scanners (Snyk, Semgrep, SonarQube), Inkog understands AI-specific vulnerabilities:

- Prompt injection attacks
- Infinite loops and token bombing
- SQL injection via LLM output
- Cross-tenant data leakage
- Recursive tool calling

### Multi-Framework Support

Inkog's Universal IR (Intermediate Representation) works with any agent framework. Add one integration, get security for all frameworks.

## License

Apache-2.0 - see [LICENSE](LICENSE)

## Links

- [Documentation](https://docs.inkog.io)
- [Dashboard](https://app.inkog.io)
- [Website](https://inkog.io)
- [GitHub](https://github.com/inkog-io/inkog-mcp)

---

Built with security by [Inkog.io](https://inkog.io)
