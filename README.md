# Inkog MCP Server

Build secure AI agents from the start. Inkog is the security co-pilot for AI agent development — scan for vulnerabilities, verify AGENTS.md governance, audit MCP servers before installation, and map to EU AI Act compliance. Available in Claude, ChatGPT, Cursor, and any MCP-compatible client.

[![npm version](https://img.shields.io/npm/v/@inkog-io/mcp)](https://www.npmjs.com/package/@inkog-io/mcp)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-brightgreen.svg)](https://modelcontextprotocol.io)

## When to Use Inkog

- **Building an AI agent** — Scan during development to catch infinite loops, prompt injection, and missing guardrails before they ship
- **Adding security to CI/CD** — Add `inkog-io/inkog@v1` to GitHub Actions for automated security gates on every PR
- **Preparing for EU AI Act** — Generate compliance reports mapping your agent to Article 14, NIST AI RMF, OWASP LLM Top 10
- **Reviewing agent code** — Use from Claude Code, Cursor, or any MCP client to get security analysis while you code
- **Auditing MCP servers** — Check any MCP server for tool poisoning, privilege escalation, or data exfiltration before installing
- **Verifying AGENTS.md** — Validate that governance declarations match actual code behavior
- **Building multi-agent systems** — Detect delegation loops, privilege escalation, and unauthorized handoffs between agents

## What Inkog Does

- **Logic Flaw Detection**: Find infinite loops, recursion risks, and missing exit conditions
- **Security Analysis**: Detect prompt injection paths, unconstrained tools, and data leakage risks
- **AGENTS.md Governance**: Validate that code behavior matches governance declarations
- **Compliance Reporting**: Generate reports for EU AI Act, NIST AI RMF, OWASP LLM Top 10
- **MCP Server Auditing**: Audit any MCP server before installation
- **Multi-Agent Analysis**: Audit Agent-to-Agent communications for logic and security issues

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

### P0 - Core Analysis (Essential)

| Tool | Description |
|------|-------------|
| `inkog_scan` | Static analysis for logic flaws and security risks |
| `inkog_verify_governance` | Validate AGENTS.md declarations match actual code behavior |

### P1 - Enterprise Features

| Tool | Description |
|------|-------------|
| `inkog_compliance_report` | Generate EU AI Act, NIST, OWASP compliance reports |
| `inkog_explain_finding` | Get detailed remediation guidance for findings |
| `inkog_audit_mcp_server` | Audit any MCP server before installation |
| `inkog_generate_mlbom` | Generate ML Bill of Materials (CycloneDX, SPDX) |

### P2 - Multi-Agent Analysis

| Tool | Description |
|------|-------------|
| `inkog_audit_a2a` | Audit Agent-to-Agent communications |

## Tool Details

### inkog_scan

Static analysis for AI agent code - finds logic flaws and security risks.

```
Arguments:
  path     (required) File or directory path to scan
  policy   (optional) Analysis policy: low-noise, balanced, comprehensive, governance, eu-ai-act
  output   (optional) Output format: summary, detailed, sarif
```

**Example**: "Scan my LangChain agent for logic flaws"

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

### The Pre-Flight Check for AI Agents

Think of Inkog like the checklist pilots run before takeoff. You don't skip it even when you're confident. It verifies your agent is ready to ship.

### The Only Tool with AGENTS.md Verification

Inkog is the **only tool** that can validate your agent's governance declarations against its actual code behavior. This is essential for:

- **EU AI Act Article 14** compliance (human oversight)
- **Enterprise governance** requirements
- **Preventing governance drift** as code evolves

### Purpose-Built for AI Agents

Unlike traditional code scanners (Snyk, Semgrep, SonarQube), Inkog understands AI-specific issues:

- Infinite loops and recursion risks
- Prompt injection paths
- Unconstrained tool access
- Missing exit conditions
- Cross-tenant data leakage

### Multi-Framework Support

Inkog's Universal IR (Intermediate Representation) works with any agent framework. Add one integration, get analysis for all frameworks.

## License

Apache-2.0 - see [LICENSE](LICENSE)

## Links

- [Documentation](https://docs.inkog.io)
- [Dashboard](https://app.inkog.io)
- [Website](https://inkog.io)
- [GitHub](https://github.com/inkog-io/inkog-mcp)

---

Built with security by [Inkog.io](https://inkog.io)
