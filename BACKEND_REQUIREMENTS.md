# Backend API Requirements for MCP Server

This document lists the backend API endpoints required for the MCP server to function.

## Critical Information

**The MCP server is a thin wrapper around the Inkog backend API.** All detection logic, compliance mapping, and analysis is performed by the backend. The MCP server simply provides an MCP-compatible interface.

## Required API Endpoints

### Currently Implemented (Working)

| Tool | Endpoint | Method | Status |
|------|----------|--------|--------|
| `inkog_scan` | `/v1/scan` | POST | **Working** |

### Required (Not Yet Implemented)

| Tool | Endpoint | Method | Priority |
|------|----------|--------|----------|
| `inkog_verify_governance` | `/v1/governance/verify` | POST | **P0 - Critical** |
| `inkog_compliance_report` | `/v1/compliance/report` | POST | P1 |
| `inkog_explain_finding` | `/v1/findings/{id}/explain` | GET | P1 |
| `inkog_audit_mcp_server` | `/v1/mcp/audit` | POST | P1 |
| `inkog_generate_mlbom` | `/v1/mlbom/generate` | POST | P1 |
| `inkog_audit_a2a` | `/v1/a2a/audit` | POST | P2 |

## Endpoint Specifications

### POST /v1/governance/verify

**Purpose**: Validate AGENTS.md declarations against actual code behavior.

**Request Body**:
```json
{
  "path": "/path/to/agent/directory",
  "files": [
    {
      "path": "relative/path/file.py",
      "content": "base64_encoded_content"
    }
  ],
  "agents_md": {
    "path": "AGENTS.md",
    "content": "base64_encoded_content"
  }
}
```

**Response**:
```json
{
  "success": true,
  "overall_status": "valid" | "invalid" | "partial",
  "score": 85,
  "declared_capabilities": [
    {
      "name": "read-only",
      "constraint_type": "ConstraintNoWrite",
      "status": "valid" | "violated",
      "line": 15
    }
  ],
  "mismatches": [
    {
      "capability": "read-only",
      "expected": "No write operations",
      "actual": "Found file write at agent.py:45",
      "severity": "high",
      "file": "agent.py",
      "line": 45
    }
  ],
  "recommendations": [
    "Update AGENTS.md to declare write capability"
  ]
}
```

**Backend Implementation Notes**:
- Reuse existing `pkg/parsers/agents_md.go` for parsing
- Reuse `pkg/governance/aggregator.go` for mismatch detection
- Convert IR findings to governance response format

### POST /v1/compliance/report

**Purpose**: Generate compliance report for various frameworks.

**Request Body**:
```json
{
  "path": "/path/to/scan",
  "files": [...],
  "framework": "eu-ai-act" | "nist-ai-rmf" | "iso-42001" | "owasp-llm-top-10",
  "format": "markdown" | "json" | "pdf"
}
```

**Response**:
```json
{
  "success": true,
  "framework": "eu-ai-act",
  "overall_score": 72,
  "risk_level": "medium",
  "articles": [
    {
      "id": "Article 14",
      "title": "Human Oversight",
      "status": "partial",
      "score": 60,
      "findings": [
        {
          "id": "finding-123",
          "requirement": "Human approval for high-risk actions",
          "status": "non-compliant",
          "evidence": "No human approval gate found for data deletion"
        }
      ],
      "recommendations": [
        "Implement human-in-the-loop for irreversible actions"
      ]
    }
  ],
  "summary": "Agent partially complies with EU AI Act requirements..."
}
```

**Backend Implementation Notes**:
- Extend `pkg/governance/aggregator.go` compliance mapping
- Add new compliance framework mappings (NIST, ISO)
- Generate formatted reports

### GET /v1/findings/{id}/explain

**Purpose**: Get detailed explanation and remediation for a finding.

**Path Parameters**:
- `id`: Finding ID or pattern name (e.g., `prompt-injection`, `infinite-loop`)

**Response**:
```json
{
  "success": true,
  "pattern": "prompt-injection",
  "title": "Prompt Injection Vulnerability",
  "severity": "high",
  "description": "User-controlled input is directly concatenated into the system prompt...",
  "impact": "Attackers can manipulate the AI agent's behavior...",
  "examples": {
    "vulnerable": "prompt = f\"You are a {user_input} assistant\"",
    "secure": "prompt = f\"You are a {sanitize(user_input)} assistant\""
  },
  "remediation": [
    "Never concatenate user input directly into system prompts",
    "Use parameterized prompts or input sanitization",
    "Implement output validation"
  ],
  "references": [
    {
      "title": "OWASP LLM Top 10: LLM01 Prompt Injection",
      "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    }
  ],
  "cwe": "CWE-94",
  "owasp": "LLM01"
}
```

**Backend Implementation Notes**:
- Add pattern metadata to existing detector definitions
- Expose remediation guidance via API

### POST /v1/mcp/audit

**Purpose**: Security audit an MCP server from registry or GitHub.

**Request Body**:
```json
{
  "server_name": "github",  // From MCP registry
  // OR
  "repository_url": "https://github.com/org/repo"
}
```

**Response**:
```json
{
  "success": true,
  "server": {
    "name": "github",
    "version": "1.0.0",
    "repository": "https://github.com/modelcontextprotocol/servers"
  },
  "audit_results": {
    "overall_risk": "medium",
    "security_score": 75,
    "tool_count": 12,
    "tools_analyzed": [...]
  },
  "findings": [...],
  "permissions": {
    "file_access": true,
    "network_access": true,
    "code_execution": false
  },
  "recommendations": [
    "Implement rate limiting for API calls"
  ]
}
```

**Backend Implementation Notes**:
- Fetch MCP server from registry API
- Clone repository temporarily for analysis
- Apply existing detection patterns to MCP server code
- Special handling for MCP tool definitions

### POST /v1/mlbom/generate

**Purpose**: Generate ML Bill of Materials in CycloneDX or SPDX format.

**Request Body**:
```json
{
  "path": "/path/to/agent",
  "files": [...],
  "format": "cyclonedx" | "spdx" | "json"
}
```

**Response**:
```json
{
  "success": true,
  "format": "cyclonedx",
  "bom": {
    "$schema": "...",
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
      {
        "type": "machine-learning-model",
        "name": "gpt-4",
        "version": "latest",
        "supplier": { "name": "OpenAI" }
      },
      {
        "type": "framework",
        "name": "langchain",
        "version": "0.1.0"
      }
    ]
  },
  "summary": {
    "total_components": 15,
    "models": 2,
    "frameworks": 3,
    "tools": 5,
    "dependencies": 5
  }
}
```

**Backend Implementation Notes**:
- Create new `pkg/mlbom/` package
- Extract model references from IR nodes (LLMCallNode)
- Extract tool definitions from IR nodes (ToolCallNode)
- Parse requirements.txt, pyproject.toml for dependencies
- Generate CycloneDX/SPDX formatted output

### POST /v1/a2a/audit

**Purpose**: Audit Agent-to-Agent communications in multi-agent systems.

**Request Body**:
```json
{
  "path": "/path/to/multi-agent-system",
  "files": [...],
  "protocol": "a2a" | "crewai" | "langgraph" | "auto-detect"
}
```

**Response**:
```json
{
  "success": true,
  "protocol": "crewai",
  "agents": [
    {
      "name": "Researcher",
      "role": "Research Assistant",
      "tools": ["search", "browse"],
      "delegation_targets": ["Writer"]
    }
  ],
  "communications": [
    {
      "from": "Researcher",
      "to": "Writer",
      "type": "delegation",
      "has_guards": true
    }
  ],
  "findings": [
    {
      "type": "infinite-delegation",
      "severity": "high",
      "description": "Circular delegation detected: A -> B -> C -> A",
      "agents_involved": ["A", "B", "C"]
    }
  ],
  "risk_assessment": {
    "overall_risk": "medium",
    "trust_boundary_violations": 0,
    "unguarded_delegations": 2
  }
}
```

**Backend Implementation Notes**:
- Extend existing multi-agent detection in `pkg/ir/adapters/`
- Add A2A protocol adapter
- Detect delegation chains, privilege escalation
- Build agent communication graph

## Implementation Priority

1. **Phase 1 (P0)**: Governance verification - This is Inkog's MOAT
2. **Phase 2 (P1)**: Compliance, Explain, MCP Audit, MLBOM - Enterprise features
3. **Phase 3 (P2)**: A2A Audit - Multi-agent security

## Notes

- All endpoints require `Authorization: Bearer sk_live_xxx` header
- All endpoints follow existing error response format
- File content should be base64 encoded to preserve formatting
- Large directories should be handled with pagination or streaming
