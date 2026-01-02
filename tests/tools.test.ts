import { describe, it, expect } from 'vitest';
import { getToolList, registeredToolCount } from '../src/tools/index.js';

describe('tools', () => {
  describe('getToolList', () => {
    it('returns array of tools', () => {
      const tools = getToolList();

      expect(Array.isArray(tools)).toBe(true);
      expect(tools.length).toBeGreaterThan(0);
    });

    it('each tool has required properties', () => {
      const tools = getToolList();

      for (const tool of tools) {
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');
        expect(typeof tool.name).toBe('string');
        expect(typeof tool.description).toBe('string');
        expect(typeof tool.inputSchema).toBe('object');
      }
    });

    it('contains expected tools', () => {
      const tools = getToolList();
      const toolNames = tools.map((t) => t.name);

      expect(toolNames).toContain('inkog_scan');
      expect(toolNames).toContain('inkog_verify_governance');
      expect(toolNames).toContain('inkog_compliance_report');
      expect(toolNames).toContain('inkog_explain_finding');
      expect(toolNames).toContain('inkog_audit_mcp_server');
      expect(toolNames).toContain('inkog_generate_mlbom');
      expect(toolNames).toContain('inkog_audit_a2a');
    });

    it('tool names follow naming convention', () => {
      const tools = getToolList();

      for (const tool of tools) {
        // Allow lowercase letters, digits, and underscores
        expect(tool.name).toMatch(/^inkog_[a-z0-9_]+$/);
      }
    });
  });

  describe('registeredToolCount', () => {
    it('matches actual tool list length', () => {
      const tools = getToolList();
      expect(registeredToolCount).toBe(tools.length);
    });

    it('is 7 tools total', () => {
      expect(registeredToolCount).toBe(7);
    });
  });

  describe('tool input schemas', () => {
    it('scan tool has path parameter', () => {
      const tools = getToolList();
      const scanTool = tools.find((t) => t.name === 'inkog_scan');

      expect(scanTool).toBeDefined();
      expect(scanTool?.inputSchema.properties).toHaveProperty('path');
      expect(scanTool?.inputSchema.required).toContain('path');
    });

    it('governance tool has path parameter', () => {
      const tools = getToolList();
      const governanceTool = tools.find((t) => t.name === 'inkog_verify_governance');

      expect(governanceTool).toBeDefined();
      expect(governanceTool?.inputSchema.properties).toHaveProperty('path');
      expect(governanceTool?.inputSchema.required).toContain('path');
    });

    it('compliance tool has path and framework parameters', () => {
      const tools = getToolList();
      const complianceTool = tools.find((t) => t.name === 'inkog_compliance_report');

      expect(complianceTool).toBeDefined();
      expect(complianceTool?.inputSchema.properties).toHaveProperty('path');
      expect(complianceTool?.inputSchema.properties).toHaveProperty('framework');
    });

    it('explain tool has finding_id or pattern parameters', () => {
      const tools = getToolList();
      const explainTool = tools.find((t) => t.name === 'inkog_explain_finding');

      expect(explainTool).toBeDefined();
      const props = explainTool?.inputSchema.properties ?? {};
      expect(props).toHaveProperty('finding_id');
      expect(props).toHaveProperty('pattern');
    });

    it('mcp audit tool has server_name or repository_url parameters', () => {
      const tools = getToolList();
      const mcpAuditTool = tools.find((t) => t.name === 'inkog_audit_mcp_server');

      expect(mcpAuditTool).toBeDefined();
      const props = mcpAuditTool?.inputSchema.properties ?? {};
      expect(props).toHaveProperty('server_name');
      expect(props).toHaveProperty('repository_url');
    });

    it('mlbom tool has path and format parameters', () => {
      const tools = getToolList();
      const mlbomTool = tools.find((t) => t.name === 'inkog_generate_mlbom');

      expect(mlbomTool).toBeDefined();
      expect(mlbomTool?.inputSchema.properties).toHaveProperty('path');
      expect(mlbomTool?.inputSchema.properties).toHaveProperty('format');
    });

    it('a2a audit tool has path parameter', () => {
      const tools = getToolList();
      const a2aTool = tools.find((t) => t.name === 'inkog_audit_a2a');

      expect(a2aTool).toBeDefined();
      expect(a2aTool?.inputSchema.properties).toHaveProperty('path');
    });
  });
});
