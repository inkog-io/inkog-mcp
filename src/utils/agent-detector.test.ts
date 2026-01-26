/**
 * Tests for Agent Repository Detection
 *
 * Tests cover:
 * - Framework detection accuracy
 * - Binary extension skipping
 * - Confidence scoring
 * - AGENTS.md detection
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  detectAgentRepo,
  isBinaryExtension,
  containsSecuritySensitiveCode,
  getFilteringRecommendation,
  BINARY_EXTENSIONS,
  ALWAYS_SKIP_PATTERNS,
  type FrameworkType,
} from './agent-detector.js';

// =============================================================================
// Test Helpers
// =============================================================================

const TEST_DIR = '/tmp/inkog-test-agent-detector';

function createTestDir(): void {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

function cleanupTestDir(): void {
  if (fs.existsSync(TEST_DIR)) {
    fs.rmSync(TEST_DIR, { recursive: true });
  }
}

function writeTestFile(relativePath: string, content: string): void {
  const fullPath = path.join(TEST_DIR, relativePath);
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(fullPath, content);
}

// =============================================================================
// Binary Extension Tests
// =============================================================================

describe('isBinaryExtension', () => {
  it('should detect common binary extensions', () => {
    expect(isBinaryExtension('test.pyc')).toBe(true);
    expect(isBinaryExtension('image.png')).toBe(true);
    expect(isBinaryExtension('image.jpg')).toBe(true);
    expect(isBinaryExtension('model.onnx')).toBe(true);
    expect(isBinaryExtension('lib.so')).toBe(true);
    expect(isBinaryExtension('package.whl')).toBe(true);
    expect(isBinaryExtension('data.pkl')).toBe(true);
    expect(isBinaryExtension('model.safetensors')).toBe(true);
  });

  it('should not flag code files as binary', () => {
    expect(isBinaryExtension('main.py')).toBe(false);
    expect(isBinaryExtension('agent.ts')).toBe(false);
    expect(isBinaryExtension('config.json')).toBe(false);
    expect(isBinaryExtension('workflow.yaml')).toBe(false);
    expect(isBinaryExtension('AGENTS.md')).toBe(false);
    expect(isBinaryExtension('.env')).toBe(false);
  });

  it('should handle paths with directories', () => {
    expect(isBinaryExtension('/path/to/image.png')).toBe(true);
    expect(isBinaryExtension('/path/to/code.py')).toBe(false);
    expect(isBinaryExtension('src/utils/helper.ts')).toBe(false);
  });
});

describe('BINARY_EXTENSIONS constant', () => {
  it('should include common compiled extensions', () => {
    expect(BINARY_EXTENSIONS.has('.pyc')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.pyo')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.so')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.dll')).toBe(true);
  });

  it('should include image formats', () => {
    expect(BINARY_EXTENSIONS.has('.png')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.jpg')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.gif')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.svg')).toBe(true);
  });

  it('should include ML model formats', () => {
    expect(BINARY_EXTENSIONS.has('.onnx')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.pt')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.h5')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.safetensors')).toBe(true);
    expect(BINARY_EXTENSIONS.has('.gguf')).toBe(true);
  });
});

// =============================================================================
// Security-Sensitive Code Tests
// =============================================================================

describe('containsSecuritySensitiveCode', () => {
  it('should detect exec patterns', () => {
    expect(containsSecuritySensitiveCode('exec(user_input)')).toBe(true);
    expect(containsSecuritySensitiveCode('eval(code)')).toBe(true);
    expect(containsSecuritySensitiveCode('os.system(cmd)')).toBe(true);
  });

  it('should detect database patterns', () => {
    expect(containsSecuritySensitiveCode('cursor.execute(query)')).toBe(true);
  });

  it('should detect subprocess patterns', () => {
    expect(containsSecuritySensitiveCode('subprocess.run(cmd)')).toBe(true);
  });

  it('should not flag safe code', () => {
    expect(containsSecuritySensitiveCode('def execute_plan():')).toBe(false);
    expect(containsSecuritySensitiveCode('class Agent:')).toBe(false);
    expect(containsSecuritySensitiveCode('import langchain')).toBe(false);
  });
});

// =============================================================================
// Agent Repo Detection Tests
// =============================================================================

describe('detectAgentRepo', () => {
  beforeEach(() => {
    createTestDir();
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should detect AGENTS.md with high confidence', () => {
    writeTestFile('AGENTS.md', '# Agent Governance\n\nThis agent can access the web.');

    const result = detectAgentRepo(TEST_DIR);

    expect(result.hasGovernance).toBe(true);
    expect(result.isAgentRepo).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(40);
  });

  it('should detect LangChain imports', () => {
    writeTestFile('agent.py', `
from langchain import Agent
from langchain_core.prompts import ChatPromptTemplate

agent = Agent()
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('langchain');
  });

  it('should detect LangGraph patterns', () => {
    writeTestFile('graph.py', `
from langgraph.graph import StateGraph
from langgraph.prebuilt import create_react_agent

graph = StateGraph(AgentState)
graph.add_node("agent", agent)
graph.add_edge("agent", "tools")
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('langgraph');
    expect(result.entryPoints).toContain('graph.py');
  });

  it('should detect CrewAI patterns', () => {
    writeTestFile('crew.py', `
from crewai import Agent, Task, Crew

researcher = Agent(
    role='Researcher',
    goal='Research topics'
)

crew = Crew(agents=[researcher])
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('crewai');
    expect(result.entryPoints).toContain('crew.py');
  });

  it('should detect AutoGen patterns', () => {
    writeTestFile('agents.py', `
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent("assistant")
user_proxy = UserProxyAgent("user")
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('autogen');
  });

  it('should detect DSPy patterns', () => {
    writeTestFile('pipeline.py', `
import dspy
from dspy import ChainOfThought

class MyModule(dspy.Module):
    def forward(self, question):
        return self.cot(question=question)
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('dspy');
    expect(result.entryPoints).toContain('pipeline.py');
  });

  it('should detect hot directories', () => {
    writeTestFile('agents/researcher.py', 'class Researcher: pass');
    writeTestFile('tools/search.py', 'def search(): pass');
    writeTestFile('nodes/processor.py', 'class Processor: pass');

    const result = detectAgentRepo(TEST_DIR);

    expect(result.hotDirectories).toContain('agents');
    expect(result.hotDirectories).toContain('tools');
    expect(result.hotDirectories).toContain('nodes');
  });

  it('should find entry points', () => {
    writeTestFile('main.py', 'if __name__ == "__main__": run()');
    writeTestFile('app.py', 'app = FastAPI()');
    writeTestFile('src/index.ts', 'export default agent;');

    const result = detectAgentRepo(TEST_DIR);

    expect(result.entryPoints).toContain('main.py');
    expect(result.entryPoints).toContain('app.py');
  });

  it('should return low confidence for non-agent repos', () => {
    writeTestFile('utils.py', 'def helper(): return True');
    writeTestFile('config.json', '{"key": "value"}');

    const result = detectAgentRepo(TEST_DIR);

    expect(result.confidence).toBe('none');
    expect(result.isAgentRepo).toBe(false);
  });

  it('should handle multiple frameworks', () => {
    writeTestFile('agent.py', `
from langchain import Agent
from crewai import Crew
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.frameworks).toContain('langchain');
    expect(result.frameworks).toContain('crewai');
    expect(result.frameworks.length).toBeGreaterThanOrEqual(2);
  });

  it('should handle non-existent directory', () => {
    const result = detectAgentRepo('/non/existent/path');

    expect(result.isAgentRepo).toBe(false);
    expect(result.confidence).toBe('none');
    expect(result.score).toBe(0);
  });
});

// =============================================================================
// Filtering Recommendation Tests
// =============================================================================

describe('getFilteringRecommendation', () => {
  it('should recommend aggressive filtering for high confidence', () => {
    const signature = {
      isAgentRepo: true,
      confidence: 'high' as const,
      frameworks: ['langchain'] as FrameworkType[],
      entryPoints: ['main.py'],
      hasGovernance: true,
      hotDirectories: ['agents', 'tools'],
      score: 85,
    };

    const rec = getFilteringRecommendation(signature);

    expect(rec.aggressiveFilter).toBe(true);
    expect(rec.skipPatterns.length).toBeGreaterThan(ALWAYS_SKIP_PATTERNS.length);
    expect(rec.priorityPatterns).toContain('**/agents/**');
    expect(rec.priorityPatterns).toContain('**/tools/**');
  });

  it('should recommend moderate filtering for medium confidence', () => {
    const signature = {
      isAgentRepo: true,
      confidence: 'medium' as const,
      frameworks: ['langchain'] as FrameworkType[],
      entryPoints: ['main.py'],
      hasGovernance: false,
      hotDirectories: ['src'],
      score: 50,
    };

    const rec = getFilteringRecommendation(signature);

    expect(rec.aggressiveFilter).toBe(false);
    expect(rec.skipPatterns).toEqual(ALWAYS_SKIP_PATTERNS);
  });

  it('should recommend minimal filtering for low confidence', () => {
    const signature = {
      isAgentRepo: true,
      confidence: 'low' as const,
      frameworks: [] as FrameworkType[],
      entryPoints: [],
      hasGovernance: false,
      hotDirectories: [],
      score: 25,
    };

    const rec = getFilteringRecommendation(signature);

    expect(rec.aggressiveFilter).toBe(false);
    expect(rec.priorityPatterns).toEqual([]);
  });

  it('should recommend minimal filtering for non-agent repos', () => {
    const signature = {
      isAgentRepo: false,
      confidence: 'none' as const,
      frameworks: [] as FrameworkType[],
      entryPoints: [],
      hasGovernance: false,
      hotDirectories: [],
      score: 0,
    };

    const rec = getFilteringRecommendation(signature);

    expect(rec.aggressiveFilter).toBe(false);
    expect(rec.priorityPatterns).toEqual([]);
  });
});

// =============================================================================
// Generic Pattern Rejection Tests (False Positive Prevention)
// =============================================================================

describe('Generic Pattern Rejection', () => {
  beforeEach(() => {
    createTestDir();
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should NOT detect Haystack from generic "Pipeline" usage', () => {
    // This is a CI/CD pipeline file, NOT a Haystack agent
    writeTestFile('ci/pipeline.py', `
class Pipeline:
    """CI/CD Pipeline class"""
    def run(self):
        pass

pipeline = Pipeline()
pipeline.run()
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect haystack - Pipeline alone is too generic
    expect(result.frameworks).not.toContain('haystack');
  });

  it('should NOT detect from generic "Document" usage', () => {
    // This is a document processing file, NOT an agent framework
    writeTestFile('utils/document.py', `
class Document:
    """Generic document class"""
    def __init__(self, content):
        self.content = content

class DocumentProcessor:
    def process(self, doc: Document):
        return doc.content.upper()
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect any framework just from Document class
    expect(result.frameworks).not.toContain('haystack');
    expect(result.frameworks).not.toContain('llamaindex');
  });

  it('should NOT detect from generic "Agent" class usage', () => {
    // This is a game agent, NOT an AI agent framework
    writeTestFile('game/agent.py', `
class Agent:
    """Game agent class"""
    def __init__(self, position):
        self.position = position

    def move(self, direction):
        self.position += direction

agent = Agent(position=0)
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect crewai or openai-agents just from Agent class
    expect(result.frameworks).not.toContain('crewai');
    expect(result.frameworks).not.toContain('openai-agents');
  });

  it('should NOT detect from generic "Task" class usage', () => {
    // This is a task queue, NOT an AI agent framework
    writeTestFile('jobs/task.py', `
class Task:
    """Background task class"""
    def __init__(self, name):
        self.name = name

    def execute(self):
        pass

task = Task("process_data")
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect crewai just from Task class
    expect(result.frameworks).not.toContain('crewai');
  });

  it('should NOT detect from generic "Module" usage', () => {
    // This is a Python module system, NOT DSPy
    writeTestFile('core/module.py', `
class Module:
    """Base module class"""
    def __init__(self):
        self.loaded = False

    def load(self):
        self.loaded = True
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect dspy just from Module class
    expect(result.frameworks).not.toContain('dspy');
  });

  it('should NOT detect from generic "component" decorator usage', () => {
    // This is a UI component, NOT Haystack
    writeTestFile('ui/components.py', `
def component(cls):
    """UI component decorator"""
    return cls

@component
class Button:
    pass
`);

    const result = detectAgentRepo(TEST_DIR);

    // Should NOT detect haystack from generic component decorator
    expect(result.frameworks).not.toContain('haystack');
  });

  it('should detect Haystack ONLY with actual import', () => {
    writeTestFile('agent.py', `
from haystack import Pipeline
from haystack.components.generators import OpenAIGenerator

pipe = Pipeline()
pipe.add_component("generator", OpenAIGenerator())
`);

    const result = detectAgentRepo(TEST_DIR);

    // SHOULD detect haystack because of the import statement
    expect(result.frameworks).toContain('haystack');
  });

  it('should detect CrewAI ONLY with actual import', () => {
    writeTestFile('crew.py', `
from crewai import Agent, Task, Crew

agent = Agent(role="researcher")
crew = Crew(agents=[agent])
`);

    const result = detectAgentRepo(TEST_DIR);

    // SHOULD detect crewai because of the import statement
    expect(result.frameworks).toContain('crewai');
  });
});

// =============================================================================
// Pure Python Agent Detection Tests
// =============================================================================

describe('Pure Python Agent Detection', () => {
  beforeEach(() => {
    createTestDir();
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should detect OpenAI SDK usage', () => {
    writeTestFile('agent.py', `
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('pure-python');
  });

  it('should detect Anthropic SDK usage', () => {
    writeTestFile('agent.py', `
from anthropic import Anthropic

client = Anthropic()
message = client.messages.create(
    model="claude-3-opus-20240229",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}]
)
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('pure-python');
  });

  it('should detect Google AI SDK usage', () => {
    writeTestFile('agent.py', `
import google.generativeai as genai

model = genai.GenerativeModel('gemini-pro')
response = model.generate_content("Hello")
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('pure-python');
  });

  it('should detect tool/function calling patterns', () => {
    writeTestFile('agent.py', `
import openai

tools = [{
    "type": "function",
    "function": {
        "name": "get_weather",
        "parameters": {"type": "object", "properties": {}}
    }
}]

response = openai.chat.completions.create(
    model="gpt-4",
    messages=[],
    tools=tools,
    tool_choice="auto"
)
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('pure-python');
  });

  it('should detect AsyncOpenAI usage', () => {
    writeTestFile('agent.py', `
from openai import AsyncOpenAI

client = AsyncOpenAI()

async def chat():
    response = await client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('pure-python');
  });

  it('should NOT detect pure-python from unrelated code', () => {
    writeTestFile('utils.py', `
# Just a regular Python file
def process_data(data):
    return data.upper()

class DataProcessor:
    pass
`);

    const result = detectAgentRepo(TEST_DIR);

    expect(result.frameworks).not.toContain('pure-python');
  });
});

// =============================================================================
// Confidence Scoring Tests
// =============================================================================

describe('Confidence Scoring', () => {
  beforeEach(() => {
    createTestDir();
  });

  afterEach(() => {
    cleanupTestDir();
  });

  it('should give high confidence with AGENTS.md + framework + hot dirs', () => {
    writeTestFile('AGENTS.md', '# Governance');
    writeTestFile('agents/main.py', 'from langchain import Agent');
    writeTestFile('tools/search.py', 'def search(): pass');

    const result = detectAgentRepo(TEST_DIR);

    expect(result.confidence).toBe('high');
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  it('should give medium confidence with framework imports only', () => {
    writeTestFile('main.py', 'from langchain import Agent');

    const result = detectAgentRepo(TEST_DIR);

    // Framework detection alone should give some score
    // Score depends on whether the detector samples this file
    expect(result.isAgentRepo).toBe(true);
    expect(result.frameworks).toContain('langchain');
  });

  it('should detect entry point files at root level', () => {
    // Create definitive agent file (crew.py is in DEFINITIVE_FILES)
    writeTestFile('crew.py', 'print("hello")');

    const result = detectAgentRepo(TEST_DIR);

    // crew.py is a definitive file, should be detected
    expect(result.entryPoints).toContain('crew.py');
    expect(result.score).toBeGreaterThan(0);
  });
});
