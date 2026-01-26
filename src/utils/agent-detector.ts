/**
 * Agent Repository Detector
 *
 * Intelligently detects AI agent repositories and their frameworks.
 * Used for adaptive filtering to optimize scan performance on large codebases.
 *
 * Key features:
 * - AGENTS.md detection (industry standard governance file)
 * - Framework detection (LangChain, LangGraph, CrewAI, AutoGen, etc.)
 * - Confidence scoring for filtering decisions
 * - Entry point identification
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// =============================================================================
// Types
// =============================================================================

/**
 * Supported AI agent frameworks.
 * Based on industry research (OWASP Agentic, AGENTS.md standard, framework landscape 2026)
 */
export type FrameworkType =
  | 'langchain'
  | 'langgraph'
  | 'crewai'
  | 'autogen'
  | 'openai-agents'
  | 'llamaindex'
  | 'haystack'
  | 'dspy'
  | 'n8n'
  | 'flowise'
  | 'dify'
  | 'semantic-kernel'
  | 'agentkit'
  | 'pure-python'  // Raw SDK usage without frameworks (OpenAI, Anthropic, Google)
  | 'unknown';

/**
 * Confidence level for agent repository detection.
 * Determines how aggressively we filter files.
 */
export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'none';

/**
 * Result of agent repository detection.
 */
export interface AgentRepoSignature {
  /** Whether this appears to be an AI agent repository */
  isAgentRepo: boolean;
  /** Confidence level of the detection */
  confidence: ConfidenceLevel;
  /** Detected frameworks */
  frameworks: FrameworkType[];
  /** Identified entry points (relative paths) */
  entryPoints: string[];
  /** Whether AGENTS.md governance file is present */
  hasGovernance: boolean;
  /** Hot directories containing agent logic */
  hotDirectories: string[];
  /** Detection score (0-100) for debugging */
  score: number;
}

/**
 * Options for agent detection.
 */
export interface AgentDetectorOptions {
  /** Maximum number of files to sample for framework detection */
  maxSampleFiles?: number;
  /** Maximum depth to search for entry points */
  maxDepth?: number;
}

// =============================================================================
// Detection Markers
// =============================================================================

/**
 * Governance file markers - HIGHEST priority.
 * AGENTS.md is the industry standard (60K+ repos, Linux Foundation adoption).
 */
const GOVERNANCE_MARKERS = ['AGENTS.md', 'agents.md', '.agents.md', 'Agents.md'];

/**
 * Definitive file patterns that strongly indicate an agent repo.
 */
const DEFINITIVE_FILES = [
  'crew.py',
  'graph.py',
  'workflow.py',
  'pipeline.py',
  'agent.py',
  'agents.py',
];

/**
 * Definitive directory patterns.
 */
const DEFINITIVE_DIRECTORIES = ['agents', 'nodes', 'tools', 'graphs', 'workflows', 'pipelines'];

/**
 * Framework import patterns for detection.
 * Maps framework name to import patterns to search for.
 */
/**
 * Framework import patterns for detection.
 * Maps framework name to import patterns to search for.
 *
 * IMPORTANT: Only include patterns that are SPECIFIC to the framework.
 * Generic terms like 'Pipeline', 'Document', 'Agent(', 'Task(' have been removed
 * because they cause false positives (match any pipeline, document handler, etc.)
 *
 * The rule: If a pattern could reasonably appear in non-agent code, don't include it.
 */
const FRAMEWORK_IMPORTS: Record<FrameworkType, string[]> = {
  langchain: [
    'from langchain',
    'from langchain_core',
    'from langchain_community',
    'from langchain_openai',
    'from langchain_anthropic',
    'import langchain',
  ],
  langgraph: [
    'from langgraph',
    'import langgraph',
    // These are specific enough - StateGraph/MessageGraph are LangGraph-specific
    'StateGraph',
    'MessageGraph',
  ],
  // CrewAI: Removed 'Agent(', 'Task(' - too generic. Kept framework-specific patterns.
  crewai: ['from crewai', 'import crewai', 'Crew(', '@agent', '@task', '@crew'],
  autogen: [
    'from autogen',
    'import autogen',
    // These class names are AutoGen-specific
    'AssistantAgent',
    'UserProxyAgent',
    'GroupChat',
    'ConversableAgent',
  ],
  // OpenAI Agents SDK: Removed 'Agent(', 'Runner(' - too generic
  'openai-agents': [
    'from agents import',
    'from openai_agents',
    'import agents',
    'function_tool',
    'handoff',
    '@function_tool',
  ],
  // LlamaIndex: Removed 'Document', 'Node' - too generic
  llamaindex: [
    'from llama_index',
    'from llamaindex',
    'import llama_index',
    'VectorStoreIndex',
    'ServiceContext',
    'SimpleDirectoryReader',
    'GPTVectorStoreIndex',
  ],
  // Haystack: Removed 'Pipeline', 'Document', 'component' - all too generic
  haystack: ['from haystack', 'import haystack', '@haystack.component'],
  // DSPy: Removed 'Module' - too generic (matches Python modules)
  dspy: ['from dspy', 'import dspy', 'dspy.Signature', 'ChainOfThought', 'dspy.Predict'],
  n8n: ['"@n8n/n8n-core"', '"n8n-workflow"', 'INodeType', 'IExecuteFunctions'],
  flowise: ['flowise', 'chatflow', 'INodeData', 'ICommonObject'],
  dify: ['from dify', 'import dify', 'DifyClient'],
  'semantic-kernel': [
    'from semantic_kernel',
    'import semantic_kernel',
    '@kernel_function',
    'KernelPlugin',
  ],
  agentkit: ['agentkit', 'cdp_langchain', 'CdpAgentkitWrapper'],
  // Pure Python: Direct SDK usage without frameworks
  'pure-python': [
    // OpenAI SDK (most common)
    'from openai import',
    'import openai',
    'openai.OpenAI(',
    'openai.AsyncOpenAI(',
    'client.chat.completions.create',
    'ChatCompletion.create',
    // Anthropic SDK
    'from anthropic import',
    'import anthropic',
    'anthropic.Anthropic(',
    'anthropic.AsyncAnthropic(',
    'client.messages.create',
    // Google AI SDK
    'import google.generativeai',
    'from google.generativeai',
    'genai.GenerativeModel',
    // Cohere SDK
    'import cohere',
    'from cohere import',
    'cohere.Client(',
    // Mistral SDK
    'from mistralai',
    'import mistralai',
    // Tool/Function calling patterns (framework-agnostic indicators of agent behavior)
    'tools=[{',
    '"type": "function"',
    'tool_choice=',
    'function_call=',
    'parallel_tool_calls',
  ],
  unknown: [],
};

/**
 * Security-sensitive patterns that should ALWAYS be scanned.
 * Files containing these should never be filtered out.
 */
const SECURITY_SENSITIVE_PATTERNS = [
  'exec(',
  'eval(',
  'subprocess',
  'os.system',
  'shell_exec',
  'cursor.execute',
  'raw_input',
  'input(',
  'pickle.load',
  '__import__',
  'compile(',
  'importlib',
];

/**
 * Hot directories that typically contain agent logic.
 */
const HOT_DIRECTORIES = [
  'agent',
  'agents',
  'core',
  'src',
  'lib',
  'nodes',
  'tools',
  'graphs',
  'workflows',
  'pipelines',
  'chains',
  'prompts',
];

/**
 * Entry point file patterns.
 */
const ENTRY_POINT_PATTERNS = [
  'main.py',
  'app.py',
  'agent.py',
  'server.py',
  'run.py',
  'cli.py',
  'crew.py',
  'graph.py',
  'workflow.py',
  'index.ts',
  'index.js',
  'main.ts',
  'main.js',
  'server.ts',
  'server.js',
];

// =============================================================================
// Binary Extensions to Skip
// =============================================================================

/**
 * Binary file extensions that should be skipped early (before reading content).
 * These files will never contain agent code.
 */
export const BINARY_EXTENSIONS = new Set([
  // Compiled Python
  '.pyc',
  '.pyo',
  '.pyd',
  // Images
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.bmp',
  '.ico',
  '.svg',
  '.webp',
  // Documents
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  // Archives
  '.zip',
  '.tar',
  '.gz',
  '.bz2',
  '.7z',
  '.rar',
  // Binaries
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.whl',
  '.egg',
  // Fonts
  '.ttf',
  '.otf',
  '.woff',
  '.woff2',
  '.eot',
  // Media
  '.mp3',
  '.mp4',
  '.wav',
  '.avi',
  '.mov',
  '.webm',
  // Data
  '.db',
  '.sqlite',
  '.sqlite3',
  '.bin',
  '.dat',
  '.pkl',
  '.pickle',
  '.npy',
  '.npz',
  // Models
  '.onnx',
  '.pt',
  '.pth',
  '.h5',
  '.safetensors',
  '.gguf',
]);

/**
 * Patterns that should ALWAYS be skipped (never contain agent code).
 */
export const ALWAYS_SKIP_PATTERNS = [
  // Lock files
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/poetry.lock',
  '**/Pipfile.lock',
  '**/Cargo.lock',
  '**/go.sum',
  '**/composer.lock',
  // Generated
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.nuxt/**',
  // Dependencies
  '**/node_modules/**',
  '**/.venv/**',
  '**/venv/**',
  '**/vendor/**',
  '**/site-packages/**',
  // Cache
  '**/__pycache__/**',
  '**/.pytest_cache/**',
  '**/.mypy_cache/**',
  '**/.cache/**',
  '**/.tox/**',
  // IDE
  '**/.idea/**',
  '**/.vscode/**',
  // Git
  '**/.git/**',
  // Coverage
  '**/coverage/**',
  '**/htmlcov/**',
  '**/.coverage',
];

/**
 * Patterns to deprioritize in agent repos (scan last, skip if limit reached).
 */
export const LOW_PRIORITY_PATTERNS = [
  '**/tests/**',
  '**/test/**',
  '**/__tests__/**',
  '**/spec/**',
  '**/docs/**',
  '**/documentation/**',
  '**/examples/**',
  '**/samples/**',
  '**/migrations/**',
  '**/static/**',
  '**/assets/**',
  '**/fixtures/**',
  '**/mocks/**',
  '**/*.test.ts',
  '**/*.test.js',
  '**/*.spec.ts',
  '**/*.spec.js',
  '**/test_*.py',
  '**/*_test.py',
  '**/*_test.go',
];

// =============================================================================
// Detector Implementation
// =============================================================================

const DEFAULT_OPTIONS: Required<AgentDetectorOptions> = {
  maxSampleFiles: 50,
  maxDepth: 3,
};

/**
 * Detect if a directory contains an AI agent repository.
 *
 * @param dirPath Path to the directory to analyze
 * @param options Detection options
 * @returns Agent repository signature with confidence and frameworks
 */
export function detectAgentRepo(
  dirPath: string,
  options?: AgentDetectorOptions
): AgentRepoSignature {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  const result: AgentRepoSignature = {
    isAgentRepo: false,
    confidence: 'none',
    frameworks: [],
    entryPoints: [],
    hasGovernance: false,
    hotDirectories: [],
    score: 0,
  };

  const resolvedPath = path.resolve(dirPath);
  if (!fs.existsSync(resolvedPath)) {
    return result;
  }

  const stats = fs.statSync(resolvedPath);
  if (!stats.isDirectory()) {
    // Single file - check if it's agent-related
    return detectSingleFile(resolvedPath);
  }

  let score = 0;

  // Check for governance file (HIGHEST priority - +40 points)
  for (const marker of GOVERNANCE_MARKERS) {
    const governancePath = path.join(resolvedPath, marker);
    if (fs.existsSync(governancePath)) {
      result.hasGovernance = true;
      score += 40;
      break;
    }
  }

  // Check for definitive files (+20 points each, max 60)
  let definitiveScore = 0;
  for (const file of DEFINITIVE_FILES) {
    const filePath = path.join(resolvedPath, file);
    if (fs.existsSync(filePath)) {
      result.entryPoints.push(file);
      definitiveScore += 20;
      if (definitiveScore >= 60) break;
    }
  }
  score += definitiveScore;

  // Check for hot directories (+10 points each, max 30)
  let hotDirScore = 0;
  for (const dir of HOT_DIRECTORIES) {
    const dirPathFull = path.join(resolvedPath, dir);
    if (fs.existsSync(dirPathFull) && fs.statSync(dirPathFull).isDirectory()) {
      result.hotDirectories.push(dir);
      hotDirScore += 10;
      if (hotDirScore >= 30) break;
    }
  }
  score += hotDirScore;

  // Check for definitive directories (+15 points each, max 45)
  let definitiveDir = 0;
  for (const dir of DEFINITIVE_DIRECTORIES) {
    const dirPathFull = path.join(resolvedPath, dir);
    if (fs.existsSync(dirPathFull) && fs.statSync(dirPathFull).isDirectory()) {
      definitiveDir += 15;
      if (!result.hotDirectories.includes(dir)) {
        result.hotDirectories.push(dir);
      }
      if (definitiveDir >= 45) break;
    }
  }
  score += definitiveDir;

  // Sample files for framework detection (+25 points per framework, max 50)
  const sampleFiles = collectSampleFiles(resolvedPath, opts.maxSampleFiles, opts.maxDepth);
  const detectedFrameworks = detectFrameworksFromFiles(sampleFiles);
  result.frameworks = detectedFrameworks;
  score += Math.min(detectedFrameworks.length * 25, 50);

  // Find entry points
  const entryPoints = findEntryPoints(resolvedPath, opts.maxDepth);
  result.entryPoints = [...new Set([...result.entryPoints, ...entryPoints])];

  // Calculate final score and confidence
  result.score = Math.min(score, 100);
  result.confidence = scoreToConfidence(result.score);
  result.isAgentRepo = result.score >= 20;

  return result;
}

/**
 * Detect agent characteristics for a single file.
 */
function detectSingleFile(filePath: string): AgentRepoSignature {
  const result: AgentRepoSignature = {
    isAgentRepo: false,
    confidence: 'none',
    frameworks: [],
    entryPoints: [],
    hasGovernance: false,
    hotDirectories: [],
    score: 0,
  };

  const filename = path.basename(filePath).toLowerCase();

  // Check if it's a governance file
  if (GOVERNANCE_MARKERS.map((m) => m.toLowerCase()).includes(filename)) {
    result.hasGovernance = true;
    result.isAgentRepo = true;
    result.confidence = 'high';
    result.score = 100;
    return result;
  }

  // Check if it's a definitive agent file
  if (DEFINITIVE_FILES.includes(filename)) {
    result.isAgentRepo = true;
    result.confidence = 'medium';
    result.entryPoints.push(filename);
    result.score = 50;
  }

  // Try to detect framework from content
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const frameworks = detectFrameworksFromContent(content);
    if (frameworks.length > 0) {
      result.frameworks = frameworks;
      result.isAgentRepo = true;
      result.confidence = result.confidence === 'none' ? 'medium' : result.confidence;
      result.score = Math.max(result.score, 50);
    }
  } catch {
    // Ignore read errors
  }

  return result;
}

/**
 * Collect sample files from a directory for framework detection.
 */
function collectSampleFiles(dirPath: string, maxFiles: number, maxDepth: number): string[] {
  const files: string[] = [];

  function collect(currentPath: string, depth: number): void {
    if (depth > maxDepth || files.length >= maxFiles) return;

    try {
      const entries = fs.readdirSync(currentPath);
      for (const entry of entries) {
        if (files.length >= maxFiles) break;

        const fullPath = path.join(currentPath, entry);

        // Skip common non-code directories
        if (
          entry === 'node_modules' ||
          entry === '.git' ||
          entry === '__pycache__' ||
          entry === '.venv' ||
          entry === 'venv'
        ) {
          continue;
        }

        try {
          const stats = fs.statSync(fullPath);
          if (stats.isDirectory()) {
            collect(fullPath, depth + 1);
          } else if (stats.isFile()) {
            const ext = path.extname(entry).toLowerCase();
            // Only sample code files
            if (['.py', '.ts', '.js', '.go', '.java'].includes(ext)) {
              files.push(fullPath);
            }
          }
        } catch {
          // Skip files we can't access
        }
      }
    } catch {
      // Skip directories we can't read
    }
  }

  collect(dirPath, 0);
  return files;
}

/**
 * Detect frameworks from a list of files.
 */
function detectFrameworksFromFiles(files: string[]): FrameworkType[] {
  const detected = new Set<FrameworkType>();

  for (const file of files) {
    try {
      // Read first 10KB of each file (enough for imports)
      const fd = fs.openSync(file, 'r');
      const buffer = Buffer.alloc(10240);
      const bytesRead = fs.readSync(fd, buffer, 0, 10240, 0);
      fs.closeSync(fd);

      const content = buffer.toString('utf-8', 0, bytesRead);
      const frameworks = detectFrameworksFromContent(content);
      for (const fw of frameworks) {
        detected.add(fw);
      }
    } catch {
      // Ignore read errors
    }
  }

  return Array.from(detected);
}

/**
 * Detect frameworks from file content.
 */
function detectFrameworksFromContent(content: string): FrameworkType[] {
  const detected: FrameworkType[] = [];

  for (const [framework, patterns] of Object.entries(FRAMEWORK_IMPORTS)) {
    if (framework === 'unknown') continue;

    for (const pattern of patterns) {
      if (content.includes(pattern)) {
        detected.push(framework as FrameworkType);
        break;
      }
    }
  }

  return detected;
}

/**
 * Find entry point files in a directory.
 */
function findEntryPoints(dirPath: string, maxDepth: number): string[] {
  const entryPoints: string[] = [];

  function search(currentPath: string, relativePath: string, depth: number): void {
    if (depth > maxDepth) return;

    try {
      const entries = fs.readdirSync(currentPath);
      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry);
        const relPath = relativePath ? path.join(relativePath, entry) : entry;

        // Skip common non-code directories
        if (
          entry === 'node_modules' ||
          entry === '.git' ||
          entry === '__pycache__' ||
          entry === '.venv'
        ) {
          continue;
        }

        try {
          const stats = fs.statSync(fullPath);
          if (stats.isDirectory()) {
            search(fullPath, relPath, depth + 1);
          } else if (stats.isFile()) {
            if (ENTRY_POINT_PATTERNS.includes(entry.toLowerCase())) {
              entryPoints.push(relPath);
            }
          }
        } catch {
          // Skip inaccessible files
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  search(dirPath, '', 0);
  return entryPoints;
}

/**
 * Convert score to confidence level.
 */
function scoreToConfidence(score: number): ConfidenceLevel {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'none';
}

/**
 * Check if a file path matches any security-sensitive patterns.
 * These files should ALWAYS be scanned regardless of filtering.
 */
export function containsSecuritySensitiveCode(content: string): boolean {
  for (const pattern of SECURITY_SENSITIVE_PATTERNS) {
    if (content.includes(pattern)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a file extension is binary (should be skipped).
 */
export function isBinaryExtension(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Get filtering recommendations based on agent detection result.
 */
export function getFilteringRecommendation(signature: AgentRepoSignature): {
  skipPatterns: string[];
  priorityPatterns: string[];
  aggressiveFilter: boolean;
} {
  // High confidence: aggressive filtering, skip tests/docs
  if (signature.confidence === 'high') {
    return {
      skipPatterns: [...ALWAYS_SKIP_PATTERNS, ...LOW_PRIORITY_PATTERNS],
      priorityPatterns: signature.hotDirectories.map((d) => `**/${d}/**`),
      aggressiveFilter: true,
    };
  }

  // Medium confidence: moderate filtering
  if (signature.confidence === 'medium') {
    return {
      skipPatterns: ALWAYS_SKIP_PATTERNS,
      priorityPatterns: signature.hotDirectories.map((d) => `**/${d}/**`),
      aggressiveFilter: false,
    };
  }

  // Low/None confidence: minimal filtering, scan broadly
  return {
    skipPatterns: ALWAYS_SKIP_PATTERNS,
    priorityPatterns: [],
    aggressiveFilter: false,
  };
}
