/**
 * File Reader Utility
 *
 * Safe file system operations for reading agent codebases.
 * Features:
 * - Directory traversal with configurable patterns
 * - Binary file detection (by extension and content)
 * - Size limits
 * - Ignore patterns (node_modules, .git, etc.)
 * - Agent-aware intelligent filtering
 * - Framework detection for optimized scanning
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { minimatch } from 'minimatch';
import {
  type AgentRepoSignature,
  ALWAYS_SKIP_PATTERNS,
  LOW_PRIORITY_PATTERNS,
  detectAgentRepo,
  getFilteringRecommendation,
  isBinaryExtension,
} from './agent-detector.js';

// =============================================================================
// Types
// =============================================================================

export interface FileInput {
  path: string;
  content: string;
}

/**
 * Filter mode for file reading.
 * - 'auto': Automatically detect agent repos and adapt filtering (default)
 * - 'agent-only': Aggressive filtering for known agent repos
 * - 'all': No filtering, scan all files
 */
export type FilterMode = 'auto' | 'agent-only' | 'all';

export interface ReadOptions {
  /** Maximum file size in bytes (default: 1MB) */
  maxFileSize?: number;
  /** Maximum total size in bytes (default: 10MB) */
  maxTotalSize?: number;
  /** Maximum number of files (default: 100) */
  maxFiles?: number;
  /** File extensions to include (default: common code extensions) */
  extensions?: string[];
  /** Patterns to ignore (default: node_modules, .git, etc.) */
  ignorePatterns?: string[];
  /** Filter mode for intelligent file selection (default: 'auto') */
  filterMode?: FilterMode;
}

export interface ReadResult {
  files: FileInput[];
  skipped: {
    path: string;
    reason: string;
  }[];
  totalSize: number;
  /** Scan metadata for reporting */
  metadata?: {
    totalFilesFound: number;
    filesScanned: number;
    filesSkipped: number;
    criticalFilesSkipped: number;
    priorityBreakdown?: {
      critical: number;
      high: number;
      medium: number;
      normal: number;
      low: number;
    };
    /** Agent detection result (if filterMode is 'auto') */
    agentDetection?: AgentRepoSignature;
    /** Files skipped by early binary extension filter */
    binaryFilesSkipped?: number;
    /** Files skipped by pattern filter */
    patternFilesSkipped?: number;
  };
}

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_EXTENSIONS = [
  '.py',
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.go',
  '.java',
  '.rb',
  '.php',
  '.cs',
  '.rs',
  '.c',
  '.cpp',
  '.h',
  '.hpp',
  '.yaml',
  '.yml',
  '.json',
  '.md',
  '.env',
  '.conf',
  '.cfg',
  '.toml',
  '.xml',
];

const DEFAULT_IGNORE_PATTERNS = [
  'node_modules',
  '.git',
  '__pycache__',
  '.venv',
  'venv',
  'vendor',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'coverage',
  '.pytest_cache',
  '.mypy_cache',
  'target', // Rust/Java
  'bin',
  'obj',
  '.idea',
  '.vscode',
  '.DS_Store',
  'Thumbs.db',
];

const DEFAULT_MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB
const DEFAULT_MAX_TOTAL_SIZE = 50 * 1024 * 1024; // 50MB (increased for larger repos)
const DEFAULT_MAX_FILES = 2000; // Increased to support enterprise codebases

// =============================================================================
// File Priority Configuration (Enterprise-Grade)
// =============================================================================

/**
 * Priority tiers for file scanning.
 * Higher scores = scanned first.
 *
 * This ensures critical agent files are ALWAYS scanned,
 * even when hitting file limits on large repos.
 */
interface PriorityConfig {
  score: number;
  patterns: string[];
}

const FILE_PRIORITIES: Record<string, PriorityConfig> = {
  // CRITICAL (Score: 1000) - ALWAYS scan first
  // These are the most likely to contain agent logic and entry points
  critical: {
    score: 1000,
    patterns: [
      // Governance files
      '**/AGENTS.md',
      '**/agents.md',
      // Agent definition files
      '**/agent.py',
      '**/agent.ts',
      '**/agent.js',
      '**/agents/*.py',
      '**/agents/*.ts',
      '**/crew.py',
      '**/graph.py',
      '**/workflow.py',
      '**/pipeline.py',
      // Entry points (nested)
      '**/main.py',
      '**/app.py',
      '**/index.ts',
      '**/index.js',
      '**/server.ts',
      '**/server.js',
      // ROOT-LEVEL entry points (bare filenames for matchBase)
      'main.py',
      'app.py',
      'agent.py',
      'server.py',
      'run.py',
      'cli.py',
      'index.ts',
      'index.js',
      'main.ts',
      'main.js',
      'server.ts',
      'server.js',
      // Configuration files that often contain secrets
      'config.py',
      'settings.py',
      'config.ts',
      'config.js',
      '.env',
      '.env.local',
      '.env.production',
    ],
  },
  // HIGH (Score: 500) - Agent-related and security-sensitive files
  high: {
    score: 500,
    patterns: [
      // Agent-related patterns
      '**/*agent*.py',
      '**/*agent*.ts',
      '**/*agent*.js',
      '**/*tool*.py',
      '**/*tool*.ts',
      '**/*llm*.py',
      '**/*llm*.ts',
      '**/*prompt*.py',
      '**/*prompt*.ts',
      '**/*chain*.py',
      '**/*chain*.ts',
      // Source directories
      '**/src/**/*.py',
      '**/src/**/*.ts',
      '**/core/**/*.py',
      '**/core/**/*.ts',
      '**/lib/**/*.py',
      '**/lib/**/*.ts',
      // SECURITY-SENSITIVE patterns (files likely to contain vulnerabilities)
      '**/*exec*.py',
      '**/*eval*.py',
      '**/*shell*.py',
      '**/*subprocess*.py',
      '**/*command*.py',
      '**/*sql*.py',
      '**/*query*.py',
      '**/*db*.py',
      '**/*database*.py',
      '**/*auth*.py',
      '**/*credential*.py',
      '**/*secret*.py',
      '**/*token*.py',
      '**/*password*.py',
      '**/*api_key*.py',
      // Node and code generation patterns
      '**/*node*.py',
      '**/*generate*.py',
      '**/*scrape*.py',
      '**/*fetch*.py',
      '**/*request*.py',
    ],
  },
  // MEDIUM (Score: 100) - Configuration files
  medium: {
    score: 100,
    patterns: [
      '**/*.json',
      '**/*.yaml',
      '**/*.yml',
      '**/*.toml',
      '**/*.env',
      '**/*.env.*',
    ],
  },
  // NORMAL (Score: 10) - Regular source files
  normal: {
    score: 10,
    patterns: [
      '**/*.py',
      '**/*.ts',
      '**/*.js',
      '**/*.go',
      '**/*.java',
    ],
  },
  // LOW (Score: 1) - Tests and examples (scan last)
  low: {
    score: 1,
    patterns: [
      '**/test_*.py',
      '**/*_test.py',
      '**/*.test.ts',
      '**/*.test.js',
      '**/*.spec.ts',
      '**/*.spec.js',
      '**/tests/**',
      '**/test/**',
      '**/__tests__/**',
      '**/examples/**',
      '**/docs/**',
      '**/fixtures/**',
    ],
  },
};

/**
 * Calculate priority score for a file path.
 * Higher score = higher priority = scanned first.
 *
 * IMPORTANT: Returns the MAXIMUM score across all matching tiers,
 * not the first match. This ensures a file like "tests/agent_helper.py"
 * gets its HIGH score from "*agent*" rather than LOW from "tests/**".
 */
export function calculateFilePriority(filePath: string): number {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  let maxScore = 5; // Default score for unmatched files

  // Check ALL priority tiers and find the maximum score
  for (const config of Object.values(FILE_PRIORITIES)) {
    for (const pattern of config.patterns) {
      if (matchesGlobPattern(normalizedPath, pattern)) {
        if (config.score > maxScore) {
          maxScore = config.score;
        }
        // Found a match in this tier, no need to check other patterns in same tier
        break;
      }
    }
  }

  // Depth bonus: shallow files are more likely to be entry points
  const depth = normalizedPath.split('/').filter(Boolean).length;
  if (depth <= 2) {
    maxScore += 25; // Root or one level deep
  }

  return maxScore;
}

/**
 * Glob pattern matching using minimatch library.
 * Properly handles:
 * - Root-level files (main.py matches glob patterns)
 * - Nested paths (src/agents/main.py matches recursive patterns)
 * - Wildcards in filenames (files with agent in name)
 */
export function matchesGlobPattern(filePath: string, pattern: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  const normalizedPattern = pattern.replace(/\\/g, '/').toLowerCase();

  // Use minimatch with appropriate options
  return minimatch(normalizedPath, normalizedPattern, {
    dot: true, // Match dotfiles (.env, .agents.md)
    matchBase: true, // Allow pattern without path to match basename
    nocase: true, // Case insensitive
  });
}

interface PrioritizedFile {
  path: string;
  size: number;
  score: number;
}

// =============================================================================
// File Reader
// =============================================================================

/**
 * Check if a path should be ignored
 */
function shouldIgnore(filePath: string, ignorePatterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  return ignorePatterns.some((pattern) => {
    // Check if any path segment matches the pattern
    const segments = normalizedPath.split('/');
    return segments.some((segment) => segment === pattern || segment.startsWith(pattern + '.'));
  });
}

/**
 * Check if a path matches any of the given glob patterns.
 */
function matchesAnyPattern(filePath: string, patterns: string[]): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  return patterns.some((pattern) =>
    minimatch(normalizedPath, pattern.toLowerCase(), {
      dot: true,
      matchBase: true,
      nocase: true,
    })
  );
}

/**
 * Check if file should be skipped early by extension (binary files).
 */
function shouldSkipByExtension(filePath: string): boolean {
  return isBinaryExtension(filePath);
}

/**
 * Check if a file is likely binary
 */
function isBinaryFile(buffer: Buffer): boolean {
  // Check for null bytes in first 8KB
  const sample = buffer.subarray(0, 8192);
  for (const byte of sample) {
    if (byte === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Read a single file safely
 */
export function readFile(filePath: string, options?: ReadOptions): FileInput | null {
  const maxFileSize = options?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  try {
    const stats = fs.statSync(filePath);

    if (!stats.isFile()) {
      return null;
    }

    if (stats.size > maxFileSize) {
      return null;
    }

    const buffer = fs.readFileSync(filePath);

    if (isBinaryFile(buffer)) {
      return null;
    }

    const content = buffer.toString('utf-8');

    return {
      path: filePath,
      content,
    };
  } catch {
    return null;
  }
}

/**
 * Read all files from a directory recursively with intelligent prioritization.
 *
 * THREE-PASS ALGORITHM:
 * 1. DETECT: Analyze repo for agent frameworks and determine filtering strategy
 * 2. PASS 1: Collect all file paths with early binary/pattern filtering
 * 3. PASS 2: Sort by priority score, read files in priority order
 *
 * This ensures:
 * - Critical agent files (agent.py, main.py, AGENTS.md) are ALWAYS scanned first
 * - Binary files are skipped early (by extension) to save I/O
 * - Pattern-based filtering reduces noise for agent repos (tests, docs, migrations)
 * - Large enterprise codebases (10,000+ files) complete within timeout
 */
export function readDirectory(dirPath: string, options?: ReadOptions): ReadResult {
  const maxFileSize = options?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const maxTotalSize = options?.maxTotalSize ?? DEFAULT_MAX_TOTAL_SIZE;
  const maxFiles = options?.maxFiles ?? DEFAULT_MAX_FILES;
  const extensions = options?.extensions ?? DEFAULT_EXTENSIONS;
  const ignorePatterns = options?.ignorePatterns ?? DEFAULT_IGNORE_PATTERNS;
  const filterMode = options?.filterMode ?? 'auto';

  const result: ReadResult = {
    files: [],
    skipped: [],
    totalSize: 0,
  };

  // Track filtering statistics
  let binaryFilesSkipped = 0;
  let patternFilesSkipped = 0;

  // Normalize and validate path
  const resolvedPath = path.resolve(dirPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${dirPath}`);
  }

  const rootStats = fs.statSync(resolvedPath);

  // Single file case
  if (rootStats.isFile()) {
    // Early binary extension check
    if (shouldSkipByExtension(resolvedPath)) {
      result.skipped.push({ path: resolvedPath, reason: 'binary_extension' });
      return result;
    }
    const file = readFile(resolvedPath, options);
    if (file !== null) {
      result.files.push(file);
      result.totalSize = rootStats.size;
    }
    return result;
  }

  // ==========================================================================
  // DETECT: Analyze repository for agent frameworks
  // ==========================================================================
  let agentSignature: AgentRepoSignature | undefined;
  let additionalSkipPatterns: string[] = [];
  let aggressiveFilter = false;

  if (filterMode === 'auto') {
    agentSignature = detectAgentRepo(resolvedPath);
    const recommendation = getFilteringRecommendation(agentSignature);
    additionalSkipPatterns = recommendation.skipPatterns;
    aggressiveFilter = recommendation.aggressiveFilter;
  } else if (filterMode === 'agent-only') {
    // Force aggressive filtering
    additionalSkipPatterns = [...ALWAYS_SKIP_PATTERNS, ...LOW_PRIORITY_PATTERNS];
    aggressiveFilter = true;
  }
  // filterMode === 'all' means no additional filtering

  // ==========================================================================
  // PASS 1: Collect all file paths (no content reading)
  // ==========================================================================
  const allFiles: PrioritizedFile[] = [];

  function collectFiles(currentPath: string): void {
    // Check if path should be ignored by default patterns
    if (shouldIgnore(currentPath, ignorePatterns)) {
      return;
    }

    let stats: fs.Stats;
    try {
      stats = fs.statSync(currentPath);
    } catch {
      return;
    }

    if (stats.isDirectory()) {
      let entries: string[];
      try {
        entries = fs.readdirSync(currentPath);
      } catch {
        return;
      }

      for (const entry of entries) {
        collectFiles(path.join(currentPath, entry));
      }
    } else if (stats.isFile()) {
      // EARLY FILTER 1: Skip binary files by extension
      if (shouldSkipByExtension(currentPath)) {
        binaryFilesSkipped++;
        result.skipped.push({ path: currentPath, reason: 'binary_extension' });
        return;
      }

      // Check extension against allowed list
      const ext = path.extname(currentPath).toLowerCase();
      if (extensions.length > 0 && !extensions.includes(ext)) {
        return;
      }

      // EARLY FILTER 2: Skip by pattern (when filtering enabled)
      const relativePath = path.relative(resolvedPath, currentPath);
      if (additionalSkipPatterns.length > 0 && matchesAnyPattern(relativePath, additionalSkipPatterns)) {
        patternFilesSkipped++;
        result.skipped.push({ path: currentPath, reason: 'pattern_filtered' });
        return;
      }

      // Check file size
      if (stats.size > maxFileSize) {
        result.skipped.push({ path: currentPath, reason: 'file_too_large' });
        return;
      }

      // Add to collection with priority score
      // Boost priority if in hot directories (when agent repo detected)
      let score = calculateFilePriority(currentPath);
      if (agentSignature?.hotDirectories) {
        for (const hotDir of agentSignature.hotDirectories) {
          if (relativePath.startsWith(hotDir + '/') || relativePath.startsWith(hotDir + path.sep)) {
            score += 50; // Boost files in hot directories
            break;
          }
        }
      }

      allFiles.push({
        path: currentPath,
        size: stats.size,
        score,
      });
    }
  }

  collectFiles(resolvedPath);

  // ==========================================================================
  // PASS 2: Sort by priority and read in order
  // ==========================================================================

  // Sort by score descending (highest priority first)
  allFiles.sort((a, b) => b.score - a.score);

  // Track statistics for reporting
  let _criticalFilesScanned = 0;
  let criticalFilesSkipped = 0;

  for (const fileInfo of allFiles) {
    // Check limits
    if (result.files.length >= maxFiles) {
      // Track if we're skipping critical files
      if (fileInfo.score >= 500) {
        criticalFilesSkipped++;
      }
      result.skipped.push({ path: fileInfo.path, reason: 'max_files_exceeded' });
      continue;
    }

    if (result.totalSize + fileInfo.size > maxTotalSize) {
      if (fileInfo.score >= 500) {
        criticalFilesSkipped++;
      }
      result.skipped.push({ path: fileInfo.path, reason: 'total_size_exceeded' });
      continue;
    }

    // Read file content
    try {
      const buffer = fs.readFileSync(fileInfo.path);

      if (isBinaryFile(buffer)) {
        result.skipped.push({ path: fileInfo.path, reason: 'binary_file' });
        continue;
      }

      const content = buffer.toString('utf-8');

      result.files.push({
        path: fileInfo.path,
        content,
      });
      result.totalSize += fileInfo.size;

      if (fileInfo.score >= 500) {
        _criticalFilesScanned++;
      }
    } catch {
      result.skipped.push({ path: fileInfo.path, reason: 'read_error' });
    }
  }

  // Calculate priority breakdown
  const priorityBreakdown = {
    critical: allFiles.filter(f => f.score >= 1000).length,
    high: allFiles.filter(f => f.score >= 500 && f.score < 1000).length,
    medium: allFiles.filter(f => f.score >= 100 && f.score < 500).length,
    normal: allFiles.filter(f => f.score >= 10 && f.score < 100).length,
    low: allFiles.filter(f => f.score < 10).length,
  };

  // Add metadata with filtering statistics
  const metadata: NonNullable<ReadResult['metadata']> = {
    totalFilesFound: allFiles.length + binaryFilesSkipped + patternFilesSkipped,
    filesScanned: result.files.length,
    filesSkipped: result.skipped.length,
    criticalFilesSkipped,
    priorityBreakdown,
    binaryFilesSkipped,
    patternFilesSkipped,
  };
  if (agentSignature) {
    metadata.agentDetection = agentSignature;
  }
  result.metadata = metadata;

  // Log filtering summary (helpful for debugging)
  if (agentSignature) {
    const filterInfo = aggressiveFilter ? 'aggressive' : 'moderate';
    console.log(
      `Agent repo detected (confidence: ${agentSignature.confidence}, frameworks: [${agentSignature.frameworks.join(', ')}]). ` +
      `Filtering: ${filterInfo}. Skipped: ${binaryFilesSkipped} binary, ${patternFilesSkipped} by pattern.`
    );
  }

  // Log warning if critical files were skipped
  if (criticalFilesSkipped > 0) {
    console.warn(
      `WARNING: ${criticalFilesSkipped} critical agent files were skipped due to limits. ` +
      `Consider increasing maxFiles (current: ${maxFiles}) or maxTotalSize.`
    );
  }

  return result;
}

/**
 * Get relative paths for display
 */
export function getRelativePaths(files: FileInput[], basePath: string): FileInput[] {
  const resolvedBase = path.resolve(basePath);
  return files.map((file) => {
    let relativePath = path.relative(resolvedBase, file.path);
    // Handle case where basePath is the same as the file path (single file scan)
    // path.relative returns "" which would cause the API to try writing to a directory
    if (relativePath === '' || relativePath === '.') {
      relativePath = path.basename(file.path);
    }
    return {
      path: relativePath,
      content: file.content,
    };
  });
}

/**
 * Check if a path looks like an AGENTS.md file
 */
export function isAgentsMdFile(filePath: string): boolean {
  const filename = path.basename(filePath).toLowerCase();
  return filename === 'agents.md';
}

/**
 * Find AGENTS.md file in a directory
 */
export function findAgentsMd(dirPath: string): string | null {
  const resolvedPath = path.resolve(dirPath);

  if (!fs.existsSync(resolvedPath)) {
    return null;
  }

  const stats = fs.statSync(resolvedPath);

  if (stats.isFile()) {
    return isAgentsMdFile(resolvedPath) ? resolvedPath : null;
  }

  // Check common locations
  const candidates = ['AGENTS.md', 'agents.md', 'Agents.md', '.agents.md'];

  for (const candidate of candidates) {
    const candidatePath = path.join(resolvedPath, candidate);
    if (fs.existsSync(candidatePath)) {
      return candidatePath;
    }
  }

  return null;
}
