/**
 * File Reader Utility
 *
 * Safe file system operations for reading agent codebases.
 * Features:
 * - Directory traversal with configurable patterns
 * - Binary file detection
 * - Size limits
 * - Ignore patterns (node_modules, .git, etc.)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// =============================================================================
// Types
// =============================================================================

export interface FileInput {
  path: string;
  content: string;
}

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
  // These are the most likely to contain agent logic
  critical: {
    score: 1000,
    patterns: [
      '**/AGENTS.md',
      '**/agents.md',
      '**/agent.py',
      '**/agent.ts',
      '**/agent.js',
      '**/agents/*.py',
      '**/agents/*.ts',
      '**/crew.py',
      '**/graph.py',
      '**/workflow.py',
      '**/pipeline.py',
      '**/main.py',
      '**/app.py',
      '**/index.ts',
      '**/index.js',
      '**/server.ts',
      '**/server.js',
    ],
  },
  // HIGH (Score: 500) - Agent-related files
  high: {
    score: 500,
    patterns: [
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
      '**/src/**/*.py',
      '**/src/**/*.ts',
      '**/core/**/*.py',
      '**/core/**/*.ts',
      '**/lib/**/*.py',
      '**/lib/**/*.ts',
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
 */
function calculateFilePriority(filePath: string): number {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

  // Check each priority tier from highest to lowest
  for (const config of Object.values(FILE_PRIORITIES)) {
    for (const pattern of config.patterns) {
      if (matchesGlobPattern(normalizedPath, pattern)) {
        // Boost score for files in root or src directories
        let score = config.score;
        if (normalizedPath.split('/').length <= 3) {
          score += 50; // Shallow files get bonus
        }
        return score;
      }
    }
  }

  // Default score for unmatched files
  return 5;
}

/**
 * Simple glob pattern matching.
 * Supports: ** (any path), * (any segment), exact match
 */
function matchesGlobPattern(filePath: string, pattern: string): boolean {
  const normalizedPattern = pattern.replace(/\\/g, '/').toLowerCase();

  // Convert glob to regex
  let regexPattern = normalizedPattern
    .replace(/\*\*/g, '<<<DOUBLESTAR>>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<<DOUBLESTAR>>>/g, '.*')
    .replace(/\./g, '\\.')
    .replace(/\//g, '\\/');

  // Match anywhere in path or from start
  if (!regexPattern.startsWith('.*')) {
    regexPattern = '(^|.*)' + regexPattern;
  }

  try {
    const regex = new RegExp(regexPattern + '$', 'i');
    return regex.test(filePath);
  } catch {
    return false;
  }
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
 * TWO-PASS ALGORITHM:
 * 1. PASS 1: Collect all file paths and metadata (no content reading)
 * 2. PASS 2: Sort by priority score, read files in priority order
 *
 * This ensures critical agent files (agent.py, main.py, etc.) are ALWAYS
 * scanned first, even on large enterprise codebases with 10,000+ files.
 */
export function readDirectory(dirPath: string, options?: ReadOptions): ReadResult {
  const maxFileSize = options?.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const maxTotalSize = options?.maxTotalSize ?? DEFAULT_MAX_TOTAL_SIZE;
  const maxFiles = options?.maxFiles ?? DEFAULT_MAX_FILES;
  const extensions = options?.extensions ?? DEFAULT_EXTENSIONS;
  const ignorePatterns = options?.ignorePatterns ?? DEFAULT_IGNORE_PATTERNS;

  const result: ReadResult = {
    files: [],
    skipped: [],
    totalSize: 0,
  };

  // Normalize and validate path
  const resolvedPath = path.resolve(dirPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${dirPath}`);
  }

  const rootStats = fs.statSync(resolvedPath);

  // Single file case
  if (rootStats.isFile()) {
    const file = readFile(resolvedPath, options);
    if (file !== null) {
      result.files.push(file);
      result.totalSize = rootStats.size;
    }
    return result;
  }

  // ==========================================================================
  // PASS 1: Collect all file paths (no content reading)
  // ==========================================================================
  const allFiles: PrioritizedFile[] = [];

  function collectFiles(currentPath: string): void {
    // Check if path should be ignored
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
      // Check extension
      const ext = path.extname(currentPath).toLowerCase();
      if (extensions.length > 0 && !extensions.includes(ext)) {
        return;
      }

      // Check file size
      if (stats.size > maxFileSize) {
        result.skipped.push({ path: currentPath, reason: 'file_too_large' });
        return;
      }

      // Add to collection with priority score
      allFiles.push({
        path: currentPath,
        size: stats.size,
        score: calculateFilePriority(currentPath),
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

  // Add metadata
  result.metadata = {
    totalFilesFound: allFiles.length,
    filesScanned: result.files.length,
    filesSkipped: result.skipped.length,
    criticalFilesSkipped,
    priorityBreakdown,
  };

  // Log warning if critical files were skipped
  if (criticalFilesSkipped > 0) {
    console.warn(
      `⚠️ WARNING: ${criticalFilesSkipped} critical agent files were skipped due to limits. ` +
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
