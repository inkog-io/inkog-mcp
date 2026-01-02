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
const DEFAULT_MAX_TOTAL_SIZE = 10 * 1024 * 1024; // 10MB
const DEFAULT_MAX_FILES = 100;

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
 * Read all files from a directory recursively
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

  function walk(currentPath: string): void {
    // Stop if we've hit limits
    if (result.files.length >= maxFiles) {
      return;
    }
    if (result.totalSize >= maxTotalSize) {
      return;
    }

    // Check if path should be ignored
    if (shouldIgnore(currentPath, ignorePatterns)) {
      result.skipped.push({ path: currentPath, reason: 'ignored_pattern' });
      return;
    }

    let stats: fs.Stats;
    try {
      stats = fs.statSync(currentPath);
    } catch {
      result.skipped.push({ path: currentPath, reason: 'read_error' });
      return;
    }

    if (stats.isDirectory()) {
      let entries: string[];
      try {
        entries = fs.readdirSync(currentPath);
      } catch {
        result.skipped.push({ path: currentPath, reason: 'read_error' });
        return;
      }

      for (const entry of entries) {
        walk(path.join(currentPath, entry));
      }
    } else if (stats.isFile()) {
      // Check extension
      const ext = path.extname(currentPath).toLowerCase();
      if (extensions.length > 0 && !extensions.includes(ext)) {
        result.skipped.push({ path: currentPath, reason: 'extension_not_supported' });
        return;
      }

      // Check file size
      if (stats.size > maxFileSize) {
        result.skipped.push({ path: currentPath, reason: 'file_too_large' });
        return;
      }

      // Check total size limit
      if (result.totalSize + stats.size > maxTotalSize) {
        result.skipped.push({ path: currentPath, reason: 'total_size_exceeded' });
        return;
      }

      // Check file count limit
      if (result.files.length >= maxFiles) {
        result.skipped.push({ path: currentPath, reason: 'max_files_exceeded' });
        return;
      }

      // Read file
      try {
        const buffer = fs.readFileSync(currentPath);

        if (isBinaryFile(buffer)) {
          result.skipped.push({ path: currentPath, reason: 'binary_file' });
          return;
        }

        const content = buffer.toString('utf-8');

        result.files.push({
          path: currentPath,
          content,
        });
        result.totalSize += stats.size;
      } catch {
        result.skipped.push({ path: currentPath, reason: 'read_error' });
      }
    }
  }

  // Normalize path
  const resolvedPath = path.resolve(dirPath);

  // Check if path exists
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${dirPath}`);
  }

  const stats = fs.statSync(resolvedPath);

  if (stats.isFile()) {
    // Single file
    const file = readFile(resolvedPath, options);
    if (file !== null) {
      result.files.push(file);
      result.totalSize = stats.size;
    }
  } else if (stats.isDirectory()) {
    walk(resolvedPath);
  }

  return result;
}

/**
 * Get relative paths for display
 */
export function getRelativePaths(files: FileInput[], basePath: string): FileInput[] {
  const resolvedBase = path.resolve(basePath);
  return files.map((file) => ({
    path: path.relative(resolvedBase, file.path),
    content: file.content,
  }));
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
