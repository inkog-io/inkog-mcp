/**
 * Array Utilities
 *
 * Enterprise-grade null-safe array operations for handling API responses
 * where arrays may be null or undefined despite TypeScript definitions.
 *
 * Design principles:
 * - Fail-safe defaults: null/undefined → empty array
 * - Type preservation: Generic functions maintain type information
 * - Zero runtime overhead for valid arrays
 * - Consistent behavior across all array operations
 *
 * Usage:
 *   import { safeArray, safeLength } from '../utils/array-utils.js';
 *   const tools = safeArray(agent.tools); // string[] (never null)
 *   const count = safeLength(agent.tools); // number (0 for null)
 */

// =============================================================================
// Core Functions
// =============================================================================

/**
 * Returns a safe array, converting null/undefined to empty array.
 * Use this when you need to iterate, map, or filter an array that may be null.
 *
 * @example
 * safeArray(null)        // []
 * safeArray(undefined)   // []
 * safeArray([1, 2, 3])   // [1, 2, 3]
 */
export function safeArray<T>(arr: T[] | null | undefined): T[] {
  return arr ?? [];
}

/**
 * Returns the length of an array, returning 0 for null/undefined.
 * Use this when you need to check array size without null checks.
 *
 * @example
 * safeLength(null)        // 0
 * safeLength(undefined)   // 0
 * safeLength([1, 2, 3])   // 3
 */
export function safeLength(arr: unknown[] | null | undefined): number {
  return arr?.length ?? 0;
}

/**
 * Safely joins array elements, returning empty string for null/undefined.
 * Use this when you need to display array contents as a string.
 *
 * @example
 * safeJoin(null, ', ')           // ''
 * safeJoin(['a', 'b'], ', ')     // 'a, b'
 * safeJoin([], ', ')             // ''
 */
export function safeJoin(arr: string[] | null | undefined, separator = ', '): string {
  return (arr ?? []).join(separator);
}

/**
 * Returns first element of array or undefined.
 * Safe for null/undefined arrays.
 *
 * @example
 * safeFirst(null)        // undefined
 * safeFirst([1, 2, 3])   // 1
 */
export function safeFirst<T>(arr: T[] | null | undefined): T | undefined {
  return arr?.[0];
}

/**
 * Safely checks if array has any elements.
 * Returns false for null, undefined, or empty arrays.
 *
 * @example
 * hasElements(null)        // false
 * hasElements([])          // false
 * hasElements([1, 2, 3])   // true
 */
export function hasElements(arr: unknown[] | null | undefined): boolean {
  return (arr?.length ?? 0) > 0;
}

// =============================================================================
// Type Guards
// =============================================================================

/**
 * Type guard to check if value is a non-empty array.
 * Narrows type to T[] with at least one element.
 *
 * @example
 * if (isNonEmptyArray(items)) {
 *   // items is T[] with items.length > 0
 * }
 */
export function isNonEmptyArray<T>(arr: T[] | null | undefined): arr is T[] & { length: number } {
  return Array.isArray(arr) && arr.length > 0;
}

/**
 * Type guard to check if value is an array (possibly empty).
 * Narrows type to T[].
 *
 * @example
 * if (isArray(items)) {
 *   // items is T[]
 * }
 */
export function isArray<T>(arr: T[] | null | undefined): arr is T[] {
  return Array.isArray(arr);
}

// =============================================================================
// Higher-Order Functions
// =============================================================================

/**
 * Safely maps over an array, returning empty array for null/undefined.
 *
 * @example
 * safeMap(null, x => x * 2)       // []
 * safeMap([1, 2], x => x * 2)     // [2, 4]
 */
export function safeMap<T, U>(arr: T[] | null | undefined, fn: (item: T, index: number) => U): U[] {
  return (arr ?? []).map(fn);
}

/**
 * Safely filters an array, returning empty array for null/undefined.
 *
 * @example
 * safeFilter(null, x => x > 1)    // []
 * safeFilter([1, 2, 3], x => x > 1) // [2, 3]
 */
export function safeFilter<T>(arr: T[] | null | undefined, predicate: (item: T) => boolean): T[] {
  return (arr ?? []).filter(predicate);
}

/**
 * Safely finds an element in an array, returning undefined for null/undefined arrays.
 *
 * @example
 * safeFind(null, x => x.id === '123')       // undefined
 * safeFind([{id: '123'}], x => x.id === '123') // {id: '123'}
 */
export function safeFind<T>(arr: T[] | null | undefined, predicate: (item: T) => boolean): T | undefined {
  return (arr ?? []).find(predicate);
}

/**
 * Safely checks if any element matches predicate.
 * Returns false for null/undefined arrays.
 *
 * @example
 * safeSome(null, x => x > 1)      // false
 * safeSome([1, 2], x => x > 1)    // true
 */
export function safeSome<T>(arr: T[] | null | undefined, predicate: (item: T) => boolean): boolean {
  return (arr ?? []).some(predicate);
}

/**
 * Safely checks if all elements match predicate.
 * Returns true for null/undefined arrays (vacuous truth).
 *
 * @example
 * safeEvery(null, x => x > 0)     // true
 * safeEvery([1, 2], x => x > 0)   // true
 */
export function safeEvery<T>(arr: T[] | null | undefined, predicate: (item: T) => boolean): boolean {
  return (arr ?? []).every(predicate);
}

// =============================================================================
// Aggregation Functions
// =============================================================================

/**
 * Safely reduces an array with an initial value.
 * Returns initial value for null/undefined arrays.
 *
 * @example
 * safeReduce(null, (acc, x) => acc + x, 0)    // 0
 * safeReduce([1, 2, 3], (acc, x) => acc + x, 0) // 6
 */
export function safeReduce<T, U>(
  arr: T[] | null | undefined,
  reducer: (accumulator: U, current: T, index: number) => U,
  initialValue: U
): U {
  return (arr ?? []).reduce(reducer, initialValue);
}

/**
 * Safely counts elements matching a predicate.
 * Returns 0 for null/undefined arrays.
 *
 * @example
 * safeCount(null, x => x > 1)     // 0
 * safeCount([1, 2, 3], x => x > 1) // 2
 */
export function safeCount<T>(arr: T[] | null | undefined, predicate: (item: T) => boolean): number {
  return (arr ?? []).filter(predicate).length;
}
