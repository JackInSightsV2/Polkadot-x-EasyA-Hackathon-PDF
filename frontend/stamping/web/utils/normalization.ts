export const NORMALIZATION_STRATEGY = 'unicode_nfkc_lowercase_whitespace_collapse';

/**
 * Apply the same deterministic normalization used by the backend.
 * - Unicode NFKC
 * - Lowercase
 * - Collapse whitespace to single spaces
 * - Trim leading/trailing whitespace
 */
export function normalizeText(rawText: string): string {
  if (!rawText) return '';

  const unicodeNormalized = rawText.normalize('NFKC');
  const lowerCased = unicodeNormalized.toLowerCase();
  const collapsedWhitespace = lowerCased.replace(/\s+/g, ' ');
  return collapsedWhitespace.trim();
}
