import { readFile } from 'node:fs/promises';
import path from 'node:path';

const SOURCE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);

// A single line can match several patterns, and a minified file can put
// thousands of matches on one line, so the report is capped. The cap is per
// version: a handful of hits is enough to tell a reviewer what to look at.
const MAX_WARNINGS = 50;

const PATTERNS = [
  {
    code: 'fetch',
    // A member call is left alone: Scratch.fetch() is the sandboxed wrapper
    // TurboWarp asks extensions to use, so flagging it would be noise.
    match: /(?<!\.)\bfetch\s*\(/,
    message: 'Calls fetch() directly; prefer Scratch.fetch().',
  },
  {
    code: 'eval',
    match: /\beval\s*\(/,
    message: 'Runs a string as code with eval().',
  },
  {
    code: 'new-function',
    match: /\bnew\s+Function\b/,
    message: 'Builds a function from a string with new Function().',
  },
  {
    code: 'xmlhttprequest',
    match: /\bXMLHttpRequest\b/,
    message: 'Opens a raw XMLHttpRequest instead of using Scratch.fetch().',
  },
  {
    code: 'insecure-http',
    match: /http:\/\//,
    message: 'References a plaintext http:// URL.',
  },
];

// Scan the extracted project for patterns an author should know about before
// the version reaches a reviewer. `files` is the extracted entry list, which
// the tarball reader has already checked stays inside projectDir.
export async function scanSourceWarnings(projectDir, files) {
  const warnings = [];
  for (const file of [...files].sort()) {
    if (!SOURCE_EXTENSIONS.has(path.extname(file).toLowerCase())) continue;
    let text;
    try {
      text = await readFile(path.join(projectDir, file), 'utf8');
    } catch {
      continue;
    }
    const lines = text.split('\n');
    for (let index = 0; index < lines.length; index++) {
      for (const pattern of PATTERNS) {
        if (!pattern.match.test(lines[index])) continue;
        warnings.push({
          code: pattern.code,
          file,
          line: index + 1,
          message: pattern.message,
        });
        if (warnings.length >= MAX_WARNINGS) return warnings;
      }
    }
  }
  return warnings;
}
