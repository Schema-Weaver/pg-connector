#!/usr/bin/env node

/**
 * Post-build script: ensures the CLI entry point has a clean shebang,
 * LF line endings (critical for Linux/EC2), and executable permissions.
 * Runs after tsc build:cjs.
 */

import { readFile, writeFile, chmod } from 'node:fs/promises';

const CLI_PATH = 'dist/cjs/cli/index.js';
const SHEBANG = '#!/usr/bin/env node\n';

async function main() {
  try {
    let content = await readFile(CLI_PATH, 'utf8');

    // Strip Windows CRLF line endings → LF.
    // This is the fix for the Linux/EC2 bug where `\r` in the shebang
    // causes: /usr/bin/env: 'node\r': No such file or directory
    content = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    // Ensure shebang is present and clean
    if (content.startsWith('#!')) {
      // Replace any existing shebang line (may have \r or other issues)
      content = content.replace(/^#![^\n]*\n/, SHEBANG);
      console.log('[postbuild] Sanitized existing shebang in', CLI_PATH);
    } else {
      content = SHEBANG + content;
      console.log('[postbuild] Injected shebang into', CLI_PATH);
    }

    await writeFile(CLI_PATH, content, 'utf8');

    // Set executable bit (no-op on Windows, essential on Unix)
    await chmod(CLI_PATH, 0o755);
    console.log('[postbuild] Set executable permissions on', CLI_PATH);
  } catch (err) {
    console.error('[postbuild] Error:', err.message);
    process.exit(1);
  }
}

main();
