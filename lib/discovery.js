'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PROJECT_CONFIGS = [
  ['.mcp.json', 'mcp-project'],
  ['mcp.json', 'mcp-project'],
  [path.join('.cursor', 'mcp.json'), 'cursor'],
  [path.join('.vscode', 'mcp.json'), 'vscode'],
  [path.join('.gemini', 'settings.json'), 'gemini'],
  [path.join('.claude', 'settings.json'), 'claude-code'],
  [path.join('.claude', 'settings.local.json'), 'claude-code'],
];

const PROJECT_INSTRUCTIONS = [
  'AGENTS.md', 'SKILL.md',
  path.join('.claude', 'CLAUDE.md'),
  path.join('.cursor', 'rules'),
];

function existingFile(filename) {
  try { return fs.statSync(filename).isFile(); }
  catch { return false; }
}

function existingDirectory(filename) {
  try { return fs.statSync(filename).isDirectory(); }
  catch { return false; }
}

function addCandidate(seen, files, filename, adapter, location) {
  const absolute = path.resolve(filename);
  const key = process.platform === 'win32' ? absolute.toLowerCase() : absolute;
  if (seen.has(key) || !existingFile(absolute)) return;
  seen.add(key);
  files.push({ kind: 'config', path: absolute, adapter, location });
}

function projectRoots(start, home) {
  const roots = [];
  let current = path.resolve(start);
  for (let depth = 0; depth < 8; depth += 1) {
    roots.push(current);
    if (fs.existsSync(path.join(current, '.git'))) break;
    const parent = path.dirname(current);
    if (parent === current) break;
    if (home && current === path.resolve(home)) break;
    current = parent;
  }
  return roots;
}

function discoverInstructionFiles(roots) {
  const found = [];
  const seen = new Set();
  for (const root of roots) {
    for (const relative of PROJECT_INSTRUCTIONS) {
      const candidate = path.join(root, relative);
      if (existingFile(candidate)) {
        const absolute = path.resolve(candidate);
        if (!seen.has(absolute)) { seen.add(absolute); found.push(absolute); }
      } else if (relative.endsWith('rules') && existingDirectory(candidate)) {
        for (const entry of fs.readdirSync(candidate, { withFileTypes: true })) {
          if (!entry.isFile() || !/\.(md|mdc)$/i.test(entry.name)) continue;
          const absolute = path.join(candidate, entry.name);
          if (!seen.has(absolute)) { seen.add(absolute); found.push(absolute); }
        }
      }
    }
  }
  return found.sort();
}

function homeCandidates(home, appData) {
  const candidates = [
    [path.join(home, '.cursor', 'mcp.json'), 'cursor'],
    [path.join(home, '.gemini', 'settings.json'), 'gemini'],
    [path.join(home, '.claude', 'settings.json'), 'claude-code'],
    [path.join(home, '.claude.json'), 'claude-code'],
    [path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), 'windsurf'],
    [path.join(home, '.copilot', 'mcp-config.json'), 'vscode'],
  ];
  if (process.platform === 'win32' && appData) {
    candidates.push(
      [path.join(appData, 'Claude', 'claude_desktop_config.json'), 'claude-desktop'],
      [path.join(appData, 'Code', 'User', 'mcp.json'), 'vscode'],
    );
  } else if (process.platform === 'darwin') {
    candidates.push(
      [path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), 'claude-desktop'],
      [path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'), 'vscode'],
    );
  } else {
    candidates.push([path.join(home, '.config', 'Code', 'User', 'mcp.json'), 'vscode']);
  }
  return candidates;
}

function discover(options = {}) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const home = path.resolve(options.home || os.homedir());
  const appData = options.appData === undefined ? process.env.APPDATA : options.appData;
  const roots = projectRoots(cwd, home);
  const files = [];
  const seen = new Set();
  for (const root of roots) {
    for (const [relative, adapter] of PROJECT_CONFIGS) {
      addCandidate(seen, files, path.join(root, relative), adapter, 'project');
    }
  }
  for (const [filename, adapter] of homeCandidates(home, appData)) {
    addCandidate(seen, files, filename, adapter, 'user');
  }
  return {
    protocol: 'backbond-discovery-plan/v1',
    root: cwd,
    scanned_locations: ['project ancestors (bounded to 8)', 'known user config paths'],
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
    instruction_files: discoverInstructionFiles(roots),
  };
}

module.exports = { PROJECT_CONFIGS, discover };
