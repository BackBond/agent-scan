#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const source = path.resolve(__dirname, '..');
const argument = process.argv[2];
if (!argument) throw new Error('usage: export-clean-public.js <empty-target-directory>');
const target = path.resolve(argument);
if (target === source || target.startsWith(`${source}${path.sep}`)) throw new Error('target must be outside the source repository');
if (fs.existsSync(target) && fs.readdirSync(target).length) throw new Error('target directory must be empty');
fs.mkdirSync(target, { recursive: true });

const allowlist = [
  '.github', 'bin', 'docs', 'lib', 'scripts', 'site', 'test',
  '.gitignore', 'action.yml', 'AGENTS.md', 'CHANGELOG.md', 'LICENSE', 'package.json', 'README.md',
];
for (const relative of allowlist) {
  const from = path.join(source, relative);
  if (!fs.existsSync(from)) continue;
  fs.cpSync(from, path.join(target, relative), { recursive: true, errorOnExist: true });
}
if (fs.existsSync(path.join(target, '.git'))) throw new Error('export unexpectedly contains Git metadata');
process.stdout.write(`${target}\n`);
