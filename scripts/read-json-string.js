#!/usr/bin/env node
'use strict';

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  if (!input.trim()) return;
  const value = JSON.parse(input);
  if (typeof value === 'string') process.stdout.write(value);
});
