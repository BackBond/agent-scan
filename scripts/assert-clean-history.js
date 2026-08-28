#!/usr/bin/env node
'use strict';

const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');

const restricted = new Set([
  '2aaf9a112578b0758b35b8a39f677e829e8cc1235666261c5d4fdc30435da935',
  '821e56e9a416c37160f5429dba6b554b429a683345e1fc52f6b44b4d4872b19e',
  '07b0ba45bbafd7b77ae2a34353bd526950383b6d6b6714498f31e95a44da7fb6',
  '591bfb4ee4d7c9e1df4fe589dd31915ee34383ab2e58132ef26a83addca4b8f1',
  '245465190398d13d5d02ca214a0b3d3398e6c918e329c835ba66cffdea067b2d',
  '05c321154b27b885db71ad55c75258d48586b461981c5cf7152e77193d8b7e26',
  'cf928e8ce57fdf0c86df1f5623665f48af691e2ff7ee113ddf4fb0041636ba67',
  '52d6ef6f2e00da24f53395d351d74ffa3b8429b6ed9673b592f5ae2f42f5f161',
  '7744aa2906e6505e640f116c96924d5f07afb404d5af58a5ce59ba0b8319c49b',
  '2202e402768c1dfc55af2261a53d2580a357900b440fdbfd5b7f11ab844a9d69',
  '290d5d30f2220a5044bb7a4bc06003b5a9e089a89b48c1f35b8f017893c14526',
  'c3cfaa82954506872cfda435718b1a654d51adfb4f063bf752061b1de43eca11',
]);

const history = execFileSync('git', ['log', '--all', '-p', '--no-ext-diff', '--pretty=format:'], {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});
const tokens = history.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
for (const token of tokens) {
  const digest = createHash('sha256').update(token).digest('hex');
  if (restricted.has(digest)) {
    process.stderr.write('public-history gate: restricted implementation fingerprints exist in reachable Git history\n');
    process.exit(1);
  }
}
process.stdout.write('public-history gate: clean\n');
