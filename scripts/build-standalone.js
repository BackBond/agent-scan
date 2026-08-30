#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const ENTRY = path.join(ROOT, 'bin', 'agent-scan.js');
const output = path.resolve(process.argv[2] || path.join(ROOT, 'agent-scan.cjs'));
const modules = new Map();
const license = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8').replace(/\r\n?/g, '\n').trim();
const licenseComment = license.split('\n').map(line => ` * ${line.replace(/\*\//g, '* /')}`).join('\n');

function moduleId(filename) {
  return path.relative(ROOT, filename).split(path.sep).join('/');
}

function resolveLocal(from, request) {
  const candidate = path.resolve(path.dirname(from), request);
  for (const filename of [candidate, `${candidate}.js`, `${candidate}.json`]) {
    if (fs.existsSync(filename) && fs.statSync(filename).isFile()) return filename;
  }
  throw new Error(`cannot bundle ${request} from ${moduleId(from)}`);
}

function visit(filename) {
  const id = moduleId(filename);
  if (modules.has(id)) return;
  if (!filename.startsWith(`${ROOT}${path.sep}`)) throw new Error(`refusing module outside repository: ${filename}`);
  if (path.extname(filename) === '.json') {
    modules.set(id, { kind: 'json', value: JSON.parse(fs.readFileSync(filename, 'utf8')) });
    return;
  }
  let source = fs.readFileSync(filename, 'utf8').replace(/^#![^\r\n]*(?:\r?\n)?/, '');
  source = source.replace(/\r\n?/g, '\n');
  modules.set(id, { kind: 'javascript', source });
  const requirePattern = /\brequire\(\s*(['"])([^'"]+)\1\s*\)/g;
  for (const match of source.matchAll(requirePattern)) {
    if (match[2].startsWith('.')) visit(resolveLocal(filename, match[2]));
  }
}

function renderFactory(id, entry) {
  if (entry.kind === 'json') {
    return `${JSON.stringify(id)}: function(module) {\nmodule.exports = ${JSON.stringify(entry.value, null, 2)};\n}`;
  }
  return `${JSON.stringify(id)}: function(module, exports, require, __filename, __dirname) {\n${entry.source}\n}`;
}

visit(ENTRY);
const factories = [...modules.entries()].sort(([left], [right]) => left.localeCompare(right))
  .map(([id, entry]) => renderFactory(id, entry)).join(',\n\n');
const bundle = `#!/usr/bin/env node
'use strict';

/*
 * @backbond/agent-scan standalone release asset.
 * Generated deterministically by scripts/build-standalone.js.
 * Local modules are embedded below without minification; Node built-ins remain native.
 */

/*
${licenseComment}
 */

const __nativeRequire = require;
const __posix = __nativeRequire('node:path').posix;
const __factories = {
${factories}
};
const __cache = Object.create(null);

function __resolve(from, request) {
  if (!request.startsWith('.')) return request;
  const base = __posix.normalize(__posix.join(__posix.dirname(from), request));
  for (const candidate of [base, base + '.js', base + '.json']) {
    if (Object.prototype.hasOwnProperty.call(__factories, candidate)) return candidate;
  }
  throw new Error('standalone module not found: ' + request + ' from ' + from);
}

function __load(id) {
  if (!Object.prototype.hasOwnProperty.call(__factories, id)) return __nativeRequire(id);
  if (__cache[id]) return __cache[id].exports;
  const module = { exports: {} };
  __cache[id] = module;
  const localRequire = request => __load(__resolve(id, request));
  __factories[id](module, module.exports, localRequire, id, __posix.dirname(id));
  return module.exports;
}

__load(${JSON.stringify(moduleId(ENTRY))});
`;

fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, bundle, { encoding: 'utf8', mode: 0o755 });
process.stdout.write(`${output}\n`);
