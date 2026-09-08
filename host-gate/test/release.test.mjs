import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { buildRelease, renderBundle } from '../scripts/build-release.mjs';

test('standalone release is deterministic, syntax-valid, and contains only approved artifacts',()=>{
  const dir=mkdtempSync(join(tmpdir(),'bb-gate-build-'));
  try {
    assert.equal(renderBundle().bundle,renderBundle().bundle);
    const first=buildRelease(dir),before=readFileSync(join(dir,'build.json'),'utf8');
    assert.equal(first.checksums['agent-scan-gate.mjs'],'783c623f98833db524c164b4edba5e6d9e08502669b6eb9a13bb302be223b083');
    assert.equal(JSON.parse(before).release_tag,'host-gate-v0.1.0');
    assert.equal(Object.hasOwn(JSON.parse(before),'release_status'),false);
    assert.deepEqual(first.checksums,buildRelease(dir).checksums);
    assert.equal(before,readFileSync(join(dir,'build.json'),'utf8'));
    assert.deepEqual(readdirSync(dir).sort(),['LICENSE.txt','agent-scan-gate.mjs','agent-scan-gate.mjs.sha256','agent-scan.cjs','agent-scan.cjs.sha256','build.json'].sort());
    const bundle=readFileSync(join(dir,'agent-scan-gate.mjs'),'utf8');
    assert.match(bundle,/MIT License/);
    assert.doesNotMatch(bundle,/from ['"]\.\.?\//);
    assert.equal(spawnSync(process.execPath,['--check',join(dir,'agent-scan-gate.mjs')]).status,0);
    for(const [name,digest] of Object.entries(first.checksums))assert.equal(createHash('sha256').update(readFileSync(join(dir,name))).digest('hex'),digest);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('standalone CLI rejects bad config and missing/altered adjacent scanner before server startup',()=>{
  const dir=mkdtempSync(join(tmpdir(),'bb-gate-cli-'));
  try {
    buildRelease(dir);
    const executable=join(dir,'agent-scan-gate.mjs'),config=join(dir,'config.json');
    writeFileSync(config,JSON.stringify({command:process.execPath,args:['-e','process.stdout.write("SERVER_MUST_NOT_START")']}));
    let run=spawnSync(process.execPath,[executable],{encoding:'utf8'});
    assert.equal(run.status,2);assert.equal(run.stdout,'');
    writeFileSync(join(dir,'agent-scan.cjs'),'altered');
    run=spawnSync(process.execPath,[executable,'--config',config],{encoding:'utf8'});
    assert.equal(run.status,2);assert.equal(run.stdout,'');assert.match(run.stderr,/scanner_checksum_mismatch/);
    rmSync(join(dir,'agent-scan.cjs'));
    run=spawnSync(process.execPath,[executable,'--config',config],{encoding:'utf8'});
    assert.equal(run.status,2);assert.equal(run.stdout,'');assert.match(run.stderr,/scanner_unavailable/);
  } finally {rmSync(dir,{recursive:true,force:true});}
});
