import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
const { startWrapper } = await import(process.env.BB_WRAPPER_MODULE_URL || '../stdio-wrapper.mjs');
import { SCANNER_SHA256 } from '../host-gate.mjs';
const scannerPath=fileURLToPath(new URL('../vendor/agent-scan.cjs',import.meta.url));
const fixture=fileURLToPath(new URL('../fixtures/fixture-server.mjs',import.meta.url));
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function until(check,timeout=5000){const deadline=Date.now()+timeout;while(!check()){if(Date.now()>deadline)throw Error('condition timeout');await wait(10);}}
function harness(mode='clean',timeoutMs=3000,extra={}) {
  const {withReviewOverride=false,...wrapperOptions}=extra;
  const dir=mkdtempSync(join(tmpdir(),'bb-stdio-test-'));
  const control=join(dir,'state.json'),counter=join(dir,'counter');
  const approvalPath=join(dir,'operator-review.json');
  const revocationsPath=join(dir,'revocations.json');
  writeFileSync(revocationsPath,JSON.stringify({protocol:'backbond-review-revocations/v1',revoked_approval_ids:[]}));
  let state={mode,revision:0};writeFileSync(control,JSON.stringify(state));writeFileSync(counter,'');
  const input=new PassThrough(),output=new PassThrough(),diagnostics=new PassThrough();
  let buffer='',logs='',seq=0,closed=false;const responses=new Map(),messages=[];
  output.on('data',chunk=>{buffer+=chunk;let end;while((end=buffer.indexOf('\n'))>=0){const m=JSON.parse(buffer.slice(0,end));buffer=buffer.slice(end+1);messages.push(m);responses.get(m.id)?.(m);responses.delete(m.id);}});
  diagnostics.on('data',chunk=>logs+=chunk);
  const wrapper=startWrapper({config:{command:process.execPath,args:[fixture,control,counter],timeoutMs,...withReviewOverride?{reviewOverrideFile:approvalPath,reviewRevocationsFile:revocationsPath}:{}},scannerPath,input,output,diagnostics,...wrapperOptions});
  wrapper.completion.then(()=>{closed=true;for(const resolve of responses.values())resolve({error:{message:'closed'}});responses.clear();});
  const request=(method,params)=>new Promise(resolve=>{if(closed){resolve({error:{message:'closed'}});return;}const id=++seq;responses.set(id,resolve);input.write(JSON.stringify({jsonrpc:'2.0',id,method,...params===undefined?{}:{params}})+'\n');});
  return {input,messages,request,wrapper,get logs(){return logs;},get closed(){return closed;},
    approve(patch={}){
      const event=logs.trim().split('\n').map(JSON.parse).filter(e=>e.record).at(-1);
      const record={protocol:'backbond-review-override/v1',approval_id:'test-approval-1',operator:'fixture-operator',
        approved_at:new Date(Date.now()-1000).toISOString(),
        manifest_sha256:event.manifest_sha256,scanner_sha256:SCANNER_SHA256,ruleset_sha256:event.record.ruleset.sha256,
        profile_sha256:event.record.profile.sha256,accepted_review_codes:Object.keys(event.record.coverage.gap_codes),
        reason:'Synthetic fixture metadata reviewed for this test only.',...patch};
      writeFileSync(approvalPath,JSON.stringify(record));return record;
    },
    writeApproval:raw=>writeFileSync(approvalPath,raw),
    revoke:ids=>writeFileSync(revocationsPath,JSON.stringify({protocol:'backbond-review-revocations/v1',revoked_approval_ids:ids})),
    writeRevocations:raw=>writeFileSync(revocationsPath,raw),
    removeRevocations:()=>rmSync(revocationsPath),
    count:kind=>readFileSync(counter,'utf8').split('\n').filter(x=>x===kind).length,
    change:(mode,more={})=>{state={mode,revision:state.revision+1,...more};writeFileSync(control,JSON.stringify(state));},
    async init(){const r=await request('initialize',{protocolVersion:'2025-06-18',capabilities:{},clientInfo:{name:'fixture',version:'1'}});assert.ok(r.result,JSON.stringify(r));input.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');return r.result;},
    async close(){wrapper.close();await wrapper.completion;input.destroy();output.destroy();diagnostics.destroy();rmSync(dir,{recursive:true,force:true});},
  };
}
test('stdio handshake, vetted list and call; no unvetted initialization or extra metadata leaks',async()=>{
  const h=harness();try{
    const init=await h.init();assert.deepEqual(init.capabilities,{tools:{listChanged:true}});
    assert.ok(!JSON.stringify(init).includes('PRIVATE_'));
    const list=await h.request('tools/list',{});assert.equal(list.result.tools[0].name,'add');
    assert.ok(!JSON.stringify(list).includes('EXTRA_'));
    const call=await h.request('tools/call',{name:'add',arguments:{a:1,b:2}});assert.equal(call.result.content[0].text,'3');assert.equal(h.count('call'),1);
    assert.ok(h.count('list')>=2);assert.ok(!/PRIVATE_|EXTRA_|"name":"add"/.test(h.logs));
    const logs=h.logs.trim().split('\n').map(JSON.parse);assert.ok(logs.some(l=>l.record?.ruleset.sha256.startsWith('bcfa6d47')));
  }finally{await h.close();}
});
test('recorded REVIEW override exposes tools and calls but scanner decision stays review',async()=>{
  const h=harness('review-destination',3000,{withReviewOverride:true});try{
    await h.init();assert.ok((await h.request('tools/list',{})).error);h.approve();
    const list=await h.request('tools/list',{});assert.ok(list.result.tools.length);
    assert.ok((await h.request('tools/call',{name:list.result.tools[0].name})).result);
    assert.equal(h.count('call'),1);
    const accepted=h.logs.trim().split('\n').map(JSON.parse).filter(e=>e.reason==='review_operator_accepted');
    assert.equal(accepted.length,2);assert.equal(accepted[0].record.decision,'review');
    assert.equal(accepted[0].operator_override.operator,'fixture-operator');
    assert.ok(!h.logs.includes('Synthetic fixture metadata reviewed')); // free-text rationale stays in protected record
  }finally{await h.close();}
});
test('valid review approval cannot mask a subsequently killed scanner',async()=>{
  const h=harness('review-destination',3000,{withReviewOverride:true});const original=childProcess.execFile;
  try{
    await h.init();await h.request('tools/list',{});h.approve();assert.ok((await h.request('tools/list',{})).result);
    childProcess.execFile=(...args)=>{const child=original(...args);child.kill('SIGKILL');return child;};syncBuiltinESMExports();
    assert.ok((await h.request('tools/call',{name:'status'})).error);assert.equal(h.count('call'),0);
    assert.ok(h.logs.includes('scanner_failure'));
  }finally{childProcess.execFile=original;syncBuiltinESMExports();await h.close();}
});
for(const [label,patch,reason] of [
  ['wrong hash',{manifest_sha256:'0'.repeat(64)},'manifest_changed'],
  ['obsolete instance field',{wrapper_instance:'different-process'},'invalid'],
  ['scanner pin',{scanner_sha256:'0'.repeat(64)},'policy_mismatch'],
  ['ruleset pin',{ruleset_sha256:'0'.repeat(64)},'policy_mismatch'],
  ['profile pin',{profile_sha256:'0'.repeat(64)},'policy_mismatch'],
  ['missing operator',{operator:''},'invalid'],
  ['missing rationale',{reason:''},'invalid'],
  ['unaccepted constraints',{accepted_review_codes:[]},'review_scope_mismatch'],
  ['expired',{expires_at:'2000-01-01T00:00:00Z'},'invalid'],
  ['future dated',{approved_at:'2999-01-01T00:00:00Z'},'invalid'],
  ['unknown bypass field',{allow_block:true},'invalid']
])test('REVIEW record refuses '+label,async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});h.approve(patch);
    assert.match((await h.request('tools/list',{})).error.message,new RegExp('review_override_'+reason));
    assert.ok((await h.request('tools/call',{name:'private_identity'})).error);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('even an exact-hash operator record cannot override BLOCK',async()=>{
  const h=harness('block',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});h.approve();
    assert.match((await h.request('tools/list',{})).error.message,/gate: block$/);
    assert.equal(h.count('call'),0);assert.ok(!h.logs.includes('review_operator_accepted'));
  }finally{await h.close();}
});
test('list_changed requires relisting but an unchanged hash reuses the operator decision',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});h.approve();await h.request('tools/list',{});
    h.change('review');await until(()=>h.logs.includes('"reason":"list_changed"'));
    assert.ok((await h.request('tools/call',{name:'private_identity'})).error);
    assert.ok((await h.request('tools/list',{})).result);
    assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('silent changed hash refuses calls; restoring the exact approved hash permits relisting',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});const r=h.approve();await h.request('tools/list',{});
    h.change('review-changed',{notify:false});await wait(70);
    assert.ok((await h.request('tools/call',{name:'private_identity'})).error);assert.equal(h.count('call'),0);
    h.change('review',{notify:false});await wait(70);h.writeApproval(JSON.stringify(r));
    assert.ok((await h.request('tools/list',{})).result);
  }finally{await h.close();}
});
test('record corruption fails closed; a restored valid unrevoked record permits relisting',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});const r=h.approve();await h.request('tools/list',{});
    h.writeApproval('not-json');assert.ok((await h.request('tools/call',{name:'private_identity'})).error);
    h.writeApproval(JSON.stringify(r));assert.ok((await h.request('tools/list',{})).result);
    assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('persistent revocation refuses the next call and survives an approval-file replay',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});const r=h.approve();await h.request('tools/list',{});
    h.revoke([r.approval_id]);
    assert.match((await h.request('tools/call',{name:'private_identity'})).error.message,/review_override_revoked/);
    h.writeApproval(JSON.stringify(r));assert.match((await h.request('tools/list',{})).error.message,/review_override_revoked/);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('unchanged valid approval survives restart; persistent revocation also survives restart',async()=>{
  const a=harness('review',3000,{withReviewOverride:true});let record;
  try{await a.init();await a.request('tools/list',{});record=a.approve();assert.ok((await a.request('tools/list',{})).result);}finally{await a.close();}
  const b=harness('review',3000,{withReviewOverride:true});try{
    await b.init();b.writeApproval(JSON.stringify(record));
    assert.ok((await b.request('tools/list',{})).result);assert.equal(b.count('call'),0);
  }finally{await b.close();}
  const c=harness('review',3000,{withReviewOverride:true});try{
    await c.init();c.writeApproval(JSON.stringify(record));c.revoke([record.approval_id]);
    assert.match((await c.request('tools/list',{})).error.message,/review_override_revoked/);
  }finally{await c.close();}
});
for(const kind of ['missing','malformed','wrong-protocol','oversize'])test('revocation list '+kind+' fails closed before invocation',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});h.approve();await h.request('tools/list',{});
    if(kind==='missing')h.removeRevocations();else h.writeRevocations(kind==='malformed'?'not-json':kind==='oversize'?' '.repeat(65537):'{"protocol":"wrong","revoked_approval_ids":[]}');
    assert.match((await h.request('tools/call',{name:'private_identity'})).error.message,/review_override_revocations_/);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('approval expiry is rechecked before each call',async()=>{
  const h=harness('review',3000,{withReviewOverride:true});try{
    await h.init();await h.request('tools/list',{});h.approve({expires_at:new Date(Date.now()+1500).toISOString()});
    assert.ok((await h.request('tools/list',{})).result);await wait(1550);
    assert.match((await h.request('tools/call',{name:'private_identity'})).error.message,/review_override_invalid/);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
for(const [mode,reason] of [['block','block'],['review','review'],['empty','review'],['paginated-block','block'],['cycle','invalid_pagination'],['tool-limit','tool_limit'],['manifest-limit','manifest_limit'],['malformed','invalid_jsonrpc'],['oversize','frame_limit'],['rpc-error','upstream_rpc_error'],['timeout','upstream_timeout'],['exit','server_']]) {
  test(mode+' leaves definitions and invocation unavailable',async()=>{
    const h=harness(mode,1500);try{
      await h.init();const result=await h.request('tools/list',{});assert.ok(result.error);
      assert.ok(h.logs.includes(reason),h.logs);assert.equal(h.count('call'),0);
      const call=await h.request('tools/call',{name:'add'});assert.ok(call.error);assert.equal(h.count('call'),0);
      assert.ok(!h.logs.includes('PRIVATE_UPSTREAM_ERROR'));assert.ok(!h.logs.includes('PRIVATE_NON_JSON_OUTPUT'));
      assert.ok(!h.messages.some(m=>m.result?.tools?.length));
    }finally{await h.close();}
  });
}
test('list_changed immediately revokes approval, proactively re-vets, and blocks stale calls',async()=>{
  const h=harness();try{
    await h.init();assert.ok((await h.request('tools/list',{})).result.tools.length);
    const lists=h.count('list');h.change('block');
    await until(()=>h.messages.some(m=>m.method==='notifications/tools/list_changed'));
    const response=await h.request('tools/call',{name:'add'});assert.ok(response.error);
    await until(()=>h.logs.includes('"reason":"block"'));
    assert.ok(h.count('list')>lists);assert.equal(h.count('call'),0);
    const result=await h.request('tools/list',{});assert.ok(result.error);
  }finally{await h.close();}
});
test('clean change requires a new client list before calling',async()=>{
  const h=harness();try{
    await h.init();await h.request('tools/list',{});h.change('clean-changed');
    await until(()=>h.logs.includes('"reason":"list_changed"'));
    assert.ok((await h.request('tools/call',{name:'add'})).error);assert.equal(h.count('call'),0);
    assert.ok((await h.request('tools/list',{})).result.tools[0].description.includes('supplied'));
    assert.ok((await h.request('tools/call',{name:'add'})).result);assert.equal(h.count('call'),1);
  }finally{await h.close();}
});
test('silent metadata changes are re-vetted before invocation',async()=>{
  const h=harness();try{
    await h.init();await h.request('tools/list',{});h.change('clean-changed',{notify:false});await wait(70);
    assert.match((await h.request('tools/call',{name:'add'})).error.message,/manifest_changed/);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('notification during list collection cannot publish the in-flight snapshot',async()=>{
  const h=harness('change-during-list');try{
    await h.init();const result=await h.request('tools/list',{});assert.ok(result.error);
    assert.equal(h.count('call'),0);assert.ok(!h.messages.some(m=>m.result?.tools?.length));
    await until(()=>h.closed);assert.ok(h.logs.includes('list_change_storm'));
  }finally{await h.close();}
});
test('a missing or tampered vendor file prevents any upstream startup',()=>{
  for(const path of [scannerPath+'.missing',fixture]) {
    assert.throws(()=>startWrapper({config:{command:process.execPath,args:[fixture]},scannerPath:path}),/scanner_unavailable|scanner_checksum_mismatch/);
  }
});
test('killed scanner fails closed inside the stdio wrapper',async()=>{
  const h=harness();const original=childProcess.execFile;
  try {
    await h.init();childProcess.execFile=(...args)=>{const child=original(...args);child.kill('SIGKILL');return child;};syncBuiltinESMExports();
    const result=await h.request('tools/list',{});assert.ok(result.error);assert.equal(h.count('call'),0);assert.ok(h.logs.includes('scanner_failure'));
  }finally{childProcess.execFile=original;syncBuiltinESMExports();await h.close();}
});
test('unsupported methods and calls before a vetted list never reach the server',async()=>{
  const h=harness();try{
    await h.init();assert.equal((await h.request('resources/read',{uri:'file:///private'})).error.code,-32601);
    assert.ok((await h.request('tools/call',{name:'add'})).error);assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
test('tool timeout revokes attachment and terminates the upstream process',async()=>{
  const h=harness('call-timeout',1000);try{
    await h.init();await h.request('tools/list',{});assert.ok((await h.request('tools/call',{name:'add'})).error);
    await until(()=>h.closed);assert.equal(h.count('call'),1);assert.ok(h.logs.includes('upstream_timeout'));
  }finally{await h.close();}
});
test('oversized client frame fails closed before forwarding',async()=>{
  const h=harness();try{
    await h.init();h.input.write('x'.repeat(4*1024*1024+1));await until(()=>h.closed);
    assert.ok(h.logs.includes('frame_limit'));assert.equal(h.count('call'),0);
  }finally{await h.close();}
});
for(const field of ['ruleset','profile'])test(field+' digest mismatch refuses startup despite an intact vendor file',async()=>{
  const h=harness();const original=childProcess.execFile;
  childProcess.execFile=(...args)=>{
    const callback=args.at(-1);args[args.length-1]=(error,stdout,stderr)=>{const parsed=JSON.parse(stdout);parsed[field].sha256='0'.repeat(64);callback(error,JSON.stringify(parsed),stderr);};
    return original(...args);
  };syncBuiltinESMExports();
  try {
    const response=await h.request('initialize',{protocolVersion:'2025-06-18'});
    assert.ok(response.error);assert.ok(h.logs.includes('scanner_identity_or_decision_mismatch'));assert.equal(h.count('list'),0);assert.equal(h.count('call'),0);
  }finally{childProcess.execFile=original;syncBuiltinESMExports();await h.close();}
});
test('a stopped scanner is killed at the vet deadline on Linux',{skip:process.platform==='win32'},async()=>{
  const h=harness('clean',1200);const original=childProcess.execFile;
  try {
    await h.init();childProcess.execFile=(...args)=>{const child=original(...args);child.kill('SIGSTOP');return child;};syncBuiltinESMExports();
    const start=Date.now();const result=await h.request('tools/list',{});
    assert.ok(result.error);assert.ok(Date.now()-start<3000);assert.ok(h.logs.includes('scanner_failure'));assert.equal(h.count('call'),0);
  }finally{childProcess.execFile=original;syncBuiltinESMExports();await h.close();}
});
