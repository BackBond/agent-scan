#!/usr/bin/env node
// Internal tools-only MCP stdio boundary. No config writes or runtime downloads.
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GateError, scanManifest, SCANNER_SHA256 } from './host-gate.mjs';
import { createReviewPolicy } from './review-override.mjs';

const MAX_FRAME = 4 * 1024 * 1024;
const MAX_MANIFEST = 256 * 1024;
const VERSIONS = new Set(['2025-11-25','2025-06-18','2025-03-26','2024-11-05','2024-10-07']);
const own = (o,k) => Object.prototype.hasOwnProperty.call(o,k);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const idOK = v => typeof v === 'string' || (Number.isSafeInteger(v));
const hash = v => createHash('sha256').update(v).digest('hex');
const fault = code => new GateError(code);

// Newline framing is bounded before parsing; non-JSON stdout is a hard failure.
export class JsonLines {
  constructor(readable, writable, receive, failed) {
    this.writable=writable; this.readable=readable; this.buffer=Buffer.alloc(0); this.closed=false;
    this.onData=chunk=>{
      if(this.closed)return;
      this.buffer=Buffer.concat([this.buffer,Buffer.from(chunk)]);
      let end;
      while((end=this.buffer.indexOf(10))>=0) {
        const raw=this.buffer.subarray(0,end);this.buffer=this.buffer.subarray(end+1);
        if(raw.length>MAX_FRAME)return failed(fault('frame_limit'));
        let message;
        try {message=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));} catch {return failed(fault('invalid_jsonrpc'));}
        if(!object(message)||message.jsonrpc!=='2.0')return failed(fault('invalid_jsonrpc'));
        if(own(message,'method')) {
          if(typeof message.method!=='string'||(own(message,'id')&&!idOK(message.id))||own(message,'result')||own(message,'error'))return failed(fault('invalid_jsonrpc'));
        } else if(!idOK(message.id)||(own(message,'result')===own(message,'error')))return failed(fault('invalid_jsonrpc'));
        try{receive(message);}catch(error){failed(error);return;}
        if(this.closed)return;
      }
      if(this.buffer.length>MAX_FRAME)failed(fault('frame_limit'));
    };
    readable.on('data',this.onData);
    readable.on('error',()=>failed(fault('transport_error')));
    writable.on('error',()=>failed(fault('transport_error')));
  }
  send(message) {
    if(this.closed)throw fault('transport_closed');
    const line=JSON.stringify(message)+'\n';
    if(Buffer.byteLength(line)+this.writable.writableLength>MAX_FRAME)throw fault('output_limit');
    this.writable.write(line);
  }
  close(){this.closed=true;this.buffer=Buffer.alloc(0);this.readable.off('data',this.onData);this.readable.pause();}
}

function validateConfig(config) {
  if(!object(config)||Object.keys(config).some(k=>!['command','args','cwd','timeoutMs','reviewOverrideFile','reviewRevocationsFile'].includes(k))
      ||!isAbsolute(config.command||'')||!Array.isArray(config.args)||!config.args.every(x=>typeof x==='string')
      ||(config.cwd!==undefined&&!isAbsolute(config.cwd))
      ||(config.reviewOverrideFile!==undefined&&!isAbsolute(config.reviewOverrideFile))
      ||(config.reviewRevocationsFile!==undefined&&!isAbsolute(config.reviewRevocationsFile))
      ||(own(config,'reviewOverrideFile')!==own(config,'reviewRevocationsFile')))throw fault('invalid_host_config');
  const timeoutMs=config.timeoutMs??10000;
  if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000)throw fault('invalid_host_config');
  return {...config,timeoutMs};
}

export function startWrapper({config,scannerPath,input=process.stdin,output=process.stdout,diagnostics=process.stderr}) {
  config=validateConfig(config);
  let scannerBytes;
  try {scannerBytes=readFileSync(scannerPath);} catch {throw fault('scanner_unavailable');}
  if(hash(scannerBytes)!==SCANNER_SHA256)throw fault('scanner_checksum_mismatch');
  const instance=randomUUID();
  const reviewPolicy=createReviewPolicy({path:config.reviewOverrideFile,revocationsPath:config.reviewRevocationsFile});
  let closed=false,child,upstream,initialized=false,clientReady=false,initializing=false;
  let sequence=0,epoch=0,approved=null,exposedHash=null,queued=0,refreshQueued=false,refreshWanted=false;
  let queue=Promise.resolve();const pending=new Map(),clientIds=new Set();
  let finish;const completion=new Promise(r=>finish=r);
  const audit=(reason,checked=null)=>{
    // Never log config, command, upstream stderr, manifests, names or tool arguments.
    const entry={event:'agent_scan_gate',reason,at:new Date().toISOString(),wrapper_instance:instance};
    if(checked){entry.manifest_sha256=checked.snapshot;entry.record=checked.report;
      if(checked.override)entry.operator_override=checked.override;}
    if(diagnostics.writableLength>MAX_FRAME)throw fault('audit_backpressure');
    diagnostics.write(JSON.stringify(entry)+'\n');
  };
  function stop(error=null) {
    if(closed)return;
    closed=true;approved=null;exposedHash=null;downstream.close();upstream?.close();
    for(const p of pending.values()){clearTimeout(p.timer);p.reject(fault('transport_closed'));}pending.clear();
    try {if(error)audit(error.code||'wrapper_failure');}catch{}
    if(child?.pid) {
      const kill=signal=>{try{if(process.platform==='win32')child.kill(signal);else process.kill(-child.pid,signal);}catch{}};
      kill('SIGTERM');setTimeout(()=>{kill('SIGKILL');finish(error?2:0);},250);
    } else finish(error?2:0);
  }
  function send(message){try{downstream.send(message);}catch(error){stop(error);}}
  function invalidate(reason) {
    const wasExposed=exposedHash!==null;
    epoch++;approved=null;exposedHash=null;
    if(clientReady&&(wasExposed||reason==='list_changed'))send({jsonrpc:'2.0',method:'notifications/tools/list_changed'});
    audit(reason);
  }
  const serial=operation=>{
    if(++queued>32){queued--;stop(fault('request_limit'));return;}
    queue=queue.then(async()=>{if(!closed)await operation();}).catch(stop).finally(()=>queued--);
  };
  function request(method,params,timeoutMs=config.timeoutMs) {
    if(closed||!upstream)return Promise.reject(fault('transport_closed'));
    return new Promise((resolveResult,reject)=>{
      const id='gate-'+(++sequence);
      const timer=setTimeout(()=>{pending.delete(id);reject(fault('upstream_timeout'));stop(fault('upstream_timeout'));},Math.max(1,timeoutMs));
      pending.set(id,{resolve:resolveResult,reject,timer});
      try{upstream.send({jsonrpc:'2.0',id,method,...params===undefined?{}:{params}});}catch(error){clearTimeout(timer);pending.delete(id);reject(error);stop(error);}
    });
  }
  function upstreamMessage(message) {
    if(own(message,'method')) {
      if(own(message,'id')) {upstream.send({jsonrpc:'2.0',id:message.id,error:{code:-32601,message:'Client capabilities are not exposed by this tools-only wrapper.'}});return;}
      if(message.method==='notifications/tools/list_changed') {
        invalidate('list_changed');
        refreshWanted=true;
        if(initialized&&!refreshQueued) {
          refreshQueued=true;
          serial(async()=>{
            let attempts=0;
            try {
              do{refreshWanted=false;try{await vet();}catch(error){deny(error);}}while(refreshWanted&&!closed&&++attempts<3);
              if(refreshWanted&&!closed)stop(fault('list_change_storm'));
            }finally{refreshQueued=false;}
          });
        }
      }
      return; // No server instructions, logging messages, prompts, or resources forwarded.
    }
    const waiter=pending.get(message.id);
    if(!waiter){stop(fault('unexpected_response'));return;}
    clearTimeout(waiter.timer);pending.delete(message.id);
    if(own(message,'error'))waiter.reject(fault('upstream_rpc_error'));
    else waiter.resolve(message.result);
  }
  async function initialize(params) {
    if(initialized||initializing||!object(params)||!VERSIONS.has(params.protocolVersion))throw fault('invalid_initialize');
    initializing=true;
    // Check scanner/ruleset/profile before starting any configured server.
    await scanManifest('{"tools":[]}',scannerPath,config.timeoutMs);
    if(closed)throw fault('transport_closed');
    child=spawn(config.command,config.args,{cwd:config.cwd,stdio:['pipe','pipe','pipe'],shell:false,windowsHide:true,detached:process.platform!=='win32'});
    child.on('error',()=>stop(fault('server_start_failed')));
    child.on('exit',()=>stop(fault('server_exited')));
    child.stderr.resume(); // Discard potentially private startup logs.
    child.stderr.on('error',()=>stop(fault('server_stderr_error')));
    upstream=new JsonLines(child.stdout,child.stdin,upstreamMessage,stop);
    child.stdout.on('end',()=>stop(fault('server_stdout_closed')));
    const result=await request('initialize',{protocolVersion:params.protocolVersion,capabilities:{},clientInfo:{name:'backbond-internal-stdio-gate',version:'0.1.0'}});
    if(!object(result)||!VERSIONS.has(result.protocolVersion)||!object(result.capabilities?.tools))throw fault('unsupported_server');
    upstream.send({jsonrpc:'2.0',method:'notifications/initialized'});
    initialized=true;
    audit('wrapper_initialized');
    // Do not expose the upstream server's instructions or pre-vet metadata.
    return {protocolVersion:result.protocolVersion,capabilities:{tools:{listChanged:true}},serverInfo:{name:'backbond-internal-stdio-gate',version:'0.1.0'}};
  }
  async function vet() {
    approved=null;
    const generation=epoch,deadline=Date.now()+config.timeoutMs;
    const tools=[],cursors=new Set();let cursor;
    for(let pages=0;;pages++) {
      const remaining=deadline-Date.now();
      if(remaining<=0)throw fault('vet_timeout');
      if(pages>=100)throw fault('pagination_limit');
      const result=await request('tools/list',cursor===undefined?{}:{cursor},remaining);
      if(!object(result)||!Array.isArray(result.tools))throw fault('invalid_tools_list');
      if(tools.length+result.tools.length>200)throw fault('tool_limit');
      tools.push(...result.tools);
      if(Buffer.byteLength(JSON.stringify({tools}))>MAX_MANIFEST)throw fault('manifest_limit');
      if(epoch!==generation)throw fault('changed_during_vet');
      if(result.nextCursor===undefined)break;
      if(typeof result.nextCursor!=='string'||!result.nextCursor||cursors.has(result.nextCursor))throw fault('invalid_pagination');
      cursor=result.nextCursor;cursors.add(cursor);
    }
    const raw=JSON.stringify({tools}),snapshot=hash(raw);
    const report=await scanManifest(raw,scannerPath,deadline-Date.now());
    if(closed||epoch!==generation)throw fault('changed_during_vet');
    const checked={tools,snapshot,report,epoch:generation};
    audit(report.decision,checked);
    const override=reviewPolicy.check(checked);
    if(report.decision==='review'&&override){checked.override=override;audit('review_operator_accepted',checked);}
    else if(report.decision!=='no_blocking_finding'||report.coverage.status!=='complete')throw new GateError(report.decision,report,snapshot);
    approved=checked;return checked;
  }
  function deny(error) {
    invalidate(error.code||'wrapper_failure');
    // Scanner faults are terminal; block/review/changed metadata can be corrected.
    if(!['block','review','changed_during_vet','manifest_changed','attachment_required','unknown_tool','invalid_params'].includes(error.code)
      &&!error.code?.startsWith('review_override_'))stop(error);
  }
  async function handle(message) {
    try {
      let result;
      if(message.method==='initialize')result=await initialize(message.params);
      else {
        if(!initialized||!clientReady)throw fault('not_initialized');
        if(message.method==='ping')result={};
        else if(message.method==='tools/list') {
          if(message.params!==undefined&&(!object(message.params)||Object.keys(message.params).some(k=>k!=='_meta')))throw fault('invalid_params');
          const checked=await vet();
          if(closed||checked.epoch!==epoch)throw fault('changed_during_vet');
          exposedHash=checked.snapshot;
          // Forward only the metadata fields assessed by the current static profile.
          result={tools:checked.tools.map(({name,description,inputSchema})=>({name,...description===undefined?{}:{description},inputSchema}))};
        } else if(message.method==='tools/call') {
          if(!object(message.params)||typeof message.params.name!=='string'||Object.keys(message.params).some(k=>!['name','arguments','_meta'].includes(k))
              ||(message.params.arguments!==undefined&&!object(message.params.arguments)))throw fault('invalid_params');
          if(!approved||!exposedHash||approved.snapshot!==exposedHash)throw fault('attachment_required');
          const prior=exposedHash;const checked=await vet();
          if(checked.snapshot!==prior)throw fault('manifest_changed');
          if(!checked.tools.some(t=>t.name===message.params.name))throw fault('unknown_tool');
          if(closed||checked.epoch!==epoch)throw fault('changed_during_vet');
          result=await request('tools/call',{name:message.params.name,arguments:message.params.arguments??{}});
          if(checked.epoch!==epoch)throw fault('manifest_changed');
          if(!object(result)||result.isError===true||(!Array.isArray(result.content)&&!object(result.structuredContent)))throw fault('tool_execution_error');
        } else {
          invalidate('unsupported_method');
          send({jsonrpc:'2.0',id:message.id,error:{code:-32601,message:'Only initialize, ping, tools/list and tools/call are supported.'}});return;
        }
      }
      send({jsonrpc:'2.0',id:message.id,result});
    } catch(error) {
      send({jsonrpc:'2.0',id:message.id,error:{code:-32001,message:'Agent Scan gate: '+(error.code||'wrapper_failure')}});
      deny(error);
    } finally {clientIds.delete(message.id);}
  }
  const downstream=new JsonLines(input,output,message=>{
    if(!own(message,'method')){stop(fault('unexpected_client_response'));return;}
    if(!own(message,'id')) {
      if(message.method==='notifications/initialized'&&initialized)clientReady=true;
      else if(message.method==='notifications/cancelled')stop(fault('client_cancelled'));
      return;
    }
    if(clientIds.has(message.id)){stop(fault('duplicate_request_id'));return;}
    clientIds.add(message.id);serial(()=>handle(message));
  },stop);
  input.on('end',()=>stop(downstream.buffer.length?fault('truncated_frame'):null));
  diagnostics.on('error',()=>stop(fault('audit_failure')));
  return {completion,close:()=>stop()};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    if(process.argv.length!==4||process.argv[2]!=='--config')throw fault('usage: --config /absolute/operator-config.json');
    if(!isAbsolute(process.argv[3]))throw fault('invalid_host_config');
    const configBytes=readFileSync(process.argv[3]);
    if(configBytes.length>65536)throw fault('config_limit');
    const config=JSON.parse(configBytes);
    const scannerPath=fileURLToPath(new URL('./vendor/agent-scan.cjs',import.meta.url));
    const wrapper=startWrapper({config,scannerPath});
    process.on('SIGTERM',wrapper.close);process.on('SIGINT',wrapper.close);
    process.exitCode=await wrapper.completion;
  } catch(error) {
    process.stderr.write(JSON.stringify({event:'agent_scan_gate',reason:error instanceof GateError?error.code:'invalid_host_config'})+'\n');
    process.exitCode=2;
  }
}
