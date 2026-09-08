import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
const sdkPackage=process.env.MCP_SDK_PACKAGE_JSON;
test('official MCP SDK 1.30.0 connects through the actual wrapper executable', {skip:!sdkPackage}, async()=>{
  const require=createRequire(sdkPackage);
  const {Client}=require('@modelcontextprotocol/sdk/client/index.js');
  const {StdioClientTransport}=require('@modelcontextprotocol/sdk/client/stdio.js');
  assert.equal(JSON.parse(readFileSync(join(dirname(sdkPackage),'node_modules/@modelcontextprotocol/sdk/package.json'),'utf8')).version,'1.30.0');
  const dir=mkdtempSync(join(tmpdir(),'bb-sdk-stdio-'));
  const control=join(dir,'state.json'),counter=join(dir,'counter'),config=join(dir,'config.json');
  writeFileSync(control,JSON.stringify({mode:'clean',revision:0}));writeFileSync(counter,'');
  writeFileSync(config,JSON.stringify({command:process.execPath,args:[fileURLToPath(new URL('../fixtures/fixture-server.mjs',import.meta.url)),control,counter]}));
  const client=new Client({name:'wrapper-interop-fixture',version:'1'},{capabilities:{}});
  const transport=new StdioClientTransport({command:process.execPath,args:[process.env.BB_WRAPPER_EXECUTABLE || fileURLToPath(new URL('../stdio-wrapper.mjs',import.meta.url)),'--config',config],stderr:'pipe'});
  let diagnostics='';transport.stderr.on('data',chunk=>diagnostics+=chunk);
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().name,'backbond-internal-stdio-gate');
    assert.equal((await client.listTools()).tools[0].name,'add');
    assert.equal((await client.callTool({name:'add',arguments:{a:1,b:2}})).content[0].text,'3');
    writeFileSync(control,JSON.stringify({mode:'block',revision:1}));
    const deadline=Date.now()+5000;
    while(!diagnostics.includes('"reason":"block"')){if(Date.now()>deadline)throw Error('notification re-vet did not finish');await new Promise(r=>setTimeout(r,20));}
    await assert.rejects(client.callTool({name:'add',arguments:{a:1,b:2}}));
    assert.ok(!diagnostics.includes('PRIVATE_'));
  }finally{await client.close();await new Promise(r=>setTimeout(r,350));rmSync(dir,{recursive:true,force:true});}
});
