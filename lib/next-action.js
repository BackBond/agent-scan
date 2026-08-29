'use strict';

const { safeInline } = require('./text.js');

function liveToolsNextAction(version) {
  const packageSpec = `@backbond/agent-scan@${version}`;
  return {
    code: 'provide_live_tools',
    reason: 'A live runtime tool inventory was not supplied.',
    save_as: 'tools-list.json',
    stdin_shape: {
      jsonrpc: '2.0',
      id: 1,
      result: {
        tools: [{
          name: 'tool_name',
          description: 'What the tool does',
          inputSchema: { type: 'object', properties: {} },
        }],
      },
    },
    commands: {
      posix_or_cmd: `npx -y ${packageSpec} scan --stdin < tools-list.json`,
      powershell: `Get-Content -Raw .\\tools-list.json | npx -y ${packageSpec} scan --stdin`,
    },
  };
}

function renderNextAction(action) {
  return [
    'Next: save your current MCP tools/list response as tools-list.json.',
    `Shape: ${JSON.stringify(action.stdin_shape)}`,
    `Run: ${action.commands.posix_or_cmd}`,
    `PowerShell: ${action.commands.powershell}`,
  ].map(line => safeInline(line)).join('\n');
}

module.exports = { liveToolsNextAction, renderNextAction };
