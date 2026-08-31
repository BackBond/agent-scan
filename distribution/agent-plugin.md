# Skill-only Agent Plugin

The repository root is a valid Agent Plugin 1.0 package. For external marketplaces, use the dedicated immutable source root at `plugins/backbond-agent-scan`; it contains the same `agent-scan` skill without the repository's unrelated package files. Both forms deliberately contain no hooks, commands, or plugin-level MCP configuration.

Install from the immutable release tag supported by your agent host, or inspect the tag and copy `skills/agent-scan` into the host's standard skill directory. A portable one-command Agent Skill installer is:

```bash
npx -y skills@1.5.18 add https://github.com/BackBond/agent-scan/tree/v0.5.14 --skill agent-scan --yes
```

The installer above is separate software that fetches the tagged public repository. Review its own network and telemetry behavior before using it in a restricted environment. Installing the skill does not execute Agent Scan. The skill only teaches a compatible agent when and how to invoke the exact pinned scanner.

Plugin identity: `backbond-agent-scan`

External marketplace plugin path: `plugins/backbond-agent-scan`

Skill path inside that plugin: `skills/agent-scan/SKILL.md`

Release tag: `v0.5.14`
