# Install the BackBond Agent Scan skill

Copy this entire `agent-scan` folder into the project's standard skill directory:

```text
.agents/skills/agent-scan/
```

The result must be:

```text
.agents/skills/agent-scan/SKILL.md
```

The folder name and the `name` field in the skill frontmatter must both remain `agent-scan`. The skill is pinned to `@backbond/agent-scan@0.6.0`; do not replace the version with `@latest`.

This skill instructs a compatible agent when to run the scanner and how to interpret its output. Installing the skill does not run a scan, attach an MCP server, monitor a runtime, or create insurance coverage.
