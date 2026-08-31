# Design-partner outreach

The controlled launch asks for a tool-decision test, not a testimonial and not a copy of the partner's configuration.

## Who to invite

Prioritize 10-15 people who actively build or review:

- MCP servers or clients;
- agent platforms and tool routers;
- coding-agent or enterprise-agent deployments;
- AI application security controls; or
- risk and governance programs for deployed agents.

Avoid mass outreach. The first cohort should be willing to describe whether the scanner changed a real attachment or composition decision.

## Email / direct message

**Subject:** Will you try a local MCP pre-attachment gate?

We have published `@backbond/agent-scan@0.5.15`, a free deterministic static check for MCP and AI-agent tool manifests.

Would you run it on one proposed toolset before attaching the tools?

```text
npx -y @backbond/agent-scan@0.5.15 vet-tools --stdin < tools-list.json
```

It does not execute the tools or upload the manifest. Exit 1 means block automatic attachment, exit 3 means the metadata is insufficient or ambiguous, and exit 0 is only a scoped metadata result—not proof of runtime safety.

Please do not send us the manifest, configuration, prompts, traces, or JSON report. If you are willing, reply with only:

1. the compact result with sensitive tool names redacted;
2. whether installation worked in your environment;
3. whether the decision looked correct;
4. what action you took after the result; and
5. what runtime evidence you would still need.

Source and documentation: https://github.com/BackBond/agent-scan

## Five feedback questions

1. Did the exact pinned command install and start? If not, report the error category, operating system, shell, and Node version without local paths.
2. Was the result block, review, or no blocking finding? Do not share the raw manifest.
3. Did the result change whether you attached, disabled, wrapped, or isolated a tool?
4. Which finding was useful or which inference felt wrong?
5. What would you need to observe at runtime before a human or risk owner trusted this agent?

## Internal qualification notes

Record only:

- organization and contact;
- environment category;
- successful start: yes/no;
- decision category: block/review/no-blocking-finding;
- action influenced: yes/no and a short summary;
- runtime-evidence need;
- follow-up requested: scanner feedback/listener/coverage/none.

Do not copy raw scan evidence into CRM notes. If the contact needs help reproducing a problem, direct them to the privacy-safe source-repository issue template.

## Follow-up after a useful result

Thank you. The compact result is enough; please keep the underlying tool list private.

If the static finding changed the attachment decision, we would like to understand the runtime question it left unanswered. BackBond's broader work covers deeper assessment, continuous runtime evidence from the listener, and, where approved, financial protection. The local scan itself does not verify the environment or create coverage.
