# Two-week launch calendar

Dates are relative to the day the `/agent-scan/` landing page is live and verified. Leave one open slot each week for a real finding, question, or installation lesson from the controlled cohort.

| Day | Content | Channel | Audience | Owner | Success signal |
| --- | --- | --- | --- | --- | --- |
| -2 | Verify landing page, pinned commands, release links, CSP, `llms.txt`, and `/.well-known/agent.json` | Website | All | Engineering | Mobile/desktop QA passes; no broken internal or release links |
| -1 | Send controlled invitation to first five partners | Direct email/DM | Builders, security | Founder | Three acknowledge; two complete a run |
| 0 | Publish canonical announcement and terminal demo | Website, LinkedIn, X/Bluesky | Builders | Founder/marketing | Command-copy visits and qualified replies |
| 1 | Post the tri-state decision model: 1 block, 3 review, 0 scoped result | GitHub, social | Builders, security | Product | Users describe 3 as stop-unknown rather than failure |
| 3 | Demonstrate forced invocation and confusable-name review with sanitized manifests | Community, social | MCP maintainers | Engineering | Reproductions match documented outcomes |
| 4 | Send second five-partner cohort | Direct email/DM | Builders, security | Founder | Five cumulative completed runs |
| 5 | Explain the offline single-file path and why a failed install means no scan ran | Blog/community | Hardened environments | Engineering | Fewer registry-workaround requests |
| 7 | Share the GitHub Action and commit-bound record boundary | GitHub, LinkedIn | Platform/security | Engineering | First external CI integration |
| 9 | Publish one anonymized lesson from feedback; no raw manifest | Website/social | All | Product | Useful discussion rather than download-only reactions |
| 10 | Publish “what the static scanner cannot see” | LinkedIn/blog | Security, risk | Founder | Runtime-evidence conversations |
| 12 | Send final five-partner cohort | Direct email/DM | Risk, platform | Founder | Ten cumulative completed runs |
| 14 | Report launch facts: confirmed runs, decisions influenced, installation failures, CI adoptions | Website/GitHub | All | Product | Decision on docs fix, false-positive fix, or hold at 0.5.8 |

## Review cadence

Every 48 hours during the launch:

1. Triage installation failures before content requests.
2. Triage a false `no_blocking_finding` before adding new distribution channels.
3. Correct false-positive documentation or inference only with a minimized public-safe reproducer.
4. Keep 0.5.8 pinned unless a real correctness or delivery defect requires a new release.
5. Do not add CLI telemetry to improve campaign measurement.

## 30-day scorecard

| Metric | Target | Evidence |
| --- | ---: | --- |
| Confirmed scanner starts | 25 | Partner replies or privacy-safe issues |
| Confirmed pre-attachment uses | 10 | Partner says it was run before attachment |
| Decisions influenced | 8 | Attach/disable/wrap/isolate action reported |
| CI integrations | 5 | Public repository or partner confirmation |
| Privacy-safe feedback reports | 10 | GitHub issues or structured notes |
| Runtime-evidence/listener conversations | 3 | Qualified meeting or written requirement |

npm downloads, GitHub stars, registry views, and social reach should be recorded as context only. None of them proves scanner activation.
