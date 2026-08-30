# BackBond Schema Check status badge

Install [`schema-check-workflow.yml`](schema-check-workflow.yml) as `.github/workflows/backbond-schema.yml`, adjust `tool-schema` to the committed manifest path, and require the workflow before merging manifest changes.

```markdown
[![BackBond Schema Check](https://github.com/OWNER/REPOSITORY/actions/workflows/backbond-schema.yml/badge.svg?branch=main)](https://github.com/OWNER/REPOSITORY/actions/workflows/backbond-schema.yml)
```

The badge is dynamic workflow status, not a permanently green image. It must link to the workflow evidence rather than a marketing page.

Use **BackBond Schema Check**, never verification or certification language. A passing workflow means only that the committed file at this SHA produced `no_blocking_finding` under the pinned static pre-attachment profile. It is not production state, runtime verification, insurance coverage, or proof that the deployed server matches the manifest.

If screenshots or downstream copy repeatedly describe this badge as verified, certified, or production-safe, remove the badge rather than weakening this boundary.

Running this check does not create coverage or determine eligibility. Need deeper assessment, continuous runtime evidence, or information about financial protection where approved? Contact `hello@backbond.ai`.
