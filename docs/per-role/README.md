# Per-role setup one-pagers

One markdown file per server role. Each is operator-facing: install steps,
agent config snippet, the events the agent will collect, the rule IDs they
fire, expected first-alert latency, and a troubleshooting checklist if no
alerts appear after 15 minutes.

Each one-pager is kept in sync with the matching fixture in
`WatchTower/internal/engine/per_role_test.go`. If a rule ID is removed or
renumbered, the test fails loudly — fix the doc at the same time.

| Role | File | Test | Required OS |
|---|---|---|---|
| Active Directory (DC) | [active-directory.md](active-directory.md) | `TestRolePipeline_ActiveDirectory` | Windows Server |
| IIS | [iis.md](iis.md) | `TestRolePipeline_IIS` | Windows Server |
| MSSQL | [mssql.md](mssql.md) | `TestRolePipeline_MSSQL` | Windows Server or Linux |
| Apache | [apache.md](apache.md) | `TestRolePipeline_Apache` | Linux |
| Postfix | [postfix.md](postfix.md) | `TestRolePipeline_Postfix` | Linux |
| sshd | [sshd.md](sshd.md) | `TestRolePipeline_SSHD` | Linux |
