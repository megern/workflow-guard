# Limits and false positives

This is a small static review aid. It is not a complete GitHub workflow validator,
taint analyzer, or replacement for code review and platform controls. A clean
report means none of these six patterns were found.

## How to interpret findings

- **WG001:** A write-all declaration is reported even when child jobs narrow their
  permissions. The declaration should still be reviewed in its own scope.
- **WG002:** Repository/organization defaults may already be read-only. The
  finding describes reliance on unknown defaults, not proven write access.
  Explicit permissions at either the job or workflow level prevent this finding.
- **WG003:** The scanner recognizes head expressions in checkout `ref` and
  `repository`. It does not resolve environment variables, artifacts, wrapper
  actions, approval policies, or `if` conditions. Checkout is not proof that the
  downloaded code will execute. `workflow_run` risks are outside this version.
- **WG004:** Some event fields or expressions may be constant or sanitized, so
  the rule can over-report. Passing an expression through `env` avoids this rule,
  but unsafe uses of that variable such as `eval` are not analyzed.
- **WG005:** Tags are common, intentional dependencies and can be false positives
  under an accepted policy. A 40-character SHA/digest is checked syntactically
  only. It is not verified to exist, belong to the intended repository, or be free
  of vulnerabilities. Local actions are not inspected.
- **WG006:** Echo recognition is a conservative pattern check, not a shell
  parser. Redirected output or intentional masked output may be harmless. It does
  not follow secrets through environment variables or detect other logging
  commands such as `printf`, external tools, PowerShell commands, or dynamic code.

Review the cited code and relevant platform settings before acting. Findings may
need additional protections beyond the short recommendation in the report.

## Parser and report behavior

- The `WorkflowLoader` derives from `yaml.SafeLoader` and treats unquoted `on`,
  `off`, `yes`, and `no` as strings while retaining true/false booleans. It does not
  modify PyYAML's global resolver configuration. The scanner reads the YAML node
  graph rather than constructing arbitrary tagged Python objects.
- Duplicate keys, merge keys (`<<`), complex mapping keys, custom tags, malformed
  YAML, missing/empty jobs, files over 1 MiB, and unreadable input are report
  errors. The scanner intentionally requires ambiguous mappings to be expanded.
- Ordinary YAML aliases are supported. Their locations point to the anchor
  definition. Repeated aliases are traversed without recursive graph expansion.
- For block/folded/quoted text, expressions normally map back to their exact
  source location. If YAML escapes hide the literal expression, the location
  points to the scalar field instead.
- Findings disclose expression **names**, not resolved secret values. Workflows
  are never evaluated. Reports still include local paths and source references;
  inspect reports before publishing private repository information.

## Further reading

GitHub documents [script injection](https://docs.github.com/en/actions/concepts/security/script-injections),
[secure workflow practices](https://docs.github.com/en/actions/reference/security/secure-use),
and [permissions semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).
