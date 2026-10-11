# Workflow Guard

## Adopt a reviewed baseline without hiding risks (local development)

Use `--baseline /absolute/local/reviewed-report.json --root /absolute/repository`
to apply the severity exit gate only to unmatched findings. **All findings remain
in text, JSON and SARIF output**; scan errors still exit 2. The baseline must be
a version 1 Workflow Guard JSON report without scan errors and must refer to
workflows inside the same root. JSON output cannot overwrite the baseline.

Identity includes repository-relative path, rule, severity, job, message and
evidence. Line moves alone do not create a new risk. Changed evidence/severity
and additional identical instances remain unmatched through multiset counting.
Review the baseline as explicit exceptions; it does not certify existing risks
as safe. JSON and SARIF record its exact hash and the unmatched finding indices.

## Public preview v0.2.0

Python 3.11+; commands below use a local Mac/Linux shell. Source and reports are public; this is a research/development preview, not a production-security certification.

```sh
git clone --branch v0.2.0 https://github.com/megern/workflow-guard.git
cd workflow-guard
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
workflow-guard --help
```

The installed entry point was exercised outside the checkout in a separate local environment. This revision has 20 passing local tests. No hosted CI or cloud compute is used. Report an issue with the command, Python/OS versions, sanitized input and expected/actual behavior; remove credentials and private records first. Benchmarks describe the supplied fixtures and hardware.

Inspect GitHub Actions workflow YAML locally and get a security review report with
file, line, column, rule, evidence, and a suggested change. The scanner uses
deterministic rules and PyYAML; it does not execute workflows, call an AI service,
download actions, or require account credentials.

## Quick start

Python 3.10 or newer:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
workflow-guard .github/workflows --json-output reports/workflows.json
```

Try the deliberately risky fixture without running its workflow:

```sh
workflow-guard examples/workflows/risky.yml --fail-on none
workflow-guard examples/workflows/safe.yml --format json
```

On Windows, activate `.venv\Scripts\activate` instead. `python -m workflow_guard`
is equivalent to the installed `workflow-guard` command.

## Checks

| Rule | Severity | Review trigger |
|---|---|---|
| WG001 | High | Workflow or job declares `permissions: write-all`. |
| WG002 | Medium | A job has neither job-level nor inherited workflow-level permissions. |
| WG003 | High | `pull_request_target` plus checkout of a pull-request head expression. |
| WG004 | High | A `github.event.*` or `github.head_ref` expression is embedded directly in `run`. |
| WG005 | Medium | A remote action/reusable workflow lacks a full commit SHA, or a container lacks a digest. |
| WG006 | High | A recognizable `echo` command directly references a secret expression. |

Explicit workflow permissions cover jobs that inherit them; explicit job
permissions cover that job. Local `./` dependencies are excluded from WG005.
Every finding includes a source location. Repeated expressions receive separate
locations; YAML aliases point to the original anchor definition.

## Reports and automation

`--format json` writes structured JSON to stdout; `--json-output FILE` also saves
it to a file. The CLI refuses to overwrite an input workflow with a report.
Directories are searched recursively for `.yml` and `.yaml` files; pass the
workflow directory rather than an entire repository containing unrelated YAML.

Exit codes: **0** means no findings meet the selected threshold, **1** means at
least one does, and **2** means an input/report error occurred. The default
threshold is `--fail-on high`; use `medium` for a stricter gate or `none` for
report-only operation. Input errors still return 2 with `none`.

[Example text report](docs/sample-report.txt) ·
[Example JSON report](docs/sample-report.json) ·
[Limits and false positives](docs/limitations.md)

## Tests

```sh
python -m unittest discover -s tests -v
```

The synthetic fixtures test covered risk patterns, source locations, false
positives, parser behavior, and exit codes. They are not a real-world accuracy
benchmark. `safe.yml` contains a **synthetic SHA** for pin-format testing; neither
fixture is an executable CI template. Keep them outside `.github/workflows`.

## العربية

أداة محلية لمراجعة ملفات GitHub Actions وإظهار أنماط تحتاج مراجعة أمنية، مع رقم
السطر والقاعدة والدليل والإصلاح المقترح. لا تنفذ الأداة ملفات workflows ولا تحتاج
إلى نموذج ذكاء اصطناعي أو اتصال بحساب GitHub.

ابدأ بالأمر `workflow-guard .github/workflows`، أو افحص الأمثلة بالأوامر أعلاه.
النتائج مؤشرات للمراجعة وليست إثباتًا لوجود ثغرة قابلة للاستغلال. ملفات الأمثلة
اصطناعية للتقييم فقط، ولا ينبغي تشغيلها كعمليات CI.

## Rule references

The checks draw on GitHub's [secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
and [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
See the limitations before using findings to block a merge. Licensed under MIT.

## Literal bracket contexts

WG003 and WG004 recognize literal bracket access such as `github['event']['issue']['title']` and mixed bracket/dot properties. Reports retain the original expression and source location. This follows [GitHub's documented context syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions). Dynamic property names, expression evaluation and full data-flow analysis remain outside the scanner's scope. Environment-variable references alone are not treated as direct script interpolation.

Run `PYTHONPATH=src python3 -m unittest discover -s tests` to check both supported forms and the env-only negative case.


### Local SARIF export

```sh
workflow-guard examples --format sarif --root . --fail-on none > /tmp/workflow-results.sarif
```

The export uses SARIF 2.1.0, repository-relative escaped paths, source locations and parse-error notifications. Its output was validated locally against the [OASIS SARIF schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json); [GitHub documents its supported subset](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support). No upload, hosted CI job or workflow execution is performed. Shell redirection should use a separate report path, as shown, to preserve inputs.
