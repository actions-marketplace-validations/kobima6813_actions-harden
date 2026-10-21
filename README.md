# actions-harden

[![ci](https://github.com/kobima6813/actions-harden/actions/workflows/ci.yml/badge.svg)](https://github.com/kobima6813/actions-harden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Find the four most common GitHub Actions security mistakes in seconds — and pin your actions to commit SHAs with one flag.**

Zero dependencies (Python 3.9+ standard library only). Runs as a CLI or as a composite GitHub Action.

> If this saves you a review cycle, please ⭐ **star the repo** — it helps other teams find it.

## What it checks

| Rule | Severity | Why it matters |
|---|---|---|
| `unpinned-action` | medium (low for `actions/*`, `github/*`) | Tags like `@v4` or `@main` can be moved. A compromised tag runs in your CI (see the `tj-actions/changed-files` incident). |
| `missing-permissions` | medium | Without `permissions:` the `GITHUB_TOKEN` gets the repository default, which may be write access to everything. |
| `permissions-write-all` | high | `write-all` hands every scope to every step. |
| `pull-request-target` | medium | Runs with secrets on PRs from forks. |
| `pull-request-target-checkout` | high | ...and checks out the untrusted PR code — the classic "pwn request". |
| `script-injection` | high | `${{ github.event.issue.title }}` (and friends) expanded inside `run:` lets anyone who can open an issue/PR run shell commands. |

## Use as a GitHub Action

```yaml
name: actions-harden
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kobima6813/actions-harden@main
        with:
          fail-on: high   # none | low | medium | high
```

Findings are printed to the log and to the job summary.

## Use as a CLI

```bash
git clone https://github.com/kobima6813/actions-harden
python3 -m actions_harden /path/to/your/repo            # text report
python3 -m actions_harden /path/to/your/repo --json     # machine-readable
python3 -m actions_harden . --fail-on none              # report only, always exit 0
```

(Run from the cloned directory, or set `PYTHONPATH` to it.)

### `--fix`: pin to commit SHAs

```bash
GITHUB_TOKEN=... python3 -m actions_harden . --fix
```

Rewrites `uses: actions/checkout@v4` to `uses: actions/checkout@<40-char sha> # v4` using the GitHub API (a token is optional but avoids rate limits). Review the diff before committing. Only `uses:` lines are changed.

## Limits

This is a fast line-based static check, not a full YAML/expression evaluator. It may miss exotic layouts and it never contacts your systems. For a human review with a pass/fail report, see the [GitHub Actions security review](https://kobima6813.github.io/ci-earlywarn/review.html).

## Related

- [CI Early-Warn](https://github.com/kobima6813/ci-earlywarn) — know about runner/toolchain breakages before they hit your builds.
- [Free CI cost check](https://kobima6813.github.io/ci-earlywarn/cost.html)

## License

MIT
