"""actions-harden: static checks for GitHub Actions workflow files (stdlib only)."""
import argparse, json, os, re, sys, urllib.request, urllib.error
from pathlib import Path

SEV = {"low": 1, "medium": 2, "high": 3}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^(\s*-?\s*uses:\s*)([\"']?)([^\s\"'#]+)\2(\s*#.*)?\s*$")
DANGEROUS = re.compile(
    r"\$\{\{\s*(github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)"
    r"|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^}]*page_name"
    r"|commits\.[^}]*(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))"
    r"|workflow_run\.(?:head_branch|head_commit\.message|display_title)|inputs\.[A-Za-z0-9_-]+|client_payload\.[^}]*)"
    r"|github\.head_ref|inputs\.[A-Za-z0-9_-]+)\s*\}\}")


def finding(path, line, rule, sev, msg):
    return {"file": str(path), "line": line, "rule": rule, "severity": sev, "message": msg}


def _indent(s):
    return len(s) - len(s.lstrip(" "))


def scan_text(text, path="<workflow>"):
    lines = text.splitlines()
    out = []
    top_perm = None
    triggers_prt = False
    checkout_head = False
    in_on = False
    in_run = False
    run_indent = 0
    jobs_without_perm = []
    in_jobs = False
    cur_job = None
    cur_job_has_perm = False
    job_indent = None

    def close_job():
        if cur_job and not cur_job_has_perm:
            jobs_without_perm.append(cur_job)

    for i, raw in enumerate(lines, 1):
        s = raw.rstrip()
        stripped = s.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ind = _indent(s)
        # leave multi-line run block
        if in_run and ind <= run_indent:
            in_run = False
        if ind == 0:
            in_on = False
            if stripped.startswith(("on:", '"on":', "'on':", "true:")):
                in_on = True
                if "pull_request_target" in stripped:
                    triggers_prt = True
            elif stripped.startswith("permissions:"):
                top_perm = stripped.split(":", 1)[1].strip() or "{block}"
                if top_perm == "write-all":
                    out.append(finding(path, i, "permissions-write-all", "high",
                                       "Top-level 'permissions: write-all' grants every scope to GITHUB_TOKEN."))
            if stripped.startswith("jobs:"):
                in_jobs = True
            else:
                if in_jobs:
                    close_job(); cur_job = None
                in_jobs = False
            continue
        if in_on and re.search(r"\bpull_request_target\b", stripped):
            triggers_prt = True
        if in_jobs:
            if job_indent is None:
                job_indent = ind
            if ind == job_indent and stripped.endswith(":"):
                close_job()
                cur_job, cur_job_has_perm = stripped[:-1].strip("'\""), False
            elif cur_job and ind == job_indent + 2 and stripped.startswith("permissions:"):
                cur_job_has_perm = True
                if stripped.split(":", 1)[1].strip() == "write-all":
                    out.append(finding(path, i, "permissions-write-all", "high",
                                       f"Job '{cur_job}' uses 'permissions: write-all'."))
        m = USES_RE.match(s)
        if m:
            ref = m.group(3)
            if not ref.startswith("./") and not ref.startswith("docker://"):
                if "@" not in ref:
                    out.append(finding(path, i, "unpinned-action", "medium", f"'{ref}' has no version ref."))
                else:
                    name, ver = ref.rsplit("@", 1)
                    if not SHA_RE.match(ver):
                        sev = "low" if name.startswith(("actions/", "github/")) else "medium"
                        out.append(finding(path, i, "unpinned-action", sev,
                                           f"'{ref}' is pinned to a mutable tag/branch, not a commit SHA."))
        if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", stripped) and re.search(r"\bref:", stripped):
            checkout_head = True
        rm = re.match(r"^\s*-?\s*run:\s*(.*)$", s)
        if rm:
            body = rm.group(1)
            if body.startswith(("|", ">")):
                in_run, run_indent = True, ind
            elif DANGEROUS.search(body):
                out.append(finding(path, i, "script-injection", "high",
                                   f"Untrusted '{DANGEROUS.search(body).group(1)}' expanded directly in a run: step. Pass it via env: instead."))
            continue
        if in_run:
            d = DANGEROUS.search(stripped)
            if d:
                out.append(finding(path, i, "script-injection", "high",
                                   f"Untrusted '{d.group(1)}' expanded directly in a run: script. Pass it via env: instead."))
    if in_jobs:
        close_job()
    if top_perm is None and jobs_without_perm:
        out.append(finding(path, 1, "missing-permissions", "medium",
                           "No top-level 'permissions:' and job(s) " + ", ".join(jobs_without_perm) +
                           " set none; GITHUB_TOKEN gets the repo default (possibly write). Add 'permissions: contents: read'."))
    if triggers_prt:
        if checkout_head:
            out.append(finding(path, 1, "pull-request-target-checkout", "high",
                               "pull_request_target checks out untrusted PR head code with a privileged token."))
        else:
            out.append(finding(path, 1, "pull-request-target", "medium",
                               "pull_request_target runs with secrets on fork PRs; make sure no PR code is executed."))
    out += scan_secrets(text, path)
    return out


SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
LOG_CMD = re.compile(r"(?:^|[;&|(\s])(?:echo|printf|print|puts|console\.log|Write-Host|Write-Output)\b")
PIPED = re.compile(r"^[^;&|]*\|(?!\|)")
REDIRECT = re.compile(r">>?\s*(?:\"?\$\{?GITHUB_\w+|[^\s&|]+)")
CLOUD_KEY = [
    (re.compile(r"^\s*-?\s*aws-(?:access-key-id|secret-access-key):\s*\$\{\{\s*secrets\."), "AWS",
     "aws-actions/configure-aws-credentials with 'role-to-assume' + 'permissions: id-token: write'"),
    (re.compile(r"^\s*-?\s*(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY):\s*\$\{\{\s*secrets\."), "AWS",
     "aws-actions/configure-aws-credentials with 'role-to-assume' (OIDC)"),
    (re.compile(r"^\s*-?\s*credentials_json:\s*\$\{\{\s*secrets\."), "GCP",
     "google-github-actions/auth with 'workload_identity_provider' (Workload Identity Federation)"),
    (re.compile(r"^\s*-?\s*(?:GOOGLE_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS_JSON|GCP_SA_KEY):\s*\$\{\{\s*secrets\."), "GCP",
     "google-github-actions/auth with 'workload_identity_provider'"),
    (re.compile(r"^\s*-?\s*creds:\s*\$\{\{\s*secrets\."), "Azure",
     "azure/login with 'client-id', 'tenant-id', 'subscription-id' (federated credentials)"),
]


def scan_secrets(text, path="<workflow>"):
    """Secret-handling checks: secrets echoed to logs, long-lived cloud keys, workflow-wide secret env."""
    out = []
    in_run = False
    run_indent = 0
    in_top_env = False
    for i, raw in enumerate(text.splitlines(), 1):
        s = raw.rstrip()
        stripped = s.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ind = _indent(s)
        if in_run and ind <= run_indent:
            in_run = False
        if ind == 0:
            in_top_env = stripped.startswith("env:")
            continue
        if in_top_env:
            m = SECRET_EXPR.search(stripped)
            if m:
                sev = "low" if m.group(1) == "GITHUB_TOKEN" else "medium"
                out.append(finding(path, i, "workflow-env-secret", sev,
                                   f"secrets.{m.group(1)} is set in workflow-level env:, exposing it to every step of every job "
                                   "(including third-party actions). Scope it to the step that needs it."))
        for rx, cloud, alt in CLOUD_KEY:
            if rx.search(s):
                out.append(finding(path, i, "long-lived-cloud-key", "medium",
                                   f"Long-lived {cloud} key from secrets. Prefer short-lived OIDC credentials: {alt}."))
                break
        body = None
        rm = re.match(r"^\s*-?\s*run:\s*(.*)$", s)
        if rm:
            if rm.group(1).startswith(("|", ">")):
                in_run, run_indent = True, ind
                continue
            body = rm.group(1)
        elif in_run:
            body = stripped
        if body and LOG_CMD.search(body):
            m = SECRET_EXPR.search(body)
            if m and not REDIRECT.search(body[m.end():]) and not PIPED.search(body[m.end():]):
                out.append(finding(path, i, "secret-in-log", "high",
                                   f"secrets.{m.group(1)} is printed in a run: step. Masking is best-effort (encoded/split "
                                   "values leak); never echo secrets."))
    return out


def workflow_files(root):
    p = Path(root)
    if p.is_file():
        return [p]
    wf = p / ".github" / "workflows"
    base = wf if wf.is_dir() else p
    return sorted([*base.rglob("*.yml"), *base.rglob("*.yaml")])


def resolve_sha(name, ref, token=None, api="https://api.github.com"):
    owner_repo = "/".join(name.split("/")[:2])
    req = urllib.request.Request(f"{api}/repos/{owner_repo}/commits/{ref}",
                                 headers={"Accept": "application/vnd.github.sha", "User-Agent": "actions-harden"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=20) as r:
        sha = r.read().decode().strip()
    if not SHA_RE.match(sha):
        raise ValueError(f"unexpected response for {name}@{ref}")
    return sha


def fix_text(text, resolver):
    changed = 0
    new = []
    for line in text.splitlines(keepends=True):
        m = USES_RE.match(line.rstrip("\n"))
        if m and "@" in m.group(3) and not m.group(3).startswith(("./", "docker://")):
            name, ver = m.group(3).rsplit("@", 1)
            if not SHA_RE.match(ver):
                try:
                    sha = resolver(name, ver)
                except Exception as e:  # keep going, report
                    print(f"warn: could not resolve {name}@{ver}: {e}", file=sys.stderr)
                else:
                    nl = "\n" if line.endswith("\n") else ""
                    line = f"{m.group(1)}{name}@{sha} # {ver}{nl}"
                    changed += 1
        new.append(line)
    return "".join(new), changed


def main(argv=None):
    ap = argparse.ArgumentParser(prog="actions-harden", description="Scan GitHub Actions workflows for common security issues.")
    ap.add_argument("path", nargs="?", default=".", help="repo root, workflows dir, or a single workflow file")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--fail-on", choices=["none", "low", "medium", "high"], default="high",
                    help="exit 1 if a finding at or above this severity exists (default: high)")
    ap.add_argument("--fix", action="store_true", help="pin actions to commit SHAs via the GitHub API (edits files)")
    a = ap.parse_args(argv)
    files = workflow_files(a.path)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if a.fix:
        for f in files:
            t = f.read_text()
            nt, n = fix_text(t, lambda nm, v: resolve_sha(nm, v, token))
            if n:
                f.write_text(nt)
                print(f"pinned {n} action(s) in {f}", file=sys.stderr)
    results = []
    for f in files:
        results += scan_text(f.read_text(), f)
    if a.json:
        print(json.dumps({"files": len(files), "findings": results}, indent=2))
    else:
        for r in results:
            print(f"{r['file']}:{r['line']}: [{r['severity'].upper()}] {r['rule']}: {r['message']}")
        c = {k: sum(r["severity"] == k for r in results) for k in SEV}
        print(f"\nScanned {len(files)} workflow file(s): {c['high']} high, {c['medium']} medium, {c['low']} low.")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as s:
                s.write(f"### actions-harden\n{len(files)} files: {c['high']} high, {c['medium']} medium, {c['low']} low\n\n")
                for r in results:
                    s.write(f"- **{r['severity']}** `{r['file']}:{r['line']}` {r['rule']}: {r['message']}\n")
    if a.fail_on != "none" and any(SEV[r["severity"]] >= SEV[a.fail_on] for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
