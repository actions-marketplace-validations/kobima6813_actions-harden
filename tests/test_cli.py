import json, os, subprocess, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from actions_harden.cli import scan_text, fix_text, main

FIX = Path(__file__).parent / "fixtures"


def rules(f):
    return sorted({x["rule"] for x in f})


class T(unittest.TestCase):
    def test_bad(self):
        f = scan_text((FIX / "bad.yml").read_text())
        self.assertEqual(rules(f), ["missing-permissions", "permissions-write-all", "pull-request-target-checkout",
                                    "script-injection", "unpinned-action"])
        self.assertEqual(sum(x["rule"] == "script-injection" for x in f), 2)
        un = [x for x in f if x["rule"] == "unpinned-action"]
        self.assertEqual({x["severity"] for x in un}, {"low", "medium"})
        self.assertIn("build", [x for x in f if x["rule"] == "missing-permissions"][0]["message"])

    def test_good(self):
        self.assertEqual(scan_text((FIX / "good.yml").read_text()), [])

    def test_prt_without_checkout_is_medium(self):
        f = scan_text("on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ok\n")
        self.assertEqual([(x["rule"], x["severity"]) for x in f], [("pull-request-target", "medium")])

    def test_job_level_permissions_ok(self):
        f = scan_text("on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: x\n    steps:\n      - run: echo\n")
        self.assertEqual(f, [])

    def test_fix(self):
        src = "    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n      - uses: a/b@" + "a" * 40 + "\n"
        out, n = fix_text(src, lambda name, ref: "f" * 40)
        self.assertEqual(n, 1)
        self.assertIn("actions/checkout@" + "f" * 40 + " # v4", out)
        self.assertIn("uses: ./x", out)

    def test_fix_resolver_failure_keeps_line(self):
        def boom(*a): raise RuntimeError("x")
        out, n = fix_text("- uses: a/b@v1\n", boom)
        self.assertEqual((out, n), ("- uses: a/b@v1\n", 0))

    def test_exit_codes(self):
        bad = str(FIX / "bad.yml")
        self.assertEqual(main([bad, "--json"]), 1)
        self.assertEqual(main([bad, "--fail-on", "none"]), 0)
        self.assertEqual(main([str(FIX / "good.yml")]), 0)

    def test_module_json(self):
        r = subprocess.run([sys.executable, "-m", "actions_harden", str(FIX / "bad.yml"), "--json", "--fail-on", "none"],
                           capture_output=True, text=True, cwd=Path(__file__).parents[1])
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(r.stdout)["files"], 1)


if __name__ == "__main__":
    unittest.main()
