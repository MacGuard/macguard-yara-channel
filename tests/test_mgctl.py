"""Tests for mgctl. Standard library only. In-process tests call mgctl.cli.main; process tests run the real launcher (bin/mgctl) so shells,
pipes, exit codes and the absence of a terminal are exercised for real. Delegation is tested against a FAKE engine written in each test
directory (clearly a test double); the optional real-engine tests run only when MGCTL_AUDIT_BIN points to a built macguard-audit."""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from mgctl import CONTRACT, VERSION, backends, cli, commands, core  # noqa: E402
from mgctl.help import render  # noqa: E402
from mgctl.services import auditfile, hashing  # noqa: E402
from mgctl.tree import BY_PATH, COMMANDS  # noqa: E402

LAUNCHER = os.path.join(ROOT, "bin", "mgctl")
ANSI = re.compile(r"\x1b\[")
FAKE_ENGINE = r'''#!/usr/bin/env python3
import hashlib, json, os, sys, time
a = sys.argv[1:]
if os.environ.get("FAKE_SLEEP"): time.sleep(float(os.environ["FAKE_SLEEP"]))
if a[:1] == ["version"]: print("macguard-audit 0.0-test"); sys.exit(0)
if a[:1] == ["engine-status"]:
    ready = not os.environ.get("FAKE_ENGINE_NOT_READY")
    print(json.dumps({"schemaVersion": 1, "ready": ready, "version": "4.5.8", "architectures": "arm64 x86_64", "detail": "ok" if ready else "no engine"})); sys.exit(0 if ready else 4)
if a[:1] == ["scan"]:
    p = a[1]
    sha = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else ""
    f = [{"title": "SHA-256", "detail": "", "state": "unknown", "weight": 1}, {"title": "Signature", "detail": "", "state": "failed" if os.environ.get("FAKE_FAIL") else "passed", "weight": 1},
         {"title": "YARA rules", "detail": "", "state": "passed", "weight": 1}]
    doc = {"schemaVersion": 1, "tool": "macguard-audit", "version": "0.0-test", "results": [{"schemaVersion": 1, "kind": "unknown", "sha256": os.environ.get("FAKE_SHA") or sha, "coverage": "test double", "file": p, "findings": f, "score": 5, "blockers": 0}]}
    print(json.dumps(doc) if "json" in a else "text report of " + p); sys.exit(2 if os.environ.get("FAKE_FAIL") else 0)
if a[:1] == ["rules-status"]: print(json.dumps({"schemaVersion": 1, "installedFiles": 3}) if "json" in a else "Installed rule files : 3"); sys.exit(0)
if a[:1] == ["verify-rules"]: print(json.dumps({"schemaVersion": 1, "ok": True, "files": 3})); sys.exit(0)
if a[:1] == ["update-rules"]: print(json.dumps({"schemaVersion": 1, "ok": True, "updated": False, "message": "up to date", "yes": "--yes" in a})); sys.exit(0)
if a[:1] == ["tui"]: print("TUI-RUNNING"); sys.exit(0)
sys.exit(3)
'''
STUB_VERIFIER = r'''#!/usr/bin/env python3
import json, os, sys
print(json.dumps({"schemaVersion": 1, "args": sys.argv[1:]}))
sys.exit(int(os.environ.get("STUB_EXIT", "0")))
'''


def slurp(path, mode="r"):
    with open(path, mode) as fh:
        return fh.read()


def write_exe(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)
    return path


def run_main(argv, env=None, macos=True):
    """Calls the CLI in-process. Returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}, clear=False), mock.patch.object(backends, "is_macos", return_value=macos):
        code = cli.main(argv, stdout=out, stderr=err, stdin=io.StringIO(""))
    return code, out.getvalue(), err.getvalue()


def run_proc(argv, env=None, **kw):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([sys.executable, LAUNCHER] + argv, capture_output=True, text=True, env=e, stdin=kw.pop("stdin", subprocess.DEVNULL), timeout=120, **kw)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="mgctl-test-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.engine = write_exe(os.path.join(self.d, "macguard-audit"), FAKE_ENGINE)
        self.env = {"MGCTL_AUDIT_BIN": self.engine, "MGCTL_LANG": "en"}

    def f(self, name="sample.bin", data=b"hello mgctl\n"):
        p = os.path.join(self.d, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p


# ---- 1, 2, 3, 4: the command tree, parsing, help, exit codes, JSON ---------------------------------------------
class TreeTests(unittest.TestCase):
    def test_contract_commands_exist_with_honest_status(self):
        want = {
            ("version",): "implemented", ("help",): "implemented", ("doctor",): "implemented", ("scan",): "implemented",
            ("inventory",): "planned", ("provenance",): "planned", ("audit", "file"): "experimental", ("audit", "system"): "planned",
            ("baseline", "create"): "planned", ("baseline", "verify"): "planned", ("baseline", "diff"): "planned",
            ("evidence", "verify"): "implemented", ("attest", "verify"): "planned",
            ("intelligence", "status"): "implemented", ("intelligence", "update"): "implemented", ("intelligence", "verify"): "implemented",
            ("report",): "planned", ("agent", "status"): "planned", ("cloud", "status"): "planned",
        }
        for path, status in want.items():
            self.assertEqual(BY_PATH[path].status, status, path)

    def test_every_handler_exists_and_planned_commands_have_no_engine(self):
        for c in COMMANDS:
            self.assertTrue(callable(getattr(commands, c.handler or "group", None)), c.path)
            if c.status == "planned" and len(c.path) > 1 or (c.status == "planned" and c.handler == "planned"):
                self.assertEqual(c.handler, "planned", c.path)

    def test_command_tree_matches_the_golden_snapshot(self):
        golden = os.path.join(ROOT, "tests", "fixtures", "mgctl", "command-tree.json")
        current = {" ".join(c.path): c.status for c in COMMANDS}
        with open(golden) as f:
            self.assertEqual(json.load(f), {"contract": CONTRACT, "commands": current}, "the contract changed: bump CONTRACT and update the snapshot on purpose")

    def test_help_exists_for_every_command_in_both_languages_without_escape_codes(self):
        for lang in ("en", "es"):
            self.assertIn("mgctl", render((), lang))
            for c in COMMANDS:
                text = render(c.path, lang)
                self.assertFalse(ANSI.search(text), c.path)
                self.assertIn("130", text)                       # exit codes are documented in every help page
                self.assertIn("docs/cli/mgctl.md", text)
        self.assertNotEqual(render(("audit", "file"), "en"), render(("audit", "file"), "es"))


class ParsingTests(Tmp):
    def test_global_options_work_before_and_after_the_command(self):
        a = run_main(["--json", "version"], self.env)
        b = run_main(["version", "--json"], self.env)
        self.assertEqual(a[0], 0)
        self.assertEqual(json.loads(a[1])["contract"], json.loads(b[1])["contract"])

    def test_unknown_command_and_subcommand_exit_3_with_a_suggestion(self):
        code, out, err = run_main(["audit", "fil"], self.env)
        self.assertEqual(code, 3)
        self.assertIn("file", err)
        self.assertEqual(run_main(["bogus"], self.env)[0], 3)
        self.assertEqual(run_main(["--nope"], self.env)[0], 3)

    def test_no_arguments_prints_help_and_exits_3(self):
        code, out, _ = run_main([], self.env)
        self.assertEqual(code, 3)
        self.assertIn("USAGE", out)

    def test_help_forms_all_work(self):
        for argv in (["--help"], ["help"], ["audit", "--help"], ["audit", "file", "--help"], ["help", "audit", "file"], ["-h"]):
            code, out, _ = run_main(argv, self.env)
            self.assertEqual(code, 0, argv)
            self.assertIn("mgctl", out)

    def test_version_flag(self):
        self.assertEqual(run_main(["--version"], self.env)[1].split()[0:2], ["mgctl", VERSION])

    def test_numeric_option_validation(self):
        for bad in (["--timeout", "0"], ["--timeout", "99999"], ["--timeout", "x"], ["--max-workers", "9"], ["--max-workers", "0"]):
            self.assertEqual(run_main(bad + ["version"], self.env)[0], 3, bad)
        self.assertEqual(run_main(["--timeout", "5", "--max-workers", "4", "version"], self.env)[0], 0)

    def test_language_selection_and_error_messages_in_spanish(self):
        code, _o, err = run_main(["--lang", "es", "audit", "file", os.path.join(self.d, "missing")], self.env)
        self.assertEqual(code, 3)
        self.assertIn("ruta no encontrada", err)
        code, _o, err = run_main(["--lang", "en", "audit", "file", os.path.join(self.d, "missing")], self.env)
        self.assertIn("path not found", err)
        self.assertEqual(run_main(["--lang", "fr", "version"], self.env)[0], 3)


class ExitCodeAndJsonTests(Tmp):
    def test_planned_commands_refuse_with_4_and_never_report_success(self):
        for path in [c.path for c in COMMANDS if c.handler == "planned"]:
            code, out, err = run_main(list(path) + ["--json"], self.env)
            doc = json.loads(out)
            self.assertEqual(code, 4, path)
            self.assertFalse(doc["ok"])
            self.assertEqual(doc["status"], "planned")
            code, out, err = run_main(list(path), self.env)
            self.assertEqual(code, 4)
            self.assertEqual(out, "")                     # nothing on stdout that could be mistaken for a result
            self.assertIn("planned", err)

    def test_json_output_is_one_valid_document_for_every_runnable_command(self):
        f = self.f()
        cases = [["version"], ["doctor"], ["alias", "status"], ["scan", f], ["audit", "file", f, "--checks", "hash"], ["intelligence", "status"],
                 ["intelligence", "verify"], ["intelligence", "update", "--yes"], ["inventory"]]
        for argv in cases:
            code, out, _e = run_main(["--json"] + argv, self.env)
            json.loads(out)                                # raises if it is not exactly one JSON document
            self.assertIn(code, (0, 2, 4), argv)

    def test_usage_errors_are_json_in_json_mode(self):
        code, out, _e = run_main(["--json", "audit", "file", os.path.join(self.d, "nope")], self.env)
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(out)["ok"])

    def test_engine_missing_or_wrong_os_exits_4(self):
        f = self.f()
        code, out, err = run_main(["scan", f], {"MGCTL_AUDIT_BIN": os.path.join(self.d, "absent")})
        self.assertEqual(code, 4)
        self.assertEqual(run_main(["scan", f], self.env, macos=False)[0], 4)
        self.assertEqual(run_main(["intelligence", "status"], self.env, macos=False)[0], 4)

    def test_scan_delegates_and_maps_the_engine_exit_code(self):
        f = self.f()
        code, out, _e = run_main(["scan", f, "--json"], self.env)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["tool"], "macguard-audit")
        self.assertEqual(run_main(["scan", f], dict(self.env, FAKE_FAIL="1"))[0], 2)

    def test_engine_timeout_is_a_clean_exit_4(self):
        f = self.f()
        code, _o, err = run_main(["--timeout", "1", "scan", f], dict(self.env, FAKE_SLEEP="5"))
        self.assertEqual(code, 4)
        self.assertIn("did not finish", err)

    def test_intelligence_update_consent_and_offline(self):
        self.assertEqual(run_main(["intelligence", "update"], self.env)[0], 3)                 # no --yes and not interactive
        self.assertEqual(run_main(["intelligence", "update", "--yes", "--offline"], self.env)[0], 4)
        code, out, _e = run_main(["--json", "intelligence", "update", "--yes"], self.env)
        self.assertEqual((code, json.loads(out)["yes"]), (0, True))


# ---- 5, 6: no terminal, shells --------------------------------------------------------------------------------
class NoTtyAndShellTests(Tmp):
    def test_tui_never_opens_without_a_terminal(self):
        r = run_proc(["audit", "--tui"], self.env)
        self.assertEqual(r.returncode, 4)
        self.assertNotIn("TUI-RUNNING", r.stdout)
        self.assertFalse(ANSI.search(r.stdout + r.stderr))

    def test_output_has_no_ansi_when_not_a_terminal(self):
        r = run_proc(["--help"], self.env)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(ANSI.search(r.stdout))

    @unittest.skipUnless(platform.system() == "Darwin", "the engine hand-off to a terminal is exercised on macOS (the only OS with the engine)")
    def test_tui_opens_in_a_real_pty_and_passes_its_exit_code(self):
        import pty
        pid, fd = pty.fork()
        if pid == 0:
            env = dict(os.environ, **self.env)
            os.execve(sys.executable, [sys.executable, LAUNCHER, "audit", "--tui"], env)
        data = b""
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
        _p, status = os.waitpid(pid, 0)
        self.assertIn(b"TUI-RUNNING", data)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def _shells(self):
        return [s for s in ("bash", "zsh", "fish") if shutil.which(s)]

    def test_works_under_bash_zsh_and_fish_when_installed(self):
        shells = self._shells()
        if not shells:
            self.skipTest("no shell found")
        for sh in shells:
            probe = f'{sys.executable} {LAUNCHER} version --json'
            r = subprocess.run([sh, "-c", probe], capture_output=True, text=True, env=dict(os.environ, **self.env), timeout=60)
            self.assertEqual(r.returncode, 0, sh)
            self.assertEqual(json.loads(r.stdout)["tool"], "mgctl", sh)
            status = "$status" if sh == "fish" else "$?"
            r = subprocess.run([sh, "-c", f"{sys.executable} {LAUNCHER} inventory 2>/dev/null; echo CODE={status}"], capture_output=True, text=True, env=dict(os.environ, **self.env), timeout=60)
            self.assertIn("CODE=4", r.stdout, sh)

    def test_which_shells_were_available(self):
        """Documents the environment honestly: a missing shell is reported, never counted as tested."""
        missing = [s for s in ("bash", "zsh", "fish") if not shutil.which(s)]
        sys.stderr.write(f"[mgctl tests] shells missing on this machine (not tested): {missing or 'none'}\n")

    def test_paths_with_shell_metacharacters_are_data(self):
        marker = os.path.join(self.d, "pwned")
        nasty = self.f("a;touch pwned;$(touch pwned)`touch pwned`'\" b.bin")
        r = run_proc(["audit", "file", nasty, "--checks", "hash", "--json"], self.env, cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(json.loads(r.stdout)["checks"][0]["sha256"], hashlib.sha256(b"hello mgctl\n").hexdigest())


# ---- audit file: contract, honesty, security ---------------------------------------------------------------------
class AuditFileTests(Tmp):
    def test_hash_only_is_complete_and_correct(self):
        data = os.urandom(3 * 1024 * 1024 + 17)
        f = self.f("big.bin", data)
        code, out, _e = run_main(["audit", "file", f, "--checks", "hash", "--json"], self.env)
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(doc["complete"])
        c = doc["checks"][0]
        self.assertEqual((c["sha256"], c["sha512"]), (hashlib.sha256(data).hexdigest(), hashlib.sha512(data).hexdigest()))

    def test_the_full_contract_reports_provenance_and_vulns_as_not_implemented_and_is_not_complete(self):
        f = self.f()
        out_dir = os.path.join(self.d, "out")
        code, out, _e = run_main(["audit", "file", f, "--checks", "hash,integrity,yara,provenance,vulns", "--format", "json", "--output", out_dir], self.env)
        doc = json.loads(out)
        by = {c["id"]: c for c in doc["checks"]}
        self.assertEqual(set(by), {"hash", "integrity", "yara", "provenance", "vulns"})
        self.assertEqual(by["provenance"]["status"], "not_implemented")
        self.assertEqual(by["vulns"]["status"], "not_implemented")
        self.assertEqual(by["hash"]["status"], "passed")
        self.assertEqual(by["integrity"]["status"], "passed")
        self.assertEqual(by["yara"]["engine"]["note"], "classic YARA, not YARA-X")
        self.assertFalse(doc["complete"])
        self.assertTrue(doc["partial"])
        self.assertEqual(code, 4)
        self.assertEqual(sorted(doc["missing"]), ["provenance", "vulns"])
        with open(os.path.join(out_dir, "report.json")) as fh:
            self.assertEqual(json.load(fh)["status"], "partial")
        self.assertEqual(stat.S_IMODE(os.stat(out_dir).st_mode), 0o700)

    def test_a_failed_check_exits_2(self):
        code, out, _e = run_main(["audit", "file", self.f(), "--checks", "hash,integrity", "--json"], dict(self.env, FAKE_FAIL="1"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["status"], "failed")

    def test_an_engine_that_is_not_ready_is_unavailable_never_clean(self):
        code, out, _e = run_main(["audit", "file", self.f(), "--checks", "yara", "--json"], dict(self.env, FAKE_ENGINE_NOT_READY="1"))
        doc = json.loads(out)
        self.assertEqual(doc["checks"][0]["status"], "unavailable")
        self.assertFalse(doc["complete"])
        self.assertEqual(code, 4)

    def test_without_the_engine_hash_still_works_and_the_rest_is_unavailable(self):
        code, out, _e = run_main(["audit", "file", self.f(), "--checks", "hash,integrity", "--json"], {"MGCTL_AUDIT_BIN": os.path.join(self.d, "absent")}, macos=False)
        by = {c["id"]: c["status"] for c in json.loads(out)["checks"]}
        self.assertEqual(by, {"hash": "passed", "integrity": "unavailable"})
        self.assertEqual(code, 4)

    def test_unknown_check_names_are_rejected(self):
        self.assertEqual(run_main(["audit", "file", self.f(), "--checks", "hash,bogus"], self.env)[0], 3)
        self.assertEqual(run_main(["audit", "file", self.f(), "--checks", ""], self.env)[0], 3)

    def test_a_file_that_changes_during_the_analysis_is_partial(self):
        f = self.f()
        real = hashing.digests

        def mutate(path, cancel=None):
            d = real(path, cancel)
            with open(path, "ab") as fh:
                fh.write(b"changed while analysed")
            return d
        with mock.patch.object(hashing, "digests", mutate):
            code, out, _e = run_main(["audit", "file", f, "--checks", "hash", "--json"], self.env)
        doc = json.loads(out)
        self.assertTrue(doc["changedDuringAnalysis"])
        self.assertFalse(doc["complete"])
        self.assertEqual(code, 4)

    def test_engine_and_local_sha256_disagreement_is_flagged(self):
        code, out, _e = run_main(["audit", "file", self.f(), "--checks", "hash,integrity", "--json"], dict(self.env, FAKE_SHA="0" * 64))
        doc = json.loads(out)
        self.assertTrue(doc["changedDuringAnalysis"])
        self.assertFalse(doc["complete"])

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read everything")
    def test_insufficient_permissions_give_a_partial_result_not_a_crash(self):
        f = self.f("secret.bin")
        os.chmod(f, 0)
        self.addCleanup(os.chmod, f, 0o600)
        code, out, _e = run_main(["audit", "file", f, "--checks", "hash", "--json"], self.env)
        self.assertEqual(json.loads(out)["checks"][0]["status"], "unavailable")
        self.assertEqual(code, 4)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can write everywhere")
    def test_unwritable_output_directory_is_a_usage_error(self):
        out = os.path.join(self.d, "ro")
        os.mkdir(out, 0o500)
        self.addCleanup(os.chmod, out, 0o700)
        self.assertEqual(run_main(["audit", "file", self.f(), "--checks", "hash", "--output", out], self.env)[0], 3)

    def test_reports_are_never_overwritten(self):
        f = self.f()
        out = os.path.join(self.d, "o")
        self.assertEqual(run_main(["audit", "file", f, "--checks", "hash", "--output", out], self.env)[0], 0)
        first = slurp(os.path.join(out, "report.json"))
        self.assertEqual(run_main(["audit", "file", f, "--checks", "hash", "--output", out], self.env)[0], 3)
        self.assertEqual(slurp(os.path.join(out, "report.json")), first)

    def test_cancellation_leaves_a_report_marked_cancelled_and_incomplete(self):
        f = self.f()
        out = os.path.join(self.d, "o")

        def slow(path, cancel=None):
            os.kill(os.getpid(), signal.SIGINT)       # a REAL SIGINT (the user presses Ctrl-C while the hash runs): it also wakes the main thread if it is blocked waiting
            for _ in range(200):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError("cancelled")
                threading.Event().wait(0.01)
            return {"sha256": "x", "sha512": "y"}
        with mock.patch.object(hashing, "digests", slow):
            code, _o, err = run_main(["audit", "file", f, "--checks", "hash", "--output", out], self.env)
        self.assertEqual(code, 130)
        rep = json.loads(slurp(os.path.join(out, "report.json")))
        self.assertEqual((rep["status"], rep["complete"]), ("cancelled", False))
        self.assertIn("nothing was reported as complete", err)

    def test_sigint_to_a_real_process_exits_130(self):
        big = self.f("huge.bin", b"")
        with open(big, "wb") as fh:
            fh.truncate(3 * 1024 * 1024 * 1024)       # sparse 3 GiB: long enough to interrupt, costs no disk
        p = subprocess.Popen([sys.executable, LAUNCHER, "audit", "file", big, "--checks", "hash", "--timeout", "600"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, env=dict(os.environ, **self.env), text=True)
        threading.Event().wait(1.0)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=60)
        self.assertIn(p.returncode, (130, 0))         # 0 only if the machine hashed 3 GiB within a second
        if p.returncode == 130:
            self.assertNotIn("complete=true", out)


class PathSecurityTests(Tmp):
    def test_rejects_nul_empty_missing_and_overlong_paths(self):
        for bad in ("", "   ", "a\x00b", "x" * 5000, os.path.join(self.d, "missing")):
            self.assertEqual(run_main(["audit", "file", bad], self.env)[0], 3, repr(bad[:20]))

    def test_symlinks_are_refused_unless_requested_and_both_paths_are_recorded(self):
        f = self.f()
        link = os.path.join(self.d, "link")
        os.symlink(f, link)
        self.assertEqual(run_main(["audit", "file", link, "--checks", "hash"], self.env)[0], 3)
        code, out, _e = run_main(["audit", "file", link, "--checks", "hash", "--follow-symlinks", "--json"], self.env)
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertTrue(doc["file"]["symlink"])
        self.assertEqual(os.path.realpath(doc["file"]["resolved"]), os.path.realpath(f))
        self.assertEqual(run_main(["scan", link], self.env)[0], 3)

    def test_dash_prefixed_names_cannot_become_engine_options(self):
        f = self.f("-rf")
        code, out, _e = run_main(["audit", "file", "--checks", "integrity", "--json", "--", f], self.env)
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["checks"][0]["status"] in ("passed", "unknown"))
        r = run_proc(["audit", "file", "--checks", "hash", "--json", "--", "-rf"], self.env, cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)      # after '--' the name is data; it is passed to engines as an absolute path
        self.assertEqual(os.path.realpath(json.loads(r.stdout)["file"]["resolved"]), os.path.realpath(f))
        for argv in (["scan", "-rf"], ["audit", "file", "-rf"]):
            self.assertEqual(run_proc(argv, self.env, cwd=self.d).returncode, 3)       # without '--' it is an unknown option

    def test_fifos_and_devices_are_not_regular_files(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        fifo = os.path.join(self.d, "fifo")
        os.mkfifo(fifo)
        self.assertEqual(run_main(["audit", "file", fifo, "--checks", "hash"], self.env)[0], 3)
        self.assertEqual(run_main(["audit", "file", "/dev/null", "--checks", "hash"], self.env)[0], 3)

    def test_output_directory_symlink_is_refused(self):
        real = os.path.join(self.d, "real")
        os.mkdir(real)
        link = os.path.join(self.d, "outlink")
        os.symlink(real, link)
        self.assertEqual(run_main(["audit", "file", self.f(), "--checks", "hash", "--output", link], self.env)[0], 3)

    def test_directories_get_no_digest(self):
        code, out, _e = run_main(["audit", "file", self.d, "--checks", "hash", "--json"], self.env)
        self.assertEqual(json.loads(out)["checks"][0]["status"], "not_applicable")


# ---- evidence verify ---------------------------------------------------------------------------------------------
class EvidenceVerifyTests(Tmp):
    def setUp(self):
        super().setUp()
        self.stub = write_exe(os.path.join(self.d, "stub_verifier.py"), STUB_VERIFIER)
        self.env["MGCTL_VERIFIER"] = self.stub

    def test_exit_codes_of_the_verifier_are_mapped_and_reported(self):
        mapping = {0: 0, 1: 2, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4}
        for vcode, want in mapping.items():
            code, out, _e = run_main(["--json", "evidence", "verify", "--tag", "rules-1"], dict(self.env, STUB_EXIT=str(vcode)))
            doc = json.loads(out)
            self.assertEqual((code, doc["verifierExitCode"], doc["ok"]), (want, vcode, vcode == 0))
            self.assertIn("--tag", doc["verifier"]["args"])
        self.assertIn("not who wrote", doc["note"])

    def test_exactly_one_source_and_offline_rules(self):
        self.assertEqual(run_main(["evidence", "verify"], self.env)[0], 3)
        self.assertEqual(run_main(["evidence", "verify", "--latest", "--tag", "x"], self.env)[0], 3)
        self.assertEqual(run_main(["evidence", "verify", "--latest", "--offline"], self.env)[0], 4)
        d = os.path.join(self.d, "rel")
        os.mkdir(d)
        self.assertEqual(run_main(["evidence", "verify", "--directory", d, "--offline"], self.env)[0], 0)

    def test_missing_verifier_is_unavailable(self):
        self.assertEqual(run_main(["evidence", "verify", "--latest"], {"MGCTL_VERIFIER": os.path.join(self.d, "none")})[0], 4)

    def test_the_real_verifier_is_reachable_from_a_checkout(self):
        real = os.path.join(ROOT, "scripts", "verify_public_release.py")
        if not os.path.isfile(real):
            self.skipTest("not a checkout")
        code, out, _e = run_main(["--json", "evidence", "verify", "--directory", os.path.join(self.d, "does-not-exist")], {"MGCTL_VERIFIER": real})
        self.assertEqual(code, 3)                       # the directory does not exist: rejected by mgctl before the verifier runs
        os.mkdir(os.path.join(self.d, "empty"))
        code, out, _e = run_main(["--json", "evidence", "verify", "--directory", os.path.join(self.d, "empty")], {"MGCTL_VERIFIER": real})
        doc = json.loads(out)
        self.assertEqual(doc["verifierExitCode"], 6)    # the real verifier's own answer for an incomplete set of files
        self.assertEqual(code, 4)
        self.assertFalse(doc["ok"])


# ---- 7: the optional alias and the conflict with an existing mg -------------------------------------------------
class AliasTests(Tmp):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.d, "bin")
        self.other = os.path.join(self.d, "other")
        os.mkdir(self.bin)
        os.mkdir(self.other)
        self.launcher = write_exe(os.path.join(self.d, "mgctl"), "#!/bin/sh\nexit 0\n")
        self.env["MGCTL_LAUNCHER"] = self.launcher

    def path_env(self, *dirs):
        return dict(self.env, PATH=os.pathsep.join(dirs + ("/usr/bin_not_real_for_mgctl_test",)))

    def test_an_existing_mg_blocks_the_alias_and_nothing_is_changed(self):
        write_exe(os.path.join(self.other, "mg"), "#!/bin/sh\necho emacs-like editor\n")
        env = self.path_env(self.other, self.bin)
        before = os.environ.get("PATH")
        code, out, err = run_main(["alias", "enable", "--dir", self.bin], env)
        self.assertEqual(code, 4)
        self.assertIn("another 'mg'", err)
        self.assertFalse(os.path.lexists(os.path.join(self.bin, "mg")))
        self.assertEqual(os.environ.get("PATH"), before)                       # PATH is never edited
        self.assertEqual(slurp(os.path.join(self.other, "mg")), "#!/bin/sh\necho emacs-like editor\n")

    def test_force_conflict_creates_it_but_warns_it_will_not_win(self):
        write_exe(os.path.join(self.other, "mg"), "#!/bin/sh\n")
        env = self.path_env(self.other, self.bin)
        code, out, err = run_main(["--json", "alias", "enable", "--dir", self.bin, "--force-conflict"], env)
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertIn(os.path.join(self.other, "mg"), doc["shadowedBy"])
        self.assertTrue(os.path.islink(os.path.join(self.bin, "mg")))

    def test_enable_disable_roundtrip_and_refusal_to_overwrite_or_remove_foreign_files(self):
        env = self.path_env(self.bin)
        self.assertEqual(run_main(["alias", "enable", "--dir", self.bin], env)[0], 0)
        link = os.path.join(self.bin, "mg")
        self.assertEqual(os.path.realpath(link), os.path.realpath(self.launcher))
        self.assertEqual(run_main(["alias", "enable", "--dir", self.bin], env)[0], 4)          # exists: never overwritten
        self.assertEqual(run_main(["alias", "disable", "--dir", self.bin], env)[0], 0)
        self.assertFalse(os.path.lexists(link))
        write_exe(link, "#!/bin/sh\n# someone else's mg\n")
        self.assertEqual(run_main(["alias", "disable", "--dir", self.bin], env)[0], 4)
        self.assertTrue(os.path.exists(link))                                                  # not ours: untouched

    def test_status_and_doctor_report_the_conflict(self):
        write_exe(os.path.join(self.other, "mg"), "#!/bin/sh\n")
        env = self.path_env(self.other)
        code, out, _e = run_main(["--json", "alias", "status"], env)
        doc = json.loads(out)
        self.assertTrue(doc["conflict"])
        self.assertFalse(doc["enabled"])
        code, out, _e = run_main(["--json", "doctor"], env, macos=False)
        self.assertIn("NOT ours", [c for c in json.loads(out)["checks"] if c["check"] == "alias-mg"][0]["detail"])

    def test_directory_must_exist_be_writable_and_not_a_link(self):
        env = self.path_env()
        self.assertEqual(run_main(["alias", "enable", "--dir", os.path.join(self.d, "absent")], env)[0], 3)
        link = os.path.join(self.d, "dirlink")
        os.symlink(self.bin, link)
        self.assertEqual(run_main(["alias", "enable", "--dir", link], env)[0], 3)

    def test_the_default_directory_is_never_root_owned(self):
        from mgctl.services import aliasing
        self.assertTrue(aliasing.default_dir().startswith(os.path.expanduser("~")))


# ---- 8: install, uninstall, packaging ------------------------------------------------------------------------------
class InstallTests(Tmp):
    def build(self):
        out = os.path.join(self.d, "dist")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "pkg", "make_dist.py"), "--out", out], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return out

    def test_dist_is_deterministic_and_its_checksum_verifies(self):
        a = self.build()
        first = slurp(os.path.join(a, "SHA256SUMS"))
        shutil.rmtree(a)
        self.build()
        self.assertEqual(slurp(os.path.join(a, "SHA256SUMS")), first)               # reproducible
        digest, name = first.split()
        self.assertEqual(hashlib.sha256(slurp(os.path.join(a, name), "rb")).hexdigest(), digest)

    def test_install_run_reinstall_and_uninstall_without_root(self):
        dist = self.build()
        with tarfile.open(os.path.join(dist, f"mgctl-{VERSION}.tar.gz")) as t:
            t.extractall(os.path.join(self.d, "x"), filter="data") if sys.version_info >= (3, 12) else t.extractall(os.path.join(self.d, "x"))
        src = os.path.join(self.d, "x", f"mgctl-{VERSION}")
        prefix = os.path.join(self.d, "prefix")
        run = lambda *a: subprocess.run(["/bin/sh", os.path.join(src, "install.sh"), *a], capture_output=True, text=True, timeout=60)
        r = run("install", "--prefix", prefix)
        self.assertEqual(r.returncode, 0, r.stderr)
        exe = os.path.join(prefix, "bin", "mgctl")
        v = subprocess.run([exe, "--version"], capture_output=True, text=True, env=dict(os.environ, MGCTL_LANG="en"), timeout=60)
        self.assertEqual((v.returncode, v.stdout.split()[:2]), (0, ["mgctl", VERSION]))
        self.assertEqual(run("install", "--prefix", prefix).returncode, 0)                  # upgrade in place
        self.assertFalse(os.path.lexists(os.path.join(prefix, "bin", "mg")))                # never creates the alias
        self.assertEqual(run("uninstall", "--prefix", prefix).returncode, 0)
        self.assertFalse(os.path.lexists(exe))
        self.assertFalse(os.path.exists(os.path.join(prefix, "lib", "mgctl")))

    def test_install_refuses_to_replace_something_that_is_not_ours(self):
        dist = self.build()
        with tarfile.open(os.path.join(dist, f"mgctl-{VERSION}.tar.gz")) as t:
            t.extractall(os.path.join(self.d, "x"))
        src = os.path.join(self.d, "x", f"mgctl-{VERSION}")
        prefix = os.path.join(self.d, "p2")
        os.makedirs(os.path.join(prefix, "bin"))
        write_exe(os.path.join(prefix, "bin", "mgctl"), "#!/bin/sh\necho foreign\n")
        r = subprocess.run(["/bin/sh", os.path.join(src, "install.sh"), "install", "--prefix", prefix], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 4)
        self.assertEqual(slurp(os.path.join(prefix, "bin", "mgctl")), "#!/bin/sh\necho foreign\n")
        bad = subprocess.run(["/bin/sh", os.path.join(src, "install.sh"), "install", "--prefix", "relative/dir"], capture_output=True, text=True, timeout=60)
        self.assertEqual(bad.returncode, 3)

    def test_deb_structure_and_no_mg_binary(self):
        out = os.path.join(self.d, "deb")
        r = subprocess.run([sys.executable, os.path.join(ROOT, "pkg", "make_deb.py"), "--out", out], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        path = r.stdout.strip().splitlines()[-1]
        raw = slurp(path, "rb")
        self.assertTrue(raw.startswith(b"!<arch>\n"))
        members, i = {}, 8
        while i < len(raw):
            hdr = raw[i:i + 60]
            name, size = hdr[:16].decode().strip().rstrip("/"), int(hdr[48:58])
            members[name] = raw[i + 60:i + 60 + size]
            i += 60 + size + (size % 2)
        self.assertEqual(list(members), ["debian-binary", "control.tar.gz", "data.tar.gz"])
        self.assertEqual(members["debian-binary"], b"2.0\n")
        ctrl = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"])).extractfile("./control").read().decode()
        self.assertIn("Package: macguard-mgctl", ctrl)
        self.assertIn(f"Version: {VERSION}", ctrl)
        names = tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"])).getnames()
        self.assertIn("./usr/bin/mgctl", names)
        self.assertNotIn("./usr/bin/mg", names)
        self.assertTrue(all(not n.endswith("/mg") for n in names))

    def test_homebrew_template_is_valid_ruby_and_installs_only_mgctl(self):
        rb = os.path.join(ROOT, "pkg", "homebrew", "macguard-mgctl.rb")
        text = slurp(rb)
        self.assertNotRegex(text, r'bin\.install\s+"mg"\b')
        self.assertIn("REPLACE", text)                   # a template: no invented url or checksum
        if shutil.which("ruby"):
            self.assertEqual(subprocess.run(["ruby", "-c", rb], capture_output=True, timeout=30).returncode, 0)


# ---- 9, 10, 15: compatibility and regressions ----------------------------------------------------------------------
class CompatibilityTests(unittest.TestCase):
    def test_legacy_cli_and_target_are_untouched(self):
        src = slurp(os.path.join(ROOT, "DMGTrustAuditor", "DMGTrustAuditor", "CLI", "CLI.swift"))
        for legacy in ("scan", "formats", "engine-status", "update-rules", "verify-rules", "rules-status", "hash", "signature", "identity", "explain", "tui"):
            self.assertIn(f'case "{legacy}"', src, f"legacy command {legacy} must keep working")
        proj = slurp(os.path.join(ROOT, "DMGTrustAuditor", "DMGTrustAuditor", "project.yml"))
        self.assertIn("macguard-audit:", proj)
        self.assertIn("PRODUCT_NAME: macguard-audit", proj)

    def test_no_new_binary_replaces_a_legacy_or_foreign_name(self):
        self.assertTrue(os.path.isfile(LAUNCHER))
        self.assertFalse(os.path.exists(os.path.join(ROOT, "bin", "mg")))
        self.assertFalse(os.path.exists(os.path.join(ROOT, "bin", "macguard-audit")))

    def test_json_documents_carry_schema_and_contract_versions(self):
        code, out, _e = run_main(["--json", "version"])
        doc = json.loads(out)
        self.assertEqual((doc["schemaVersion"], doc["contract"], doc["version"]), (1, CONTRACT, VERSION))

    def test_telemetry_is_absent_by_construction(self):
        banned = re.compile(r"\b(urllib|http\.client|requests|socket|urlopen)\b")
        for base, _d, files in os.walk(os.path.join(ROOT, "mgctl")):
            for fn in files:
                if fn.endswith(".py"):
                    self.assertIsNone(banned.search(slurp(os.path.join(base, fn))), f"{fn} must not use the network: engines do, mgctl does not")


class RealEngineTests(Tmp):
    """Run only when MGCTL_AUDIT_BIN points to a real, built macguard-audit (macOS)."""

    def setUp(self):
        super().setUp()
        exe = os.environ.get("MGCTL_AUDIT_BIN")
        if platform.system() != "Darwin" or not exe or not os.path.isfile(exe):
            self.skipTest("no real macguard-audit (set MGCTL_AUDIT_BIN)")
        self.env = {"MGCTL_AUDIT_BIN": exe, "MGCTL_LANG": "en"}

    def test_scan_passes_the_real_engine_output_through(self):
        f = self.f("script.sh", b"#!/bin/sh\necho hi\n")
        code, out, _e = run_main(["--json", "scan", f], self.env)
        doc = json.loads(out)
        self.assertEqual(doc["tool"], "macguard-audit")
        self.assertEqual(doc["results"][0]["sha256"], hashlib.sha256(b"#!/bin/sh\necho hi\n").hexdigest())
        self.assertIn(code, (0, 2))

    def test_audit_file_cross_checks_the_real_engine_and_never_claims_a_missing_yara_engine_is_clean(self):
        f = self.f("script.sh", b"#!/bin/sh\necho hi\n")
        code, out, _e = run_main(["--json", "audit", "file", f], self.env)
        doc = json.loads(out)
        by = {c["id"]: c for c in doc["checks"]}
        self.assertEqual(by["hash"]["status"], "passed")
        self.assertFalse(doc["changedDuringAnalysis"])                       # engine SHA-256 equals ours
        self.assertIn(by["yara"]["status"], ("passed", "warning", "failed", "unavailable"))
        if by["yara"]["status"] == "unavailable":
            self.assertEqual(code, 4)
        self.assertFalse(doc["complete"])                                    # provenance and vulns still have no engine

    def test_intelligence_status_runs_against_the_real_engine(self):
        code, out, _e = run_main(["--json", "intelligence", "status"], self.env)
        self.assertEqual(code, 0)
        self.assertIn("yaraEngine", json.loads(out))


if __name__ == "__main__":
    unittest.main()
