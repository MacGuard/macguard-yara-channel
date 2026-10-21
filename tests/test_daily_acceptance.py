"""A manual acceptance run of daily.yml must never reach the job that requests a release.

The acceptance input exists so that the real quarantine integration can be exercised (download, classification, static and dynamic gates, OIDC
call to the panel, candidates in D1) with AUTO_PUBLISH=true left alone: request-publish is the only job that starts publish.yml, so it is the one
that has to be unreachable. The condition of that job is evaluated here for every combination of its inputs, with a small evaluator of the
GitHub expression subset the workflow uses (no YAML dependency, like the rest of the suite)."""
import itertools
import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
DAILY = (WORKFLOWS / "daily.yml").read_text()
# The condition before the acceptance input existed: scheduled and ordinary manual runs must keep behaving exactly like this.
# The wording of candidate.changes in an ordinary run (scheduled or manual) must stay byte for byte what it always was.
NORMAL_MSG = 'The approved set differs from the latest release. A new release will be requested.'
ACCEPTANCE_MSG = 'The approved set differs from the latest release. This was an acceptance run: no release is requested.'
ACCEPTANCE_ENV = "ACCEPTANCE: ${{ github.event_name == 'workflow_dispatch' && inputs.acceptance }}"
BEFORE = "needs.review.outputs.publishable == 'true' && needs.review.outputs.changed == 'true' && needs.macos.result == 'success'"


def job_block(text, name):
    m = re.search(rf"^  {re.escape(name)}:\s*$(.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)", text, re.S | re.M)
    assert m, f"job {name} not found"
    return m.group(1)


def job_if(text, name):
    m = re.search(r"^    if: (.+)$", job_block(text, name), re.M)
    assert m, f"job {name} has no if"
    return m.group(1).strip()


def evaluate(expr, ctx):
    """Evaluate `||`, `&&`, `!`, `==`, `!=`, parentheses, 'strings', true/false and dotted context names, as GitHub does (truthiness of operands)."""
    toks = re.findall(r"\|\||&&|==|!=|!|\(|\)|'[^']*'|[A-Za-z_][A-Za-z0-9_.\-]*", expr)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def truthy(v):
        return v not in (None, "", False, 0)

    def primary():
        t = take()
        if t == "!":
            return not truthy(primary())
        if t == "(":
            v = disj()
            assert take() == ")"
            return v
        if t.startswith("'"):
            return t[1:-1]
        if t in ("true", "false"):
            return t == "true"
        return ctx.get(t)

    def comparison():
        v = primary()
        while peek() in ("==", "!="):
            op, w = take(), primary()
            v = (v == w) if op == "==" else (v != w)
        return v

    def conj():
        v = comparison()
        while peek() == "&&":
            take()
            w = comparison()
            v = w if truthy(v) else v
        return v

    def disj():
        v = conj()
        while peek() == "||":
            take()
            w = conj()
            v = v if truthy(v) else w
        return v

    out = disj()
    assert pos == len(toks), f"unparsed tokens in {expr!r}"
    return truthy(out)


def contexts():
    for event, acceptance, publishable, changed, macos in itertools.product(
        ("schedule", "workflow_dispatch", "push"), (None, False, True), ("true", "false", ""), ("true", "false", ""), ("success", "failure", "skipped", "cancelled")
    ):
        if event != "workflow_dispatch" and acceptance is not None:
            continue   # only a manual dispatch has inputs; on a schedule the inputs context is empty
        yield {"github.event_name": event, "inputs.acceptance": acceptance, "needs.review.outputs.publishable": publishable,
               "needs.review.outputs.changed": changed, "needs.macos.result": macos}


class AcceptanceRunsNeverRequestARelease(unittest.TestCase):
    def test_the_real_condition_is_unreachable_for_every_acceptance_input(self):
        cond, n = job_if(DAILY, "request-publish"), 0
        for ctx in contexts():
            if ctx["inputs.acceptance"] is True:
                n += 1
                self.assertFalse(evaluate(cond, ctx), f"request-publish reachable in an acceptance run: {ctx}")
        self.assertEqual(n, 3 * 3 * 4, "the table must hold every acceptance combination: publishable x changed x macos result")
        self.assertTrue(any(c["inputs.acceptance"] is True and c["needs.review.outputs.changed"] == "true" and c["needs.macos.result"] == "success"
                            and c["needs.review.outputs.publishable"] == "true" for c in contexts()))

    def test_every_other_run_behaves_exactly_as_before(self):
        cond, n = job_if(DAILY, "request-publish"), 0
        for ctx in contexts():
            if ctx["inputs.acceptance"] is True:
                continue
            n += 1
            self.assertEqual(evaluate(cond, ctx), evaluate(BEFORE, ctx), f"behaviour changed for a normal run: {ctx}")
        scheduled = {"github.event_name": "schedule", "inputs.acceptance": None, "needs.review.outputs.publishable": "true", "needs.review.outputs.changed": "true", "needs.macos.result": "success"}
        self.assertTrue(evaluate(job_if(DAILY, "request-publish"), scheduled), "the scheduled run still requests the release (AUTO_PUBLISH model untouched)")
        self.assertTrue(evaluate(job_if(DAILY, "request-publish"), {**scheduled, "github.event_name": "workflow_dispatch", "inputs.acceptance": False}), "an ordinary manual run still requests it")
        self.assertGreater(n, 100)

    def test_the_test_itself_catches_a_missing_guard(self):
        ctx = {"github.event_name": "workflow_dispatch", "inputs.acceptance": True, "needs.review.outputs.publishable": "true", "needs.review.outputs.changed": "true", "needs.macos.result": "success"}
        self.assertTrue(evaluate(BEFORE, ctx), "without the guard an acceptance run would have requested a release")
        self.assertFalse(evaluate(job_if(DAILY, "request-publish"), ctx))
        weak = BEFORE + " && !(github.event_name == 'schedule' && inputs.acceptance)"   # a guard on the wrong event is not a guard
        self.assertTrue(evaluate(weak, ctx))

    def test_request_publish_is_the_only_way_daily_starts_a_release(self):
        self.assertEqual(len(re.findall(r"gh workflow run publish\.yml", DAILY)), 1)
        self.assertIn("gh workflow run publish.yml", job_block(DAILY, "request-publish"))
        for name in re.findall(r"^  ([A-Za-z0-9_-]+):\s*$", DAILY.split("\njobs:\n", 1)[1], re.M):
            if name != "request-publish":
                self.assertNotRegex(job_block(DAILY, name), r"actions:\s*write", f"{name} could dispatch workflows")
                self.assertNotRegex(job_block(DAILY, name), r"gh workflow run|gh api .*dispatches", f"{name} could dispatch workflows")
        needs = re.search(r"^    needs: (.+)$", job_block(DAILY, "request-publish"), re.M)
        self.assertTrue(needs and "review" in needs.group(1) and "macos" in needs.group(1))

    def test_no_other_workflow_starts_publish(self):
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            if wf.name in ("daily.yml", "publish.yml"):
                continue
            self.assertNotRegex(wf.read_text(), r"workflow run publish\.yml|workflows/publish\.yml/dispatches", f"{wf.name} can start publish.yml")

    def test_the_input_is_a_boolean_that_defaults_to_off_and_is_used_nowhere_else(self):
        inputs = DAILY.split("workflow_dispatch:", 1)[1].split("\npermissions:", 1)[0]
        block = re.search(r"^      acceptance:\n(.*?)(?=^      [a-z_]+:|\Z)", inputs, re.M | re.S)
        assert block, "acceptance input missing"
        self.assertIn("type: boolean", block.group(1))
        self.assertIn("default: false", block.group(1))
        uses = [ln.strip() for ln in DAILY.splitlines() if "inputs.acceptance" in ln]
        self.assertEqual(len(uses), 2, f"the acceptance input may only gate request-publish and word the transparency-log message, found: {uses}")
        gate = [u for u in uses if u.startswith("if:")]
        self.assertEqual(len(gate), 1)
        self.assertIn(gate[0], job_block(DAILY, "request-publish"))
        self.assertEqual([u for u in uses if not u.startswith("if:")], [ACCEPTANCE_ENV], "the only other reader is the env of the transparency-log step")
        self.assertIn(ACCEPTANCE_ENV, job_block(DAILY, "review"))
        self.assertNotIn("inputs.acceptance", (WORKFLOWS / "publish.yml").read_text(), "acceptance must not change anything in publication")

    def test_acceptance_does_not_touch_the_rules_of_acceptance(self):
        # Nothing between prepare and the quarantine submission reads the input: classification, the dynamic gate, decisions and submit run as in a normal run.
        # The one reader before the gate is the env of the log step, which only chooses the WORDING of candidate.changes (see the message tests below).
        before_gate = DAILY.split("request-publish:", 1)[0]
        self.assertEqual(before_gate.count("inputs.acceptance"), 1)
        self.assertEqual(before_gate.count(ACCEPTANCE_ENV), 1)
        self.assertEqual(before_gate.count("$ACCEPTANCE"), 1, "the variable is read once, to choose the message")
        self.assertEqual(DAILY.count("AUTO_PUBLISH"), 0, "daily.yml does not read or set AUTO_PUBLISH")


    def test_the_changes_message_only_differs_in_acceptance_runs(self):
        rec = DAILY.split("Record the result in the transparency log", 1)[1].split("- name: Upload the public candidate", 1)[0]
        self.assertEqual(rec.count(NORMAL_MSG), 1, "the ordinary message stays, once, byte for byte")
        self.assertEqual(rec.count(ACCEPTANCE_MSG), 1)
        self.assertEqual(DAILY.count("A new release will be requested"), 1)
        self.assertEqual(len(re.findall(r"--code candidate\.changes", DAILY)), 1, "same event code in both cases")
        self.assertIn(f'CHANGES_MSG="{NORMAL_MSG}"', rec, "the ordinary message is the default")
        self.assertIn(f'if [ "$ACCEPTANCE" = "true" ]; then CHANGES_MSG="{ACCEPTANCE_MSG}"; fi', rec, "the acceptance message is chosen only by the acceptance condition")
        self.assertIn('--code candidate.changes --run-id "$RUN_ID" --message "$CHANGES_MSG"', rec)
        self.assertEqual(rec.count("CHANGES_MSG="), 2, "no other assignment of the message")
        self.assertEqual(rec.count("$ACCEPTANCE"), 1, "ACCEPTANCE is read nowhere else in the step")
        self.assertNotIn("release will be requested", ACCEPTANCE_MSG.replace("no release is requested", ""), "an acceptance run does not announce a publication")

    def test_the_acceptance_flag_of_the_log_step_is_true_only_for_a_manual_acceptance_run(self):
        m = re.search(r"ACCEPTANCE: \$\{\{ (.+?) \}\}", DAILY)
        self.assertTrue(m)
        for event, acc, want in (("schedule", None, False), ("push", None, False), ("workflow_dispatch", False, False), ("workflow_dispatch", None, False), ("workflow_dispatch", True, True)):
            self.assertEqual(evaluate(m.group(1), {"github.event_name": event, "inputs.acceptance": acc}), want, (event, acc))


if __name__ == "__main__":
    unittest.main()
