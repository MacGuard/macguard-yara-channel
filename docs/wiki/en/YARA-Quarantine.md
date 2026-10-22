# Rule quarantine

[Home](EN-Home) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify)

## In 30 seconds

Every YARA rule file that arrives from the sources is examined. Files that pass every test are accepted and published on their own. Files that do not pass are not published: they end up **rejected**, **blocked** or **pending review**. A person with the reviewer role may approve or reject only the ones pending review; they can **never** skip a technical test, because after approval the file is validated again. Every decision is written to a hash-chained record. {{ev:EV-YC-40}}

## An everyday example

Think of quality control in a bakery. Good bread goes to the shop. Burnt or broken bread is thrown away (you cannot "approve" burnt bread). Bread with a doubtful flaw, say less golden than usual, is looked at by a person: if they say "fine", it is weighed and measured again before it is sold. Whatever the person decides goes into a notebook where each page mentions the previous one. The analogy only illustrates the flow; it does not imply that everything is detected.

{{diagram:quarantine-lanes-1-outcomes}}

{{diagram:quarantine-lanes-2-pending}}

{{diagram:quarantine-lanes-3-recheck}}

## Step by step

1. The daily pipeline classifies each file (`scripts/rulecheck.py`) and decides (`scripts/decide.py`).
2. Accepted files (`VALIDATED`) go into the release candidate.
3. Quarantined files with judgment-only findings are sent to the private panel as candidates (`PENDING`).
4. A reviewer approves, rejects or holds. Approving publishes nothing: the next cycle validates the file again.
5. `publish.yml` re-verifies the final set and, after publishing, tells the panel what was released (`RELEASED`).

{{diagram:quarantine-states-1-pending}}

{{diagram:quarantine-states-2-under-review}}

{{diagram:quarantine-states-3-approved}}

{{diagram:quarantine-states-4-released}}

| Candidate state | Meaning |
|---|---|
| `PENDING` | Entered quarantine and waits for review. |
| `UNDER_REVIEW` | A reviewer holds it on purpose. |
| `APPROVED_PENDING_VALIDATION` | Approved; the pipeline still has to validate it again. |
| `REJECTED` | Rejected; that content (same SHA-256) does not come back. |
| `RELEASED` | A verified public release lists that exact content. |

## Under the hood

**Four fates** (`rulecheck.py`, classification function): `REJECTED` on a hard criterion (binary, no rules, over the size cap, too many rules, or content rejected before: codes `binary`, `no-rules`, `oversized`, `too-many-rules`, `previously-rejected`); `QUARANTINED` on truncated, corrupt or review findings; `DEPRECATED` if the file marks itself obsolete; `VALIDATED` if none applies. Only `VALIDATED` is published. The caps are in `config/policy.json`: `max_file_bytes` 1000000 and `max_rules_per_file` 3000. {{ev:EV-YC-40}}

**What a person can decide.** In the private review service an authorized reviewer can approve, reject, hold or send a candidate to review. Each decision needs a recorded reason, and requests are protected against repeats and against acting on a stale version. No human action produces `RELEASED`: only `publish.yml` writes it, after seeing the file in a verified manifest. {{ev:EV-YC-42}}

**Findings that can NOT be approved.** Judgment findings can be waived by a person with a recorded reason; hard failures cannot. Everything else is a technical control: the panel refuses to approve it and `decide.py` applies the rule again when it executes decisions. A test keeps both lists identical. {{ev:EV-YC-41}}

| Real code | What it means | Why it cannot be approved |
|---|---|---|
| `unbalanced-braces`, `unclosed-rule`, `ends-mid-file`, `unterminated-string`, `unterminated-comment`, `unterminated-regex` | Truncated file | Bytes are missing; approving does not bring them back. |
| `corrupt-encoding`, `no-condition`, `compile-error`, `compile-dependency` | Damaged or does not compile | The engine cannot load or measure it. |
| `blocked-module`, `no-engine` | Blocked module or no engine | There is no safe way to run it. |
| `license-changed` | The license changed | A legal matter, not a judgment call. |
| `dynamic-failure` | Caused a hang, timeout or regression | The dynamic test failed: a measured fact. |
| `previously-rejected`, `rejected-by-reviewer` | Same content rejected before | The human decision stands while the bytes are the same. |

A changed file is a new candidate (key `(sha256, path)`) and inherits no approval; the earlier version is only shown as precedent. {{ev:EV-YC-41}}

**Decision record.** Each decision writes an audit entry in the same atomic operation as the decision. The hash of each entry depends on the previous entry and on its own content, so an edited, removed or reordered entry is detectable by an authorized verification. Planned hardening: periodic anchoring of the record outside the service (see State). {{ev:EV-YC-42}}

## Check it yourself

The pipeline code and its tests are public. From a clone of the repository:

```bash
python3 -m unittest tests.test_admission tests.test_decide
```

At the time of the review (2026-10-22) these suites passed on `main`. The review service has its own test suite, which CI runs on every pull request. Test counts change with every commit, so none is quoted here: run the commands to get the current figure. {{ev:EV-YC-42}} The codes were read in `scripts/rulecheck.py` and `scripts/decide.py`. Code: [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py).

## Limits

- A "validated" file is not a guarantee of detection quality or of absence of false positives.
- Details of quarantined rules (names, findings, content) go only to the private service; public material carries counts.
- The review service only records decisions; publication and signing run in `publish.yml`.

## State

| Capability | State |
|---|---|
| Classification, decision and non-approvable findings in the pipeline | operational {{ev:EV-YC-41}} |
| Private review panel: approve, reject, hold, audit record | operational {{ev:EV-YC-05}} |
| Persistent decision memory and withdrawal of published rules | implemented in the repository, not yet active in production {{ev:EV-YC-43}} |
| Audit anchoring outside the service | implemented in the repository, not yet active in production {{ev:EV-YC-44}} |
| Admission control for new sources | implemented in the repository, not yet active in production {{ev:EV-YC-07}} |

Persistent withdrawals, policies and audit anchoring are implemented in the repository and not yet active in production; the live service tolerates their absence. Until they are active, the pipeline (`decide.py`) does not yet apply recorded withdrawals to the next release. {{ev:EV-YC-43}} {{ev:EV-YC-06}}
