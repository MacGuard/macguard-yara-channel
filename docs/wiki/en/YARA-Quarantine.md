# Rule quarantine

[Home](EN-Home) · [Quarantine](EN-YARA-Quarantine) · [Publishing](EN-YARA-Publishing) · [Transparency](EN-YARA-Transparency) · [Verify](EN-YARA-Verify)

## In 30 seconds

Every YARA rule file that arrives from the sources is examined. Files that pass every test are accepted and published on their own. Files that do not pass are not published: they end up **rejected**, **blocked** or **pending review**. A person with the reviewer role may approve or reject only the ones pending review; they can **never** skip a technical test, because after approval the file is validated again. Every decision is written to a hash-chained record. {{ev:EV-YC-40}}

## An everyday example

Think of quality control in a bakery. Good bread goes to the shop. Burnt or broken bread is thrown away (you cannot "approve" burnt bread). Bread with a doubtful flaw, say less golden than usual, is looked at by a person: if they say "fine", it is weighed and measured again before it is sold. Whatever the person decides goes into a notebook where each page mentions the previous one. The analogy only illustrates the flow; it does not imply that everything is detected.

{{diagram:quarantine-lanes}}

## Step by step

1. The daily pipeline classifies each file (`scripts/rulecheck.py`) and decides (`scripts/decide.py`).
2. Accepted files (`VALIDATED`) go into the release candidate.
3. Quarantined files with judgement-only findings are sent to the private panel as candidates (`PENDING`).
4. A reviewer approves, rejects or holds. Approving publishes nothing: the next cycle validates the file again.
5. `publish.yml` re-verifies the final set and, after publishing, tells the panel what was released (`RELEASED`).

{{diagram:quarantine-states}}

| Candidate state | Meaning |
|---|---|
| `PENDING` | Entered quarantine and waits for review. |
| `UNDER_REVIEW` | A reviewer holds it on purpose. |
| `APPROVED_PENDING_VALIDATION` | Approved; the pipeline still has to validate it again. |
| `REJECTED` | Rejected; that content (same SHA-256) does not come back. |
| `RELEASED` | A verified public release lists that exact content. |

## Under the hood

**Four fates** (`rulecheck.py`, classification function): `REJECTED` on a hard criterion (binary, no rules, over the size cap, too many rules, or content rejected before: codes `binary`, `no-rules`, `oversized`, `too-many-rules`, `previously-rejected`); `QUARANTINED` on truncated, corrupt or review findings; `DEPRECATED` if the file marks itself obsolete; `VALIDATED` if none applies. Only `VALIDATED` is published. The caps are in `config/policy.json`: `max_file_bytes` 1000000 and `max_rules_per_file` 3000. {{ev:EV-YC-40}}

**What a person can decide.** The panel offers `approve`, `reject`, `hold`, `review` and `release_review` (`admin/worker/src/core.js`, table `HUMAN`). Approve, reject and hold need a reason of 5 to 2000 visible characters; a batch needs `confirm_count` equal to the real number; each request carries an idempotent `request_id` and the version the reviewer saw (if it moved, the request is refused). No human action produces `RELEASED`: only `publish.yml` writes it, after seeing the file in a verified manifest. {{ev:EV-YC-42}}

**Findings that can NOT be approved.** Only the judgement findings in the `WAIVABLE` list may be accepted by hand: `costly-regex`, `filesize-loop`, `many-loops`, `unknown-module`, `include`, `license-unchecked`, `matches-benign-corpus`, `dependency-not-validated`, `new-source`. Everything else is a technical control: the panel refuses to approve it (`blockingReasons`) and `decide.py` applies the rule again when it executes decisions. A test keeps both lists identical (`tests/test_admission.py`). {{ev:EV-YC-41}}

| Real code | What it means | Why it cannot be approved |
|---|---|---|
| `unbalanced-braces`, `unclosed-rule`, `ends-mid-file`, `unterminated-string`, `unterminated-comment`, `unterminated-regex` | Truncated file | Bytes are missing; approving does not bring them back. |
| `corrupt-encoding`, `no-condition`, `compile-error`, `compile-dependency` | Damaged or does not compile | The engine cannot load or measure it. |
| `blocked-module`, `no-engine` | Blocked module or no engine | There is no safe way to run it. |
| `license-changed` | The licence changed | A legal matter, not a judgement call. |
| `dynamic-failure` | Caused a hang, timeout or regression | The dynamic test failed: a measured fact. |
| `previously-rejected`, `rejected-by-reviewer` | Same content rejected before | The human decision stands while the bytes are the same. |

A changed file is a new candidate (key `(sha256, path)`) and inherits no approval; the earlier version is only shown as precedent. {{ev:EV-YC-41}}

**Decision record.** Each decision writes an audit entry in the same atomic D1 batch. The hash of each entry is `SHA-256(previous_hash + canonical JSON of the entry)`, starting from 64 zeros (`chainHash`, `GENESIS` in `core.js`). `verifyChain` fails if an entry is edited, removed or reordered (verification restricted to administrators). What it does not prevent: someone with full control of the database could rewrite the **whole** chain; that is why the anchor design exists (see State). {{ev:EV-YC-42}}

## Check it yourself

The panel code and its tests are public. From a clone of the repository:

```bash
python3 -m unittest tests.test_admission tests.test_decide
cd admin/worker && npm test
```

Run on 2026-10-22 against `main`: the Python tests for this topic (112 tests, together with the signing and log ones) passed, and `node --test test/service.test.js test/policies.test.js test/anchor.test.js` in `admin/worker` gave 113 passes and 0 failures. The codes were read in `scripts/rulecheck.py`, `scripts/decide.py` and `admin/worker/src/core.js`. Code: [core.js](https://github.com/MacGuard/macguard-yara-channel/blob/main/admin/worker/src/core.js), [decide.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/decide.py), [rulecheck.py](https://github.com/MacGuard/macguard-yara-channel/blob/main/scripts/rulecheck.py). Public panel description: [admin-panel](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs-src/en/admin-panel.md).

## Limits

- A "validated" file is not a guarantee of detection quality or of absence of false positives.
- Details of quarantined rules (names, findings, content) go only to the private service; public material carries counts.
- The Worker does not verify Sigstore signatures; `publish.yml` does. The Worker only recomputes `rules_root` of the public manifest.

## State

| Capability | State |
|---|---|
| Classification, decision and non-approvable findings in the pipeline | operational {{ev:EV-YC-41}} |
| Deployed panel: approve, reject, hold, audit chain | operational {{ev:EV-YC-05}} |
| Persistent decision memory, withdrawal of published rules (`policies`, migration 0003) | implemented-not-deployed {{ev:EV-YC-43}} |
| Audit anchors (`audit_anchor`, migration 0004) | implemented-not-deployed {{ev:EV-YC-44}} |
| Source proposals (migration 0005) | implemented-not-deployed {{ev:EV-YC-07}} |

Migrations 0003, 0004 and 0005 are not applied. The `main` Worker tolerates their absence (reads answer "no policies"), but in production persistent withdrawals, policies and anchors **do not exist**. Also, in `main` the pipeline (`decide.py`) does not read policies yet: `blocked-by-policy` was not found in `scripts/`, so a recorded withdrawal would not yet be applied to the next release. There is no `reopen` action either: nothing takes a candidate out of `REJECTED`. Design: [specification](https://github.com/MacGuard/macguard-yara-channel/blob/main/docs/audit/quarantine-decision-memory-and-withdrawal-spec.md) (its header says "design only"; the code in `policies.js` and `anchor.js` is already in `main`). {{ev:EV-YC-43}} {{ev:EV-YC-06}}
