---
title: Quarantine
summary: What happens to rules that do not pass, and how their fate is decided.
---
## The idea

What passes the tests is published automatically. What does not pass goes to quarantine and a person decides: approve its deployment, delete it or keep it. On the next daily run the pipeline reads that decision and acts: publishes the rule, removes it or leaves it in quarantine. Approving **never** skips the technical checks: the rule is validated again.

{{diagram:quarantine-states}}

| State | Meaning |
|---|---|
| PENDING | Entered quarantine; waiting for review. |
| UNDER_REVIEW | A person marked it as under review. |
| APPROVED_PENDING_VALIDATION | Approved; `publish.yml` still has to validate it again. |
| REJECTED | Deleted; that content does not come back. An edited version is a new linked candidate. |
| RELEASED | Published in a release. |

## What goes public

Details of quarantined or rejected rules (names, findings, content) travel only to the private service. Public artifacts, the log and the site carry counts only. A file that is not in the manifest appears nowhere public.

> **CURRENT** The panel is operational (see [Private panel](page:admin-panel)) and the pipeline reads its decisions on every run. Persistent policies and withdrawals of already published rules are in `main` but not deployed (migrations 0003 to 0005 are not applied), and the pipeline does not consume policies yet.
