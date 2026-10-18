---
title: Decision gate and accounting
summary: How `decide.py` decides and why the numbers always add up.
---
## The invariant

The unit is the **rule file examined in one run**. Each one ends in exactly one final state and this always holds:

```
examinados = aceptados + en cuarentena + rechazados + obsoletos
```

If a figure breaks the invariant `accounting.py` raises an error: the run is blocked, nothing is logged and nothing is published. Files of the previous release that are no longer upstream are counted separately as `retired`; they are not part of this sum.

## What it decides

- It publishes the approved set only if every mandatory check passed and there is an effective change.
- Anomaly guard: a change that removes more than 15 % of the previous release or touches more than 40 % is not published automatically. A person reviews it and re-runs with `allow_large_change`.
- Previously published rules that stop passing are withheld and logged (`rules.withheld`).
- An approved human decision never bypasses any technical check.

## Public statistics

The website dashboard uses the last run of each day, without mixing days; a day without a run is "no observation", not zero. "New" in a release means files added against the previous one (in the first release, all of them), which is not the same as what was examined in the analysis.
