#!/usr/bin/env python3
"""Did the CRON run, and did it succeed on a tree that contains a given fix? A dispatched run proves nothing about the schedule.

Lists the latest runs of the scheduled workflows with their event, and exits 0 only if the newest run with event == "schedule" of each one
concluded "success" (for the daily review: on a commit that contains --since, default the commit that added cosign to daily.yml, FA-31). Read-only (gh run list).
usage: scripts/schedule_evidence.py [--repo OWNER/REPO] [--since SHA]"""
import argparse
import json
import subprocess
import sys

WORKFLOWS = {"Daily source review": True, "Deploy site (GitHub Pages and Cloudflare Pages)": False}   # True: the run must contain --since


def gh_runs(repo, workflow):
    out = subprocess.run(["gh", "run", "list", "-R", repo, "-w", workflow, "-L", "30", "--json", "databaseId,event,conclusion,status,headSha,createdAt"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def contains(since, sha):
    return subprocess.run(["git", "merge-base", "--is-ancestor", since, sha], capture_output=True).returncode == 0


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("--repo", default="MacGuard/macguard-yara-channel"); ap.add_argument("--since", default="7d46c41")
    a = ap.parse_args(argv); ok = True
    for wf, needs_fix in WORKFLOWS.items():
        runs = gh_runs(a.repo, wf); sched = [r for r in runs if r["event"] == "schedule" and r["status"] == "completed"]
        print(f"== {wf}")
        for r in runs[:6]:
            print(f"  {r['createdAt']}  {r['event']:<18} {r['status']:<10} {r['conclusion'] or '-':<8} {r['headSha'][:7]}  {r['databaseId']}")
        if not sched:
            print("  NO completed scheduled run yet"); ok = False; continue
        last = sched[0]; good = last["conclusion"] == "success" and (not needs_fix or contains(a.since, last["headSha"]))
        print(f"  newest scheduled run {last['databaseId']}: {last['conclusion']} on {last['headSha'][:7]} -> {'OK' if good else 'NOT sufficient (failed, or the tree predates ' + a.since + ')'}")
        ok &= good
    print("\nSCHEDULE EVIDENCE:", "PASS" if ok else "NOT YET")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
