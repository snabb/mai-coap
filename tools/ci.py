#!/usr/bin/env python3
"""Validate prerequisite results before running the combined CI check."""

import json
import os

FULL_EVENTS = {"schedule", "workflow_dispatch"}
ROUTINE_EVENTS = {"push", "pull_request", "merge_group"}
PREREQUISITES = {"embedded", "fuzz", "kani"}


def check_results(jobs, event):
    if event not in FULL_EVENTS | ROUTINE_EVENTS:
        raise ValueError(f"Unsupported CI event: {event}")
    if not isinstance(jobs, dict) or jobs.keys() != PREREQUISITES:
        raise ValueError("Expected embedded, fuzz and kani prerequisite results")
    failed = []
    for name, job in jobs.items():
        result = job.get("result") if isinstance(job, dict) else None
        allowed = {"success"}
        if event in ROUTINE_EVENTS and name in {"fuzz", "kani"}:
            allowed.add("skipped")
        if result not in allowed:
            failed.append(f"{name} ({result})")
    if failed:
        raise ValueError("Checks did not pass: " + ", ".join(failed))


def main():
    try:
        check_results(
            json.loads(os.environ.get("JOB_RESULTS", "{}")),
            os.environ.get("GITHUB_EVENT_NAME", ""),
        )
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print("Prerequisites passed; running host validation.")


if __name__ == "__main__":
    main()
