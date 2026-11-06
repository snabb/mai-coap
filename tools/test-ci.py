#!/usr/bin/env python3
"""Keep routine/full coverage and the required CI gate fail-closed."""

import copy
import json
import pathlib
import re
import unittest

from ci import FULL_EVENTS, ROUTINE_EVENTS, check_results

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def results(optional="success"):
    return {
        "embedded": {"result": "success"},
        "fuzz": {"result": optional},
        "kani": {"result": optional},
    }


class GateTests(unittest.TestCase):
    def test_routine_runs_accept_only_intentional_skips(self):
        for event in ROUTINE_EVENTS:
            for status in ["success", "skipped"]:
                check_results(results(status), event)
            for name in results():
                for status in ["failure", "cancelled", None]:
                    jobs = results("skipped")
                    jobs[name]["result"] = status
                    with (
                        self.subTest(event=event, name=name, status=status),
                        self.assertRaises(ValueError),
                    ):
                        check_results(jobs, event)
            jobs = results("skipped")
            jobs["embedded"]["result"] = "skipped"
            with self.assertRaises(ValueError):
                check_results(jobs, event)

    def test_full_runs_require_every_prerequisite(self):
        for event in FULL_EVENTS:
            check_results(results(), event)
            for name in results():
                for status in ["skipped", "failure", "cancelled"]:
                    jobs = results()
                    jobs[name]["result"] = status
                    with (
                        self.subTest(event=event, name=name, status=status),
                        self.assertRaises(ValueError),
                    ):
                        check_results(jobs, event)

    def test_missing_malformed_and_unexpected_dependencies_do_not_pass(self):
        bad = [None, [], {}, {"extra": {"result": "success"}}]
        for name in results():
            missing = results()
            del missing[name]
            bad.append(missing)
            malformed = results()
            malformed[name] = None
            bad.append(malformed)
        extra = results()
        extra["extra"] = {"result": "success"}
        bad.append(extra)
        for jobs in bad:
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                check_results(jobs, "push")
        with self.assertRaises(ValueError):
            check_results(results(), "unknown")

    def test_validation_does_not_modify_results(self):
        jobs = results("skipped")
        before = copy.deepcopy(jobs)
        check_results(jobs, "push")
        self.assertEqual(jobs, before)


class WorkflowTests(unittest.TestCase):
    def test_matrix_keeps_m0_m33_routine_and_all_four_targets_on_full_runs(self):
        text = WORKFLOW.read_text()
        match = re.search(
            r"target:\s*>-\s*\$\{\{\s*fromJSON\(\s*"
            r"\(github.event_name == 'schedule' \|\| github.event_name == 'workflow_dispatch'\)"
            r"\s*&& '([^']+)'\s*\|\| '([^']+)'\s*\)\s*\}\}",
            text,
        )
        self.assertIsNotNone(
            match, "review the event-to-matrix policy when changing it"
        )
        full, routine = map(json.loads, match.groups())
        self.assertEqual(routine, ["thumbv6m-none-eabi", "thumbv8m.main-none-eabihf"])
        self.assertEqual(len(full), len(set(full)))
        self.assertEqual(
            set(full),
            set(routine) | {"thumbv7em-none-eabihf", "riscv32imac-unknown-none-elf"},
        )
        matrix = text.split("      matrix:", 1)[1].split("    steps:", 1)[0]
        self.assertNotIn(
            "include:", matrix, "include rows can recreate excluded targets"
        )


if __name__ == "__main__":
    unittest.main()
