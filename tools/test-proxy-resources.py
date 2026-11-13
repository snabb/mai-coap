#!/usr/bin/env python3
"""Reject incomplete or unsafe two-endpoint proxy measurement reports."""

import importlib.util
import pathlib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "proxy_resources", pathlib.Path(__file__).with_name("proxy-resources.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ROWS = [
    f"proxy: security={mode} D=1152 forwards=2 payload=1024 incoming_future=1440 "
    "outgoing_future=1440 painted=20000 capacity=50000"
    for mode in ("plain", "secure")
]
PASS = "mai-coap proxy runtime: PASS"


class ProxyReportTests(unittest.TestCase):
    def test_both_scenarios_and_completion_are_required(self):
        report = MODULE.measurements("\n".join([*ROWS, PASS]))
        self.assertEqual(set(report), {"plain", "secure"})
        for log in ("", "\n".join(ROWS), "\n".join([ROWS[0], PASS])):
            with self.assertRaises(ValueError):
                MODULE.measurements(log)

    def test_duplicate_or_malformed_reports_fail(self):
        for row in (
            ROWS[0],
            ROWS[0].replace("forwards=2", "forwards=1"),
            ROWS[0].replace("D=1152", "D=128"),
            ROWS[0].replace("payload=1024", "payload=6"),
        ):
            with self.assertRaises(ValueError):
                MODULE.measurements("\n".join([*ROWS, row, PASS]))

    def test_invalid_sizes_and_exhausted_guard_fail(self):
        for row in (
            ROWS[0].replace("incoming_future=1440", "incoming_future=0"),
            ROWS[0].replace("painted=20000", "painted=49800"),
        ):
            with self.assertRaises(ValueError):
                MODULE.measurements("\n".join([row, ROWS[1], PASS]))

    def test_missing_empty_or_duplicate_executable_sections_fail(self):
        valid = ".vector_table 256 0\n.text 1000 256\n.bss 0 2048\n"
        self.assertEqual(MODULE.section_sizes(valid)[".text"], 1000)
        for sections in (
            "",
            valid.replace(".text 1000", ".text 0"),
            valid.replace(".text 1000 256\n", ""),
            valid + ".text 1000 256\n",
            valid + ".data -1 5000\n",
        ):
            with self.assertRaises(ValueError):
                MODULE.section_sizes(sections)


if __name__ == "__main__":
    unittest.main()
