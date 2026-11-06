#!/usr/bin/env python3
"""Check resource deltas, incomplete runs and master artifact selection."""

import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "resource_summary", pathlib.Path(__file__).with_name("resource-summary.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
M4, M33 = MODULE.TARGETS


def stack_report():
    return {
        "target": M33,
        "features": "stack-profile",
        "toolchain": "rustc current",
        "build_host": "aarch64-unknown-linux-gnu",
        "profile": "release",
        "budget_enforced": True,
        "budgets": {"combined/handshake": 4096},
        "flash_bytes": 100_000,
        "static_ram_bytes": 0,
        "scenarios": {
            "combined/handshake": {
                "datagram_bytes": 1152,
                "peak_bytes": 5000,
                "client_future_bytes": 2032,
                "server_future_bytes": 2032,
            }
        },
    }


def layout_report():
    return {
        "target": M4,
        "toolchain": "rustc current",
        "build_host": "aarch64-unknown-linux-gnu",
        "profile": "release",
        "multicast": False,
        "shared_counters": False,
        "profiles": {
            "server": {
                "capacities": {"D": 1152, "OUTBOUND": 0},
                "endpoint": {"total_bytes": 12000},
                "shared": {"total_bytes": 104},
                "endpoint_breakdown": {"packet_pool_bytes": 2336},
            }
        },
    }


def run(identifier, event="push", branch="master", repository="owner/repo"):
    return {
        "id": identifier,
        "run_number": identifier,
        "event": event,
        "head_branch": branch,
        "head_repository": {"full_name": repository},
        "head_sha": f"commit{identifier}",
        "html_url": f"https://github.com/owner/repo/actions/runs/{identifier}",
    }


class SummaryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = pathlib.Path(directory.name)
        self.current = self.root / "current"
        self.baseline = self.root / "baseline"
        self.current.mkdir()
        self.baseline.mkdir()

    def write(self, directory, name, report):
        (directory / name).write_text(json.dumps(report))

    def test_zero_context_capacity_is_identified_against_the_full_baseline(self):
        for before, after in [(255, 0), (0, 255)]:
            with self.subTest(before=before, after=after):
                current = stack_report()
                previous = copy.deepcopy(current)
                previous["id_context_bytes"] = before
                current["id_context_bytes"] = after
                rendered = MODULE.stack_section(current, previous)
                self.assertIn(
                    f"ID Context capacity (bytes) | `{before}` | `{after}`", rendered
                )
                self.assertIn("5,000 | +0", rendered)
                self.assertIn("**ID Context capacity changed**", rendered)
                self.assertIn("deltas include configuration effects", rendered)

    def test_missing_or_equal_context_capacity_keeps_deltas_without_a_change_note(self):
        for before, after in [(None, 0), (0, None), (0, 0), (255, 255)]:
            with self.subTest(before=before, after=after):
                current = stack_report()
                previous = copy.deepcopy(current)
                if before is not None:
                    previous["id_context_bytes"] = before
                if after is not None:
                    current["id_context_bytes"] = after
                rendered = MODULE.stack_section(current, previous)
                self.assertIn("5,000 | +0", rendered)
                self.assertNotIn("ID Context capacity changed", rendered)

    def test_reduction_can_still_exceed_budget_and_zero_is_a_real_baseline(self):
        current = stack_report()
        previous = copy.deepcopy(current)
        previous["toolchain"] = "rustc previous"
        previous["scenarios"]["combined/handshake"]["peak_bytes"] = 6000
        previous["scenarios"]["combined/handshake"]["client_future_bytes"] = 2000
        previous["flash_bytes"] = 101_000
        name = f"stack-{M33}.json"
        self.write(self.current, name, current)
        self.write(self.baseline, name, previous)
        rendered = MODULE.render(self.current, M33, self.baseline)
        self.assertIn("5,000 | -1,000 | 4,096 | -904 | EXCEEDED", rendered)
        self.assertIn("2,032 | +32 | 2,032 | +0", rendered)
        self.assertIn("100,000 | -1,000 | 0 | +0", rendered)
        self.assertIn("Compiler changed", rendered)
        self.assertIn("rustc previous", rendered)

    def test_missing_reports_or_baseline_do_not_invent_zero_deltas(self):
        rendered = MODULE.render(self.current, M33, self.baseline)
        self.assertIn("No resource measurements were produced", rendered)
        self.assertNotIn("PASS", rendered)
        current = stack_report()
        self.write(self.current, f"stack-{M33}.json", current)
        rendered = MODULE.render(self.current, M33, self.baseline)
        self.assertIn("5,000 | — | 4,096", rendered)
        current["budget_enforced"] = False
        current["budgets"] = None
        self.write(self.current, f"stack-{M33}.json", current)
        rendered = MODULE.render(self.current, M33)
        self.assertIn("Not enforced", rendered)
        self.assertNotIn("PASS", rendered)

    def test_owned_xarxa_static_components_are_included_not_added(self):
        current = stack_report()
        current["features"] = "xarxa-profile"
        scenario = current["scenarios"]["combined/handshake"]
        scenario.update(
            endpoint_bytes=9360,
            shared_bytes=2640,
            network_pool_bytes=24980,
            network_state_bytes=2584,
        )
        name = f"xarxa-{M33}.json"
        self.write(self.current, name, current)
        self.write(self.baseline, name, current)
        rendered = MODULE.render(self.current, M33, self.baseline)
        self.assertIn("Owned xarxa workload", rendered)
        self.assertIn("All 16 network buffers | 24,980 | +0", rendered)
        self.assertIn("already included in fixture static RAM", rendered)

    def test_linked_profiles_with_changed_features_have_no_delta(self):
        current = {
            "measurement": {"target": M4, "toolchain": "rustc", "profile": "release"},
            "server": {
                "features": "server",
                "flash_bytes": 8000,
                "static_ram_bytes": 0,
            },
        }
        previous = copy.deepcopy(current)
        previous["server"]["features"] = "server,block1"
        previous["server"]["flash_bytes"] = 9000
        self.write(self.current, "sizes.json", current)
        self.write(self.baseline, "sizes.json", previous)
        rendered = MODULE.render(self.current, M4, self.baseline)
        self.assertIn("server | 8,000 | — | 0 | —", rendered)

    def test_layout_deltas_require_same_capacities_and_do_not_add_packet_pool(self):
        current = layout_report()
        previous = copy.deepcopy(current)
        previous["profiles"]["server"]["endpoint"]["total_bytes"] = 11000
        previous["profiles"]["server"]["shared"]["total_bytes"] = 208
        name = "storage-unicast.json"
        self.write(self.current, name, current)
        self.write(self.baseline, name, previous)
        rendered = MODULE.render(self.current, M4, self.baseline)
        self.assertIn("server | 12,000 | +1,000 | 104 | -104 | 2,336 | +0", rendered)
        self.assertIn("Δ = B − A", rendered)
        previous["profiles"]["server"]["capacities"]["D"] = 512
        self.write(self.baseline, name, previous)
        rendered = MODULE.render(self.current, M4, self.baseline)
        self.assertIn("server | 12,000 | — | 104 | — | 2,336 | —", rendered)

    def test_layout_compiler_change_identifies_both_builds_and_keeps_deltas(self):
        current = layout_report()
        previous = copy.deepcopy(current)
        previous["toolchain"] = "rustc previous"
        previous["profiles"]["server"]["endpoint"]["total_bytes"] = 11000
        rendered = MODULE.layout_section(current, previous)
        self.assertIn("Baseline (A) | Current (B)", rendered)
        self.assertIn("Compiler | `rustc previous` | `rustc current`", rendered)
        self.assertIn("Profile | `release` | `release`", rendered)
        self.assertIn("**Compiler changed**", rendered)
        self.assertIn("12,000 | +1,000", rendered)

    def test_host_changes_identify_both_builds_and_keep_deltas(self):
        for kind in ("stack", "linked", "layout"):
            with self.subTest(kind=kind):
                if kind == "stack":
                    current = stack_report()
                    previous = copy.deepcopy(current)
                    previous["scenarios"]["combined/handshake"]["peak_bytes"] = 6000
                    expected = "5,000 | -1,000"
                    render = MODULE.stack_section
                elif kind == "linked":
                    current = {
                        "measurement": {
                            "target": M4,
                            "toolchain": "rustc",
                            "build_host": "aarch64-unknown-linux-gnu",
                            "profile": "release",
                        },
                        "server": {
                            "features": "server",
                            "flash_bytes": 8000,
                            "static_ram_bytes": 0,
                        },
                    }
                    previous = copy.deepcopy(current)
                    previous["server"]["flash_bytes"] = 9000
                    expected = "8,000 | -1,000"
                    render = MODULE.sizes_section
                else:
                    current = layout_report()
                    previous = copy.deepcopy(current)
                    previous["profiles"]["server"]["endpoint"]["total_bytes"] = 11000
                    expected = "12,000 | +1,000"
                    render = MODULE.layout_section
                metadata = previous["measurement"] if kind == "linked" else previous
                metadata["build_host"] = "x86_64-unknown-linux-gnu"
                rendered = render(current, previous)
                self.assertIn(
                    "Build host | `x86_64-unknown-linux-gnu` | `aarch64-unknown-linux-gnu`",
                    rendered,
                )
                self.assertIn("**Build host changed**", rendered)
                self.assertIn(expected, rendered)

    def test_older_reports_show_an_unknown_host_without_losing_deltas(self):
        current = stack_report()
        previous = copy.deepcopy(current)
        del previous["build_host"]
        previous["scenarios"]["combined/handshake"]["peak_bytes"] = 6000
        rendered = MODULE.stack_section(current, previous)
        self.assertIn("Build host | — | `aarch64-unknown-linux-gnu`", rendered)
        self.assertIn("5,000 | -1,000", rendered)
        self.assertNotIn("Build host changed", rendered)

    def test_layout_profile_change_identifies_both_profiles_without_deltas(self):
        current = layout_report()
        previous = copy.deepcopy(current)
        previous["profile"] = "debug"
        previous["profiles"]["server"]["endpoint"]["total_bytes"] = 11000
        rendered = MODULE.layout_section(current, previous)
        self.assertIn("Profile | `debug` | `release`", rendered)
        self.assertIn(
            "Build configuration changed; layout deltas are unavailable", rendered
        )
        self.assertIn("server | 12,000 | — | 104 | — | 2,336 | —", rendered)

    def test_missing_layout_build_metadata_does_not_produce_deltas(self):
        for field in ("toolchain", "profile"):
            for side in ("current", "previous", "both"):
                for missing in (None, "", "  "):
                    with self.subTest(field=field, side=side, missing=missing):
                        current = layout_report()
                        previous = copy.deepcopy(current)
                        for build, name in (
                            (current, "current"),
                            (previous, "previous"),
                        ):
                            if side in (name, "both"):
                                if missing is None:
                                    del build[field]
                                else:
                                    build[field] = missing
                        rendered = MODULE.layout_section(current, previous)
                        self.assertIn(
                            "metadata missing; layout deltas are unavailable", rendered
                        )
                        self.assertIn(
                            "server | 12,000 | — | 104 | — | 2,336 | —", rendered
                        )

    def test_download_failure_keeps_current_measurements_visible(self):
        self.write(self.current, f"stack-{M33}.json", stack_report())
        output = io.StringIO()
        with (
            patch(
                "sys.argv",
                [
                    "summary",
                    "--reports",
                    str(self.current),
                    "--target",
                    M33,
                    "--fetch-baseline",
                    "--repository",
                    "owner/repo",
                ],
            ),
            patch.object(
                MODULE,
                "fetch_baseline",
                side_effect=subprocess.CalledProcessError(1, "gh"),
            ),
            contextlib.redirect_stdout(output),
        ):
            MODULE.main()
        self.assertIn("Baseline download unavailable", output.getvalue())
        self.assertIn("5,000 | — | 4,096", output.getvalue())

    def test_baseline_skips_current_pr_and_foreign_runs_and_prefers_metrics(
        self,
    ):
        runs = [
            run(9),
            run(8, event="pull_request"),
            run(7, branch="feature"),
            run(6, repository="fork/repo"),
            run(5),
        ]
        artifact = f"resource-metrics-{M4}"
        with (
            patch.object(
                MODULE,
                "gh_json",
                side_effect=[
                    {"workflow_runs": runs},
                    {"artifacts": [{"name": artifact, "expired": False}]},
                ],
            ) as api,
            patch.object(MODULE.subprocess, "run") as download,
        ):
            note = MODULE.fetch_baseline("owner/repo", M4, self.baseline, "9")
        self.assertEqual(api.call_count, 2)
        self.assertIn("runs/5/artifacts", api.call_args.args[0])
        self.assertIn("run #5", note)
        self.assertIn("commit5", note)
        self.assertIn(artifact, download.call_args.args[0])

    def test_scheduled_measurements_are_used_after_routine_runs_without_target_artifacts(
        self,
    ):
        artifact = f"resource-metrics-{M4}"
        with (
            patch.object(
                MODULE,
                "gh_json",
                side_effect=[
                    {"workflow_runs": [run(3), run(2, event="schedule")]},
                    {
                        "artifacts": [
                            {"name": f"resource-metrics-{M33}", "expired": False}
                        ]
                    },
                    {"artifacts": [{"name": artifact, "expired": False}]},
                ],
            ),
            patch.object(MODULE.subprocess, "run") as download,
        ):
            note = MODULE.fetch_baseline("owner/repo", M4, self.baseline, "4")
        self.assertIn("run #2", note)
        self.assertIn(artifact, download.call_args.args[0])

    def test_expired_artifacts_are_skipped(self):
        artifact = f"resource-metrics-{M33}"
        with (
            patch.object(
                MODULE,
                "gh_json",
                side_effect=[
                    {"workflow_runs": [run(2), run(1)]},
                    {"artifacts": [{"name": artifact, "expired": True}]},
                    {"artifacts": [{"name": artifact, "expired": False}]},
                ],
            ),
            patch.object(MODULE.subprocess, "run") as download,
        ):
            note = MODULE.fetch_baseline("owner/repo", M33, self.baseline, "3")
        self.assertIn("run #1", note)
        self.assertIn(artifact, download.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
