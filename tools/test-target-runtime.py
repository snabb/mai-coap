#!/usr/bin/env python3
"""Checks for required stack scenarios and hard regression budgets."""

import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "target_runtime", pathlib.Path(__file__).with_name("target-runtime.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def runtime_log():
    return (
        "\n".join(
            f"stack: mode={mode} phase={phase} D=1152 painted=4096 capacity=8192 client_future=2032 server_future=2032"
            for mode in ("combined", "sequential")
            for phase in ("handshake", "traffic")
        )
        + "\nstack config: id_context_bytes=0"
    )


def xarxa_log(*, owned=2, copied=8, future=368):
    return (
        "\n".join(
            [
                f"xarxa: mode={mode} phase={phase} D=1152 painted=4096 capacity=8192 client_future={future} server_future=368 endpoint=9360 shared=2640 network_pool=24980 network_state=2584 owned={owned} copied={copied}"
                for mode in ("plain", "combined", "sequential")
                for phase in ("handshake", "traffic", "non")
            ]
            + ["xarxa pool: free=16 buffers=16"] * 3
        )
        + "\nxarxa config: id_context_bytes=0"
    )


class StackTests(unittest.TestCase):
    def test_painted_peak_accepts_exact_budget(self):
        measurements = MODULE.stack_measurements(runtime_log())
        limits = {key: 4096 for key in MODULE.SCENARIOS}
        MODULE.check_budgets("target", measurements, {"target": limits})
        for value in measurements.values():
            self.assertEqual(value["peak_bytes"], 4096)
        with self.assertRaisesRegex(ValueError, "budget exceeded"):
            MODULE.check_budgets(
                "target", measurements, {"target": dict.fromkeys(limits, 4095)}
            )

    def test_recording_requires_one_numeric_context_capacity(self):
        header = "stack config: id_context_bytes=0"
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"fixture")
            for replacement in (
                "",
                header + "\n" + header,
                header.replace("=0", "=-1"),
                header.replace("=0", "=oops"),
            ):
                with (
                    self.subTest(replacement=replacement),
                    patch.object(
                        MODULE.subprocess,
                        "check_output",
                        side_effect=[
                            ".text 100 0",
                            "symbols",
                            "rustc fixture\nhost: aarch64-unknown-linux-gnu\n",
                        ],
                    ),
                    self.assertRaisesRegex(ValueError, "fixture ID Context capacity"),
                ):
                    MODULE.record_stack(
                        "thumbv7em-none-eabihf",
                        runtime_log().replace(header, replacement),
                        image,
                        output,
                        False,
                        {},
                    )

    def test_report_preserves_target_with_dot_in_artifact_names(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"elf fixture")
            target = "thumbv8m.main-none-eabihf"
            sections = ".vector_table 8 0\n.text 100 0\n.rodata 10 0\n.data 12 0\n.bss 24 0\n.uninit 8 0\n"
            with patch.object(
                MODULE.subprocess,
                "check_output",
                side_effect=[
                    sections,
                    "symbols",
                    "rustc fixture\nhost: aarch64-unknown-linux-gnu\n",
                ],
            ) as compiler_calls:
                MODULE.record_stack(target, runtime_log(), image, output, False, {})
            self.assertEqual(compiler_calls.call_args.kwargs["cwd"], MODULE.ROOT)
            for suffix in (".elf", ".json", ".txt", "-sections.txt", "-symbols.txt"):
                self.assertTrue((output / f"stack-{target}{suffix}").exists())
            report = json.loads((output / f"stack-{target}.json").read_text())
            self.assertEqual(report["build_host"], "aarch64-unknown-linux-gnu")
            self.assertEqual(report["id_context_bytes"], 0)
            self.assertEqual(report["flash_bytes"], 130)
            self.assertEqual(report["static_ram_bytes"], 44)

    def test_cargo_uses_the_same_repo_context_as_compiler_metadata(self):
        args = MODULE.parse_args(["--target", "thumbv7em-none-eabihf"])
        with (
            patch.object(MODULE, "parse_args", return_value=args),
            patch.object(
                MODULE.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess(["cargo"], 0),
                    subprocess.CompletedProcess(
                        ["qemu"], 0, "mai-coap target runtime: PASS", ""
                    ),
                ],
            ) as commands,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            MODULE.main()
        self.assertEqual(commands.call_args_list[0].args[0][:2], ["cargo", "build"])
        self.assertEqual(commands.call_args_list[0].kwargs["cwd"], MODULE.ROOT)

    def test_toolchain_version_does_not_disable_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"elf fixture")
            target = "thumbv7em-none-eabihf"
            budgets = {target: dict.fromkeys(MODULE.SCENARIOS, 4095)}
            with (
                patch.object(
                    MODULE.subprocess,
                    "check_output",
                    side_effect=[
                        ".text 100 0",
                        "symbols",
                        "rustc future\nhost: aarch64-unknown-linux-gnu\n",
                    ],
                ),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(ValueError, "budget exceeded"),
            ):
                MODULE.record_stack(target, runtime_log(), image, output, True, budgets)
            report = json.loads((output / f"stack-{target}.json").read_text())
            self.assertEqual(report["toolchain"], "rustc future")
            self.assertTrue(report["budget_enforced"])

    def test_missing_duplicate_malformed_and_invalid_measurements_fail(self):
        log = runtime_log()
        bad = [
            "",
            "\n".join(log.splitlines()[1:]),
            log + "\n" + log.splitlines()[0],
            log.replace("D=1152", "D=512"),
            log.replace("painted=4096", "painted=0"),
            log.replace("painted=4096", "painted=8000"),
            log.replace("painted=4096", "painted=oops"),
        ]
        for value in bad:
            with self.subTest(log=value), self.assertRaises(ValueError):
                MODULE.stack_measurements(value)

    def test_xarxa_reports_require_every_phase_and_complete_reclamation(self):
        lines = [
            f"xarxa: mode={mode} phase={phase} D=1152 painted=4096 capacity=8192 client_future=368 server_future=368 endpoint=9360 shared=2640 network_pool=24980 network_state=2584 owned=2 copied=8"
            for mode in ("plain", "combined", "sequential")
            for phase in ("handshake", "traffic", "non")
        ]
        log = "\n".join(lines + ["xarxa pool: free=16 buffers=16"] * 3)
        measurements = MODULE.xarxa_measurements(log)
        self.assertEqual(set(measurements), MODULE.XARXA_SCENARIOS)
        self.assertEqual(measurements["plain/non"]["network_pool_bytes"], 24980)
        limits = {"target": dict.fromkeys(MODULE.XARXA_SCENARIOS, 4096)}
        MODULE.check_budgets("target", measurements, limits, MODULE.XARXA_SCENARIOS)
        limits["target"]["plain/non"] = 4095
        with self.assertRaisesRegex(ValueError, "budget exceeded"):
            MODULE.check_budgets("target", measurements, limits, MODULE.XARXA_SCENARIOS)
        for bad in (
            log.replace("free=16", "free=15", 1),
            log.replace("D=1152", "D=512", 1),
            "\n".join(log.splitlines()[1:]),
            log + "\n" + lines[0],
            log.replace("owned=2", "owned=0"),
            log.replace("owned=2", "owned=-1", 1),
            log.replace("copied=8", "copied=-1", 1),
        ):
            with self.subTest(log=bad), self.assertRaises(ValueError):
                MODULE.xarxa_measurements(bad)

    def test_xarxa_zero_copy_and_mode_specific_owned_expectations(self):
        measurements = MODULE.xarxa_measurements(xarxa_log(copied=0))
        self.assertTrue(all(v["copied_sends"] == 0 for v in measurements.values()))
        # Counts need not be positive at every sample, but every mode must exercise ownership.
        MODULE.xarxa_measurements(xarxa_log(copied=0).replace("owned=2", "owned=0", 1))
        log = "\n".join(
            line.replace("owned=2", "owned=0") if "mode=combined " in line else line
            for line in xarxa_log().splitlines()
        )
        with self.assertRaisesRegex(ValueError, "missing xarxa owned sends: combined"):
            MODULE.xarxa_measurements(log)
        with self.assertRaisesRegex(
            ValueError, r"missing xarxa scenarios: \['plain/handshake'\]"
        ):
            MODULE.xarxa_measurements("\n".join(xarxa_log().splitlines()[1:]))

    def test_xarxa_static_accounting_records_components_and_diagnoses_residual(self):
        target = "thumbv7em-none-eabihf"
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"fixture")
            for static_ram, residual in ((39564, 0), (39568, 4)):
                with (
                    patch.object(
                        MODULE.subprocess,
                        "check_output",
                        side_effect=[
                            f".text 100 0\n.bss {static_ram} 0",
                            "symbols",
                            "rustc fixture\nhost: aarch64-unknown-linux-gnu\n",
                        ],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if residual:
                        with self.assertRaisesRegex(
                            ValueError, "accounted=39564 residual=4 bytes"
                        ):
                            MODULE.record_stack(
                                target,
                                xarxa_log(),
                                image,
                                output,
                                False,
                                {},
                                kind="xarxa",
                            )
                    else:
                        MODULE.record_stack(
                            target, xarxa_log(), image, output, False, {}, kind="xarxa"
                        )
                        report = json.loads(
                            (output / f"xarxa-{target}.json").read_text()
                        )
                        self.assertEqual(
                            report["static_accounting"],
                            {"accounted_bytes": 39564, "residual_bytes": 0},
                        )
            with (
                patch.object(
                    MODULE.subprocess,
                    "check_output",
                    side_effect=[
                        ".text 100 0\n.bss 39564 0",
                        "symbols",
                        "rustc fixture\nhost: aarch64-unknown-linux-gnu\n",
                    ],
                ),
                self.assertRaisesRegex(ValueError, "components differ"),
            ):
                MODULE.record_stack(
                    target,
                    xarxa_log().replace("endpoint=9360", "endpoint=9364", 1),
                    image,
                    output,
                    False,
                    {},
                    kind="xarxa",
                )

    def test_xarxa_future_and_static_regressions_fail_even_below_stack_budget(self):
        lines = [
            f"xarxa: mode={mode} phase={phase} D=1152 painted=4096 capacity=8192 client_future=513 server_future=368 endpoint=9360 shared=2640 network_pool=24980 network_state=2584 owned=2 copied=8"
            for mode in ("plain", "combined", "sequential")
            for phase in ("handshake", "traffic", "non")
        ]
        log = "\n".join(
            lines
            + ["xarxa pool: free=16 buffers=16"] * 3
            + ["xarxa config: id_context_bytes=0"]
        )
        budgets = {
            "stack": dict.fromkeys(MODULE.XARXA_SCENARIOS, 4096),
            "driver_future_bytes": 512,
            "static_ram_bytes": 40960,
        }
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"fixture")
            for future, ceiling, message in (
                (513, 40960, "future budget"),
                (368, 39000, "static RAM budget"),
            ):
                limits = dict(budgets, static_ram_bytes=ceiling)
                with (
                    patch.object(
                        MODULE.subprocess,
                        "check_output",
                        side_effect=[
                            ".text 100 0\n.bss 39564 0",
                            "symbols",
                            "rustc future\nhost: aarch64-unknown-linux-gnu\n",
                        ],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    MODULE.record_stack(
                        "thumbv7em-none-eabihf",
                        log.replace("client_future=513", f"client_future={future}"),
                        image,
                        output,
                        True,
                        {"thumbv7em-none-eabihf": limits},
                        kind="xarxa",
                    )
                report = json.loads(
                    (output / "xarxa-thumbv7em-none-eabihf.json").read_text()
                )
                self.assertEqual(report["static_ram_bytes"], 39564)
                self.assertTrue(report["budget_enforced"])

    def test_xarxa_resource_limits_are_target_specific(self):
        targets = MODULE.STACK_TARGETS
        budgets = {
            target: {
                "stack": dict.fromkeys(MODULE.XARXA_SCENARIOS, 4096),
                "driver_future_bytes": future,
                "static_ram_bytes": static,
            }
            for target, future, static in (
                (targets[0], 512, 40960),
                (targets[1], 768, 45056),
            )
        }
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            image = output / "image"
            image.write_bytes(b"fixture")
            for target in targets:
                with (
                    patch.object(
                        MODULE.subprocess,
                        "check_output",
                        side_effect=[
                            ".text 100 0\n.bss 39564 0",
                            "symbols",
                            "rustc fixture\nhost: aarch64-unknown-linux-gnu\n",
                        ],
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    if target == targets[0]:
                        with self.assertRaisesRegex(
                            ValueError, "future budget exceeded"
                        ):
                            MODULE.record_stack(
                                target,
                                xarxa_log(future=513),
                                image,
                                output,
                                True,
                                budgets,
                                kind="xarxa",
                            )
                    else:
                        MODULE.record_stack(
                            target,
                            xarxa_log(future=513),
                            image,
                            output,
                            True,
                            budgets,
                            kind="xarxa",
                        )
                report = json.loads((output / f"xarxa-{target}.json").read_text())
                self.assertEqual(
                    report["resource_budgets"],
                    {
                        key: value
                        for key, value in budgets[target].items()
                        if key != "stack"
                    },
                )

    def test_stack_check_rejects_conflicting_cli_options(self):
        for extra in (
            ["--features", "edhoc"],
            ["--features=stack-profile"],
            ["--features", ""],
            ["--no-default-features"],
        ):
            with (
                self.subTest(options=extra),
                contextlib.redirect_stderr(io.StringIO()) as error,
            ):
                with self.assertRaises(SystemExit) as raised:
                    MODULE.parse_args(["--stack-check", *extra])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("cannot be combined", error.getvalue())

    def test_ordinary_runtime_and_explicit_measure_only_options(self):
        self.assertEqual(MODULE.parse_args([]).features, "edhoc")
        args = MODULE.parse_args(["--features", "", "--no-default-features"])
        self.assertEqual(args.features, "")
        self.assertTrue(args.no_default_features)
        args = MODULE.parse_args(["--stack-check", "--measure-only"])
        self.assertTrue(args.measure_only)
        self.assertTrue(args.stack_check)

    def test_missing_unknown_and_invalid_budgets_fail(self):
        measurements = MODULE.stack_measurements(runtime_log())
        for limits in (
            {},
            dict.fromkeys(MODULE.SCENARIOS, 0),
            dict.fromkeys(MODULE.SCENARIOS, True),
            dict.fromkeys(MODULE.SCENARIOS | {"extra"}, 5000),
        ):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                MODULE.check_budgets("target", measurements, {"target": limits})
        with self.assertRaises(ValueError):
            MODULE.check_budgets("missing", measurements, {})


if __name__ == "__main__":
    unittest.main()
