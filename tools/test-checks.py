#!/usr/bin/env python3
"""Checks for feature profiles shared by local checks and CI."""

import contextlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "checks", pathlib.Path(__file__).with_name("checks.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProfileTests(unittest.TestCase):
    def test_printed_owned_profiles_include_families_mixed_and_coexisting_adapters(
        self,
    ):
        profiles = subprocess.check_output(
            [
                sys.executable,
                str(MODULE.ROOT / "tools/checks.py"),
                "--list-owned-profiles",
            ],
            text=True,
        ).splitlines()
        self.assertEqual(profiles, MODULE.OWNED_BUILD_PROFILES)
        self.assertEqual(len(profiles), len(set(profiles)))
        self.assertEqual(len(profiles), 9)
        for adapter, medium in (
            ("xarxa", "xarxa/medium-ip"),
            ("embassy-net-xarxa", "embassy-net-xarxa/medium-ip"),
        ):
            for families in (("ipv4",), ("ipv6",), ("ipv4", "ipv6")):
                profile = (
                    ",".join(f"{adapter}-{family}" for family in families)
                    + ","
                    + medium
                )
                self.assertIn(profile, profiles)
                self.assertIn(profile, MODULE.PROFILES)
        for profile in MODULE.MIXED_OWNED_ADAPTERS:
            self.assertIn(profile, profiles)
            self.assertIn(profile, MODULE.PROFILES)
        self.assertIn(MODULE.LEGACY_EMBASSY + "," + MODULE.OWNED_ADAPTERS, profiles)

    def test_logging_profiles_compile_both_owned_adapters_without_duplicate_combinations(
        self,
    ):
        self.assertEqual(len(MODULE.PROFILES), len(set(MODULE.PROFILES)))
        for logging in ("log", "defmt"):
            self.assertIn(MODULE.OWNED_ADAPTERS + "," + logging, MODULE.PROFILES)


class MsrvTests(unittest.TestCase):
    def test_msrv_checks_core_full_and_every_owned_adapter_on_host_and_m0(self):
        with patch.object(MODULE, "run") as run:
            MODULE.msrv_checks()
        commands = [item.args[0] for item in run.call_args_list]
        base = ["cargo", "check", "--locked", "--lib", "--no-default-features"]
        self.assertEqual(commands[0], base)
        self.assertEqual(
            commands[1],
            base
            + [
                "--features",
                MODULE.FULL + ",std," + MODULE.LEGACY_EMBASSY + ",embassy-time",
            ],
        )
        self.assertEqual(
            commands[2],
            base + ["--target", "thumbv6m-none-eabi", "--features", MODULE.FULL],
        )
        self.assertEqual(len(commands), 3 + 2 * len(MODULE.OWNED_BUILD_PROFILES))
        for profile in MODULE.OWNED_BUILD_PROFILES:
            self.assertIn(base + ["--features", profile], commands)
            self.assertIn(
                base + ["--target", "thumbv6m-none-eabi", "--features", profile],
                commands,
            )

    def test_missing_owned_profiles_fail_before_running_any_checks(self):
        with (
            patch.object(MODULE, "OWNED_BUILD_PROFILES", []),
            patch.object(MODULE, "run") as run,
            self.assertRaisesRegex(RuntimeError, "no owned-adapter"),
        ):
            MODULE.msrv_checks()
        run.assert_not_called()

    def test_msrv_mode_dispatches_without_the_normal_matrix(self):
        with (
            patch.object(sys, "argv", ["checks.py", "--msrv"]),
            patch.object(MODULE, "msrv_checks") as msrv,
            patch.object(MODULE, "run") as run,
        ):
            MODULE.main()
        msrv.assert_called_once_with()
        run.assert_not_called()

    def test_msrv_mode_rejects_conflicting_or_ignored_options(self):
        for options in [
            ["--target", "thumbv6m-none-eabi"],
            ["--docs"],
            ["--test"],
            ["--list-owned-profiles"],
        ]:
            with (
                patch.object(sys, "argv", ["checks.py", "--msrv", *options]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as error,
            ):
                MODULE.main()
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
