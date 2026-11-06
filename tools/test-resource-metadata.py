#!/usr/bin/env python3
"""Check compiler-host provenance and reject incomplete rustc output."""

import unittest
from unittest.mock import patch

from resource_metadata import rustc_metadata


class MetadataTests(unittest.TestCase):
    def test_compiler_version_and_host_are_from_the_same_invocation(self):
        output = "rustc fixture\nbinary: rustc\nhost: aarch64-unknown-linux-gnu\nrelease: fixture\n"
        with (
            patch.dict("resource_metadata.os.environ", {}, clear=True),
            patch(
                "resource_metadata.subprocess.check_output", return_value=output
            ) as command,
        ):
            self.assertEqual(
                rustc_metadata(),
                {
                    "toolchain": "rustc fixture",
                    "build_host": "aarch64-unknown-linux-gnu",
                },
            )
            command.assert_called_once_with(["rustc", "-vV"], text=True, cwd=None)

    def test_build_directory_and_configured_compiler_are_forwarded(self):
        with (
            patch.dict("resource_metadata.os.environ", {"RUSTC": "/toolchain/rustc"}),
            patch(
                "resource_metadata.subprocess.check_output",
                return_value="rustc fixture\nhost: test-host\n",
            ) as command,
        ):
            self.assertEqual(rustc_metadata(cwd="/checkout")["build_host"], "test-host")
            command.assert_called_once_with(
                ["/toolchain/rustc", "-vV"], text=True, cwd="/checkout"
            )

    def test_incomplete_or_ambiguous_identity_is_rejected(self):
        for output in (
            "",
            "rustc fixture\n",
            "rustc fixture\nhost: \n",
            "other compiler\nhost: aarch64-unknown-linux-gnu\n",
            "rustc fixture\nhost: one\nhost: two\n",
        ):
            with (
                self.subTest(output=output),
                patch("resource_metadata.subprocess.check_output", return_value=output),
                self.assertRaisesRegex(ValueError, "compiler and its build host"),
            ):
                rustc_metadata()


if __name__ == "__main__":
    unittest.main()
