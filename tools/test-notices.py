#!/usr/bin/env python3
"""Check notices for simultaneous registry and Git versions of one package."""

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "notices", pathlib.Path(__file__).with_name("notices.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NoticeTests(unittest.TestCase):
    def test_equal_name_version_from_two_sources_keeps_both_packages(self):
        root_package = {
            "name": "mai-coap",
            "version": "0.1.0",
            "source": None,
            "manifest_path": str(MODULE.ROOT / "Cargo.toml"),
            "dependencies": [{"name": "embassy-net", "kind": None}],
        }
        packages = [
            {"name": "embassy-net", "version": "0.9.1", "source": source}
            for source in (
                "registry+crates.io",
                "git+https://example.test/embassy#revision",
            )
        ]
        with (
            patch.object(MODULE, "MANIFESTS", [MODULE.ROOT / "Cargo.toml"]),
            patch.object(
                MODULE,
                "cargo",
                side_effect=[
                    json.dumps({"packages": [root_package, *packages]}),
                    "0mai-coap v0.1.0\n1embassy-net v0.9.1\n1embassy-net v0.9.1 (git)\n",
                ],
            ),
        ):
            self.assertCountEqual(MODULE.runtime_packages(), packages)

    def test_example_runtime_dependencies_include_their_features_without_test_framework(
        self,
    ):
        root = {
            "name": "mai-coap",
            "version": "0.1.0",
            "source": None,
            "manifest_path": str(MODULE.ROOT / "Cargo.toml"),
            "dependencies": [
                {"name": name, "kind": "dev"} for name in ("rand", "proptest")
            ],
        }
        packages = [
            {"name": name, "version": "1.0.0", "source": "registry"}
            for name in ("rand", "getrandom", "proptest")
        ]
        tree = "0mai-coap v0.1.0\n1proptest v1.0.0\n2rand v1.0.0\n3getrandom v1.0.0\n1rand v1.0.0\n2getrandom v1.0.0\n"
        with (
            patch.object(MODULE, "MANIFESTS", [MODULE.ROOT / "Cargo.toml"]),
            patch.object(
                MODULE,
                "cargo",
                side_effect=[json.dumps({"packages": [root, *packages]}), tree],
            ),
        ):
            self.assertCountEqual(MODULE.runtime_packages(), packages[:2])

    def test_unexpected_cargo_tree_lines_fail_in_both_prefix_modes(self):
        root = {
            "name": "mai-coap",
            "version": "0.1.0",
            "source": None,
            "manifest_path": str(MODULE.ROOT / "Cargo.toml"),
            "dependencies": [],
        }
        for manifest in (
            MODULE.ROOT / "Cargo.toml",
            MODULE.ROOT / "embedded-example/Cargo.toml",
        ):
            for tree in ("unexpected-prefix\n1rand v1.0.0\n", "├── rand v1.0.0\n"):
                with (
                    self.subTest(manifest=manifest, tree=tree),
                    patch.object(MODULE, "MANIFESTS", [manifest]),
                    patch.object(
                        MODULE,
                        "cargo",
                        side_effect=[json.dumps({"packages": [root]}), tree],
                    ),
                    self.assertRaisesRegex(ValueError, "unexpected cargo tree line"),
                ):
                    MODULE.runtime_packages()

    def test_git_workspace_license_is_read_from_its_checked_out_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            crate = root / "crate"
            crate.mkdir()
            content = "Copyright exact Git revision\nPermission is hereby granted, free of charge\n"
            (root / "LICENSE-MIT").write_text(content)
            package = {
                "name": "crate",
                "version": "0.1.0",
                "source": "git+https://example.test/repo#revision",
                "manifest_path": str(crate / "Cargo.toml"),
                "license": "MIT",
            }
            self.assertEqual(
                MODULE.license_text(package, False), ("MIT", content.strip(), None)
            )


if __name__ == "__main__":
    unittest.main()
