#!/usr/bin/env python3
"""Checks for target layout accounting, including overlapping enum storage."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import ANY, call, patch

SPEC = importlib.util.spec_from_file_location(
    "storage_layout", pathlib.Path(__file__).with_name("storage-layout.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

DWARF = """
 <0><0>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <0> DW_AT_producer : (strp) (offset: 0x0): clang LLVM (rustc version 1.99.1 (58cf8f9c3 2026-10-13))
 <1><1>: Abbrev Number: 1 (DW_TAG_base_type)
    <1> DW_AT_name : (string) u8
    <1> DW_AT_byte_size : (data1) 1
 <1><2>: Abbrev Number: 1 (DW_TAG_union_type)
    <2> DW_AT_name : (string) Alternatives
    <2> DW_AT_byte_size : (data1) 8
 <2><20>: Abbrev Number: 1 (DW_TAG_member)
    <20> DW_AT_name : (string) small
    <20> DW_AT_type : (ref4) <0x1>
 <2><21>: Abbrev Number: 1 (DW_TAG_member)
    <21> DW_AT_name : (string) other
    <21> DW_AT_type : (ref4) <0x1>
 <1><3>: Abbrev Number: 1 (DW_TAG_array_type)
    <3> DW_AT_type : (ref4) <0x1>
 <2><30>: Abbrev Number: 1 (DW_TAG_subrange_type)
    <30> DW_AT_count : (data1) 3
 <1><4>: Abbrev Number: 1 (DW_TAG_pointer_type)
    <4> DW_AT_type : (ref4) <0x5>
 <1><5>: Abbrev Number: 1 (DW_TAG_structure_type)
    <5> DW_AT_name : (strp) (offset: 0x123): Outer
    <5> DW_AT_byte_size : (data1) 20
 <2><50>: Abbrev Number: 1 (DW_TAG_member)
    <50> DW_AT_name : (string) alternatives
    <50> DW_AT_type : (ref4) <0x2>
    <50> DW_AT_data_member_location : (data1) 0
 <2><51>: Abbrev Number: 1 (DW_TAG_member)
    <51> DW_AT_name : (string) array
    <51> DW_AT_type : (ref4) <0x3>
    <51> DW_AT_data_member_location : (data1) 8
 <2><52>: Abbrev Number: 1 (DW_TAG_member)
    <52> DW_AT_name : (string) pointer
    <52> DW_AT_type : (ref4) <0x4>
    <52> DW_AT_data_member_location : (data1) 12
 <2><53>: Abbrev Number: 1 (DW_TAG_member)
    <53> DW_AT_name : (string) marker
    <53> DW_AT_type : (ref4) <0x6>
    <53> DW_AT_data_member_location : (data1) 16
 <1><6>: Abbrev Number: 1 (DW_TAG_structure_type)
    <6> DW_AT_name : (string) Marker
    <6> DW_AT_byte_size : (data1) 0
"""


def memory_runtime(multicast=False, shared_counters=False):
    lines = [
        (
            "memory layout: D=1152 "
            f"multicast={str(multicast).lower()} "
            f"shared_counters={str(shared_counters).lower()}"
        )
    ]
    for name, capacities in MODULE.PROFILES.items():
        lines.append(
            f"memory profile: name={name} "
            + " ".join(f"{key}={value}" for key, value in capacities.items())
        )
        # Layout extraction is mocked in header tests; these sizes are placeholders.
        lines.append(
            f"memory sizes: name={name} endpoint=0 shared=0 dedup=0 "
            "pool=0 response=0 security=0"
        )
    return "\n".join(lines)


class LayoutTests(unittest.TestCase):
    def test_compiler_identity_comes_from_elf_compile_units(self):
        self.assertEqual(
            MODULE.Layout(DWARF).toolchain(),
            "rustc 1.99.1 (58cf8f9c3 2026-10-13)",
        )
        self.assertEqual(
            MODULE.Layout(DWARF.replace("1.99.1", "1.98.0")).toolchain(),
            "rustc 1.98.0 (58cf8f9c3 2026-10-13)",
        )

    def test_missing_or_conflicting_elf_compilers_are_rejected(self):
        other = """
 <0><100>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <100> DW_AT_producer : (string) clang LLVM (rustc version 1.98.0 (other 2026-09-01))
"""
        for text in (
            "",
            DWARF.replace("rustc version", "unknown compiler"),
            DWARF + other,
        ):
            with (
                self.subTest(text=text),
                self.assertRaisesRegex(ValueError, "one Rust compiler"),
            ):
                MODULE.Layout(text).toolchain()

    def test_array_union_pointer_and_padding_reconcile_without_double_counting(self):
        result = MODULE.Layout(DWARF).find(lambda name: name == "Outer")
        self.assertEqual(result["total_bytes"], 20)
        self.assertEqual(result["padding_bytes"], 5)
        self.assertEqual(
            {name: member["size_bytes"] for name, member in result["fields"].items()},
            {"alternatives": 8, "array": 3, "pointer": 4, "marker": 0},
        )

    def test_missing_types_and_conflicting_layouts_fail(self):
        layout = MODULE.Layout(DWARF)
        with self.assertRaisesRegex(ValueError, "found 0"):
            layout.find(lambda name: name == "Absent")
        other = dict(layout.nodes[5])
        other["attributes"] = dict(other["attributes"], byte_size="(data1) 24")
        layout.nodes[100] = other
        with self.assertRaisesRegex(ValueError, "found 2"):
            layout.find(lambda name: name == "Outer")

    def test_member_inventory_prevents_missing_fields_becoming_padding(self):
        with self.assertRaisesRegex(ValueError, "unexpected members"):
            MODULE.Layout(DWARF).find(
                lambda name: name == "Outer",
                {"alternatives", "array", "pointer", "marker", "missing"},
            )

    def test_overlap_and_unknown_bounds_fail(self):
        with self.assertRaisesRegex(ValueError, "overlapping"):
            MODULE.Layout(DWARF.replace("(data1) 12", "(data1) 10")).find(
                lambda name: name == "Outer"
            )
        layout = MODULE.Layout(DWARF)
        del layout.nodes[0x30]["attributes"]["count"]
        with self.assertRaisesRegex(ValueError, "no constant bounds"):
            layout.find(lambda name: name == "Outer")

    def test_default_small_and_server_profiles_are_explicit(self):
        self.assertEqual(MODULE.reported_profiles(memory_runtime()), MODULE.PROFILES)

    def test_layout_header_selects_multicast_and_shared_counter_profiles(self):
        for multicast in (False, True):
            for shared_counters in (False, True):
                with self.subTest(multicast=multicast, shared_counters=shared_counters):
                    runtime = memory_runtime(multicast, shared_counters)
                    with patch.object(
                        MODULE, "_profile_report", return_value={}
                    ) as extract:
                        result = MODULE.report(
                            DWARF,
                            runtime,
                            "release opt-level=s",
                            build_host="aarch64-unknown-linux-gnu",
                        )
                    self.assertEqual(
                        result["toolchain"], "rustc 1.99.1 (58cf8f9c3 2026-10-13)"
                    )
                    self.assertEqual(result["profile"], "release opt-level=s")
                    self.assertEqual(result["build_host"], "aarch64-unknown-linux-gnu")
                    self.assertEqual(result["multicast"], multicast)
                    self.assertEqual(result["shared_counters"], shared_counters)
                    self.assertEqual(set(result["profiles"]), set(MODULE.PROFILES))
                    self.assertEqual(extract.call_count, len(MODULE.PROFILES))
                    extract.assert_has_calls(
                        [
                            call(
                                ANY,
                                runtime,
                                name,
                                capacities,
                                multicast,
                                shared_counters,
                            )
                            for name, capacities in MODULE.PROFILES.items()
                        ]
                    )

    def test_missing_invalid_and_duplicate_layout_headers_are_rejected(self):
        runtime = memory_runtime()
        header = runtime.splitlines()[0]
        for invalid in (
            runtime.replace(header, ""),
            runtime.replace(" shared_counters=false", ""),
            runtime.replace("shared_counters=false", "shared_counters=unknown"),
            runtime + "\n" + header,
        ):
            with (
                self.subTest(runtime=invalid),
                self.assertRaisesRegex(ValueError, "exactly one.*layout header"),
            ):
                MODULE.report(DWARF, invalid, "release")

    def test_cli_uses_repo_compiler_context_and_preserves_explicit_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            runtime = root / "runtime.txt"
            runtime.write_text(memory_runtime())
            for host in (None, "x86_64-unknown-linux-gnu"):
                with self.subTest(host=host):
                    args = SimpleNamespace(
                        elf=root / "image.elf",
                        runtime_log=runtime,
                        output=root / "report.json",
                        profile="release",
                        build_host=host,
                    )
                    with (
                        patch.object(
                            MODULE.argparse.ArgumentParser,
                            "parse_args",
                            return_value=args,
                        ),
                        patch.object(
                            MODULE.subprocess,
                            "check_output",
                            side_effect=["Class: ELF32\nMachine: ARM\n", DWARF],
                        ),
                        patch.object(MODULE, "_profile_report", return_value={}),
                        patch.object(
                            MODULE,
                            "rustc_metadata",
                            return_value={"build_host": "aarch64-unknown-linux-gnu"},
                        ) as compiler,
                        contextlib.redirect_stdout(io.StringIO()),
                    ):
                        MODULE.main()
                    self.assertEqual(
                        json.loads(args.output.read_text())["build_host"],
                        host or "aarch64-unknown-linux-gnu",
                    )
                    if host is None:
                        compiler.assert_called_once_with(cwd=MODULE.ROOT)
                    else:
                        compiler.assert_not_called()

    def test_empty_explicit_build_host_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "build host must not be empty"):
            MODULE.report(DWARF, memory_runtime(), "release", build_host="  ")

    def test_empty_build_profile_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "build profile must not be empty"):
            MODULE.report(DWARF, memory_runtime(), "  ")

    def test_profile_mismatch_and_duplicate_are_rejected(self):
        line = (
            "memory profile: name=server OUTBOUND=0 DEDUP=8 OBS=0 CACHED=2 "
            "SEND=2 COMMANDS=0 DEFERRED=0 BODY_CONTEXTS=0 PACKETS=2"
        )
        with self.assertRaisesRegex(ValueError, "unexpected memory capacity"):
            MODULE.reported_profiles(line)
        with self.assertRaisesRegex(ValueError, "duplicate capacity"):
            MODULE.reported_profiles(f"{line}\n{line}")

    def test_packet_pool_wire_bytes_and_metadata_reconcile(self):
        pool = {
            "total_bytes": 20,
            "fields": {
                "references": {"size_bytes": 4},
                "storage": {"size_bytes": 16},
            },
        }
        storage = {"total_bytes": 16, "fields": {"packets": {"size_bytes": 16}}}
        packet = {"total_bytes": 8}
        self.assertEqual(
            MODULE.packet_accounting(
                pool, storage, packet, datagram_bytes=6, packets=2
            ),
            {
                "pool_bytes": 20,
                "wire_capacity_bytes": 12,
                "packet_container_overhead_bytes": 4,
                "slot_metadata_bytes": 4,
                "pool_metadata_bytes": 8,
            },
        )


if __name__ == "__main__":
    unittest.main()
