#!/usr/bin/env python3
"""Break down the Cortex-M4 memory-layout fixture's storage using its ELF DWARF."""

import argparse
import itertools
import json
import pathlib
import re
import subprocess

from resource_metadata import rustc_metadata

ROOT = pathlib.Path(__file__).resolve().parents[1]


class Layout:
    def __init__(self, text):
        self.nodes = {}
        self.sizes = {}
        parents = []
        node = None
        for line in text.splitlines():
            header = re.match(
                r"\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?",
                line,
            )
            if header:
                depth = int(header[1])
                parents = parents[:depth]
                node = None
                if header[3]:
                    node = {"tag": header[3], "attributes": {}, "children": []}
                    self.nodes[int(header[2], 16)] = node
                    if parents:
                        parents[-1]["children"].append(node)
                    parents.append(node)
            elif node is not None:
                attribute = re.search(r"DW_AT_(\w+)\s*:\s*(.*)", line)
                if attribute:
                    node["attributes"][attribute[1]] = attribute[2]

    @staticmethod
    def name(node):
        raw = node["attributes"].get("name", "")
        return re.sub(r"^(?:\([^)]*\)\s*)+:?\s*", "", raw)

    def toolchain(self):
        versions = {
            f"rustc {match[1]}"
            for node in self.nodes.values()
            if node["tag"] == "DW_TAG_compile_unit"
            and (
                match := re.search(
                    r"\(rustc version (.+)\)$",
                    node["attributes"].get("producer", ""),
                )
            )
        }
        if len(versions) != 1:
            raise ValueError("expected exactly one Rust compiler in ELF DWARF")
        return versions.pop()

    @staticmethod
    def number(node, attribute):
        raw = node["attributes"][attribute]
        value = re.sub(r"^\([^)]*\)\s*", "", raw)
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"unsupported DW_AT_{attribute}: {raw}") from error

    def referenced(self, node):
        match = re.search(r"<0x([0-9a-f]+)>", node["attributes"].get("type", ""))
        if not match:
            raise ValueError(f"missing type reference: {self.name(node)}")
        return self.nodes[int(match[1], 16)]

    def size(self, node):
        key = id(node)
        if key in self.sizes:
            return self.sizes[key]
        attributes = node["attributes"]
        if "byte_size" in attributes:
            size = self.number(node, "byte_size")
        elif node["tag"] == "DW_TAG_pointer_type":
            size = 4
        elif node["tag"] == "DW_TAG_array_type":
            size = self.size(self.referenced(node))
            ranges = [c for c in node["children"] if c["tag"] == "DW_TAG_subrange_type"]
            if not ranges:
                raise ValueError("array has no bounds")
            for bounds in ranges:
                if "count" in bounds["attributes"]:
                    count = self.number(bounds, "count")
                elif "upper_bound" in bounds["attributes"]:
                    lower = (
                        self.number(bounds, "lower_bound")
                        if "lower_bound" in bounds["attributes"]
                        else 0
                    )
                    count = self.number(bounds, "upper_bound") - lower + 1
                else:
                    raise ValueError("array has no constant bounds")
                if count < 0:
                    raise ValueError("negative array bound")
                size *= count
        elif node["tag"] in (
            "DW_TAG_typedef",
            "DW_TAG_const_type",
            "DW_TAG_volatile_type",
        ):
            size = self.size(self.referenced(node))
        else:
            raise ValueError(f"missing byte size: {node['tag']} {self.name(node)}")
        self.sizes[key] = size
        return size

    def structure(self, node):
        total = self.size(node)
        fields = {}
        occupied = []
        for member in node["children"]:
            if member["tag"] != "DW_TAG_member":
                continue
            name = self.name(member)
            if not name or name in fields:
                raise ValueError("missing or duplicate member name")
            offset = self.number(member, "data_member_location")
            size = self.size(self.referenced(member))
            if offset < 0 or offset + size > total:
                raise ValueError(f"member outside structure: {name}")
            fields[name] = {"offset_bytes": offset, "size_bytes": size}
            if size:
                occupied.append((offset, offset + size))
        if not fields:
            raise ValueError(f"no members in {self.name(node)}")
        occupied.sort()
        if any(left[1] > right[0] for left, right in itertools.pairwise(occupied)):
            raise ValueError(f"overlapping structure members: {self.name(node)}")
        return {
            "total_bytes": total,
            "padding_bytes": total - sum(f["size_bytes"] for f in fields.values()),
            "fields": fields,
        }

    def find(self, predicate, expected_members=None):
        layouts = {}
        unexpected = []
        for node in self.nodes.values():
            if (
                node["tag"] != "DW_TAG_structure_type"
                or "byte_size" not in node["attributes"]
            ):
                continue
            if predicate(self.name(node)):
                result = self.structure(node)
                if (
                    expected_members is not None
                    and set(result["fields"]) != expected_members
                ):
                    unexpected.append((self.name(node), sorted(result["fields"])))
                    continue
                layouts[json.dumps(result, sort_keys=True)] = result
        # The same concrete type can have equivalent DIEs in several compile units.
        if len(layouts) != 1:
            if not layouts and unexpected:
                raise ValueError(
                    f"unexpected members in {unexpected[0][0]}: {unexpected[0][1]}"
                )
            raise ValueError(f"expected one concrete layout, found {len(layouts)}")
        return next(iter(layouts.values()))


PROFILES = {
    "default": {
        "OUTBOUND": 8,
        "DEDUP": 32,
        "OBS": 8,
        "CACHED": 8,
        "SEND": 16,
        "COMMANDS": 8,
        "DEFERRED": 8,
        "BODY_CONTEXTS": 8,
        "PACKETS": 40,
    },
    "small": {
        "OUTBOUND": 4,
        "DEDUP": 16,
        "OBS": 4,
        "CACHED": 4,
        "SEND": 4,
        "COMMANDS": 4,
        "DEFERRED": 4,
        "BODY_CONTEXTS": 4,
        "PACKETS": 16,
    },
    "server": {
        "OUTBOUND": 0,
        "DEDUP": 8,
        "OBS": 0,
        "CACHED": 2,
        "SEND": 2,
        "COMMANDS": 0,
        "DEFERRED": 0,
        "BODY_CONTEXTS": 0,
        "PACKETS": 2,
    },
}


def packet_accounting(pool, storage, packet, datagram_bytes, packets):
    container = packet["total_bytes"]
    if storage["fields"]["packets"]["size_bytes"] != packets * container:
        raise ValueError("packet storage does not match fixture capacity")
    if container < datagram_bytes:
        raise ValueError("packet storage is smaller than its wire capacity")
    if pool["fields"]["storage"]["size_bytes"] != storage["total_bytes"]:
        raise ValueError("packet backing storage size mismatch")
    if pool["fields"]["references"]["size_bytes"] != packets * 2:
        raise ValueError("packet metadata does not match fixture capacity")
    pool_bytes = pool["total_bytes"]
    wire_bytes = datagram_bytes * packets
    if pool_bytes < wire_bytes:
        raise ValueError("packet pool is smaller than its wire capacity")
    return {
        "pool_bytes": pool_bytes,
        "wire_capacity_bytes": wire_bytes,
        "packet_container_overhead_bytes": (container - datagram_bytes) * packets,
        "slot_metadata_bytes": pool["fields"]["references"]["size_bytes"],
        "pool_metadata_bytes": pool_bytes - wire_bytes,
    }


def reported_profiles(runtime):
    found = re.findall(
        r"memory profile: name=(default|small|server) OUTBOUND=(\d+) DEDUP=(\d+) OBS=(\d+) CACHED=(\d+) SEND=(\d+) COMMANDS=(\d+) DEFERRED=(\d+) BODY_CONTEXTS=(\d+) PACKETS=(\d+)",
        runtime,
    )
    profiles = {}
    for name, *values in found:
        if name in profiles:
            raise ValueError(f"duplicate capacity report for {name}")
        profiles[name] = dict(zip(PROFILES[name], map(int, values), strict=True))
    if profiles != PROFILES:
        raise ValueError(f"unexpected memory capacity reports: {profiles}")
    return profiles


def _profile_report(
    layout, runtime, profile_name, capacities, multicast, shared_counters
):
    datagram = 1152
    outbound = capacities["OUTBOUND"]
    dedup = capacities["DEDUP"]
    observers = capacities["OBS"]
    cached = capacities["CACHED"]
    send = capacities["SEND"]
    commands = capacities["COMMANDS"]
    deferred = capacities["DEFERRED"]
    body_contexts = capacities["BODY_CONTEXTS"]
    packets = capacities["PACKETS"]
    consts = (
        datagram,
        outbound,
        dedup,
        observers,
        cached,
        send,
        commands,
        deferred,
        body_contexts,
        packets,
    )
    generic_args = ", ".join(map(str, consts))
    endpoint_name = (
        "Endpoint<mai_coap::edhoc::endpoint::Edhoc<"
        "mai_coap::crypto::software::SoftwareCrypto<mai_coap_target_tests::TestRng>, "
        f"4, 4, mai_coap::edhoc::TrustedPeers<16>, 255>, {generic_args}, mai_coap::packet_pool::InlineStorage<{datagram}, {packets}>>"
    )
    endpoint_members = {
        "shared",
        "protection",
        "duplicates",
        "exchanges",
        "deferred",
        "outgoing",
        "in_send_window",
        "pool",
        "storage_retry",
        "send_policy",
        "send_retry",
        "send_backoff_ms",
        "storage_backoff_ms",
        "storage_reclaim_blocked",
        "next_ticket",
        "ids",
        "parameters",
        "counters",
        "limiter",
        "body_epochs",
        "probes",
        "backoff",
        "observers",
    } | ({"leisure"} if multicast else set())
    endpoint = layout.find(lambda name: name == endpoint_name, endpoint_members)
    shared = layout.find(
        lambda name: name == f"Shared<{datagram}, {commands}>", {"state"}
    )
    state_members = {
        "slots",
        "driver",
        "revision",
        "body_sequence",
        "changes",
    } | ({"counters"} if shared_counters else set())
    state = layout.find(
        lambda name: name == f"SharedState<{datagram}, {commands}>", state_members
    )
    slot_members = {
        "generation",
        "data",
        "active",
        "cancelled",
        "waker",
    } | ({"replies"} if multicast else set())
    slot = layout.find(lambda name: name == f"Slot<{datagram}>", slot_members)
    packet_pool = layout.find(
        lambda name: (
            name
            == f"PacketPool<{datagram}, {packets}, mai_coap::packet_pool::InlineStorage<{datagram}, {packets}>>"
        ),
        {"references", "storage"},
    )
    packet_storage = layout.find(
        lambda name: name == f"InlineStorage<{datagram}, {packets}>", {"packets"}
    )
    packet = layout.find(lambda name: name == f"Packet<{datagram}>", {"bytes"})
    dedup_type = f"Deduplication<{dedup}, {cached}>"
    dedup_layout = layout.find(lambda name: name == dedup_type, {"entries"})
    response = layout.find(
        lambda name: name == f"Response<{datagram}>",
        {"code", "options", "values", "payload"},
    )
    match = re.search(
        rf"memory sizes: name={profile_name} endpoint=(\d+) shared=(\d+) dedup=(\d+) pool=(\d+) response=(\d+) security=(\d+)",
        runtime,
    )
    if not match:
        raise ValueError(f"missing runtime size report for {profile_name}")
    measured = tuple(map(int, match.groups()))
    extracted = (
        endpoint["total_bytes"],
        shared["total_bytes"],
        endpoint["fields"]["duplicates"]["size_bytes"],
        endpoint["fields"]["pool"]["size_bytes"],
        response["total_bytes"],
        endpoint["fields"]["protection"]["size_bytes"],
    )
    if extracted != measured:
        raise ValueError(
            f"{profile_name} DWARF/runtime mismatch: {extracted} != {measured}"
        )
    if dedup_layout["total_bytes"] != extracted[2]:
        raise ValueError(f"{profile_name} duplicate table type does not match endpoint")
    if state["fields"]["slots"]["size_bytes"] != commands * slot["total_bytes"]:
        raise ValueError(f"{profile_name} command slots do not match capacity")
    pool_breakdown = packet_accounting(
        packet_pool, packet_storage, packet, datagram, packets
    )
    if packet_pool["total_bytes"] != extracted[3]:
        raise ValueError(f"{profile_name} packet pool type does not match endpoint")
    endpoint_pool_bytes = endpoint["fields"]["pool"]["size_bytes"]
    return {
        "capacities": {"D": datagram, **capacities},
        "endpoint": endpoint,
        "endpoint_breakdown": {
            "packet_pool_bytes": endpoint_pool_bytes,
            "non_pool_state_bytes": endpoint["total_bytes"] - endpoint_pool_bytes,
        },
        "shared": shared,
        "shared_state": state,
        "command_slot": slot,
        "deduplication": dedup_layout,
        "packet_pool": packet_pool,
        "packet_storage": packet_storage,
        "packet": packet,
        "packet_accounting": pool_breakdown,
        "response": response,
    }


def report(text, runtime, profile, *, build_host=None):
    if not profile.strip():
        raise ValueError("build profile must not be empty")
    if build_host is not None and not build_host.strip():
        raise ValueError("build host must not be empty")
    layout = Layout(text)
    header = re.findall(
        r"memory layout: D=1152 multicast=(true|false) shared_counters=(true|false)",
        runtime,
    )
    if len(header) != 1:
        raise ValueError("expected exactly one memory-layout fixture layout header")
    multicast = header[0][0] == "true"
    shared_counters = header[0][1] == "true"
    reported_profiles(runtime)
    for name in PROFILES:
        if len(re.findall(rf"memory sizes: name={name} ", runtime)) != 1:
            raise ValueError(f"expected exactly one runtime size report for {name}")
    return {
        "target": "thumbv7em-none-eabihf",
        "toolchain": layout.toolchain(),
        "build_host": build_host,
        "profile": profile,
        "multicast": multicast,
        "shared_counters": shared_counters,
        "profiles": {
            name: _profile_report(
                layout, runtime, name, capacities, multicast, shared_counters
            )
            for name, capacities in PROFILES.items()
        },
        "boundary": "Target ABI layouts including collection metadata and padding. Nested rows are included in parent totals. Enum alternatives overlap and are reported once through their containing field. Packet wire capacity is separated from pool and endpoint metadata. Excludes runtime stack, network/executor storage and application I/O.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=pathlib.Path)
    parser.add_argument("--runtime-log", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--profile",
        required=True,
        help="profile and build settings used for the ELF, including any overrides",
    )
    parser.add_argument(
        "--build-host",
        help="host triple of the compiler that built the ELF (default: repository rustc host); override for an ELF built elsewhere",
    )
    args = parser.parse_args()
    header = subprocess.check_output(
        ["readelf", "--file-header", str(args.elf)], text=True
    )
    if not re.search(r"Class:\s+ELF32", header) or not re.search(
        r"Machine:\s+ARM\s*$", header, re.MULTILINE
    ):
        raise ValueError("expected a 32-bit ARM ELF")
    text = subprocess.check_output(
        ["readelf", "--debug-dump=info", "--wide", str(args.elf)], text=True
    )
    result = report(
        text,
        args.runtime_log.read_text(),
        args.profile,
        build_host=args.build_host
        if args.build_host is not None
        else rustc_metadata(cwd=ROOT)["build_host"],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
