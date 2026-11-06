#!/usr/bin/env python3
"""Feature checks shared by local validation and CI."""

import argparse
import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
FULL = (
    "server,client,block,block1,observe,proxy,edhoc,software-crypto,multicast,discovery"
)
LEGACY_EMBASSY = "embassy-net-ipv4,embassy-net-ipv6,embassy-net/medium-ip"
XARXA = "xarxa-ipv4,xarxa-ipv6,xarxa/medium-ip"
XARXA_EMBASSY = (
    "embassy-net-xarxa-ipv4,embassy-net-xarxa-ipv6,embassy-net-xarxa/medium-ip"
)
OWNED_ADAPTERS = XARXA + "," + XARXA_EMBASSY
MIXED_OWNED_ADAPTERS = [
    "xarxa-ipv4,xarxa/medium-ip,embassy-net-xarxa-ipv6,embassy-net-xarxa/medium-ip",
    "xarxa-ipv6,xarxa/medium-ip,embassy-net-xarxa-ipv4,embassy-net-xarxa/medium-ip",
]
OWNED_FAMILY_PROFILES = [
    ",".join(f"{adapter}-{family}" for family in families) + "," + medium
    for adapter, medium in (
        ("xarxa", "xarxa/medium-ip"),
        ("embassy-net-xarxa", "embassy-net-xarxa/medium-ip"),
    )
    for families in (("ipv4",), ("ipv6",), ("ipv4", "ipv6"))
]
OWNED_BUILD_PROFILES = [
    *OWNED_FAMILY_PROFILES,
    *MIXED_OWNED_ADAPTERS,
    LEGACY_EMBASSY + "," + OWNED_ADAPTERS,
]
ADAPTERS = LEGACY_EMBASSY + "," + OWNED_ADAPTERS + ",embassy-time"
PROFILES = [
    "",
    "server",
    "server,multicast",
    "client",
    "shared-counters",
    "server,shared-counters",
    "client,shared-counters",
    "block",
    "block1",
    "observe",
    "link-format",
    "oscore",
    "edhoc",
    "software-crypto",
    "multicast",
    "discovery",
    "proxy",
    "server,oscore",
    "client,oscore",
    "server,observe",
    "client,observe,block",
    "server,block",
    "client,block",
    "server,block1",
    "client,block1",
    "embassy-net-ipv4,embassy-net/medium-ip",
    "embassy-net-ipv6,embassy-net/medium-ip",
    "embassy-net-ipv4,embassy-net/medium-ip,log",
    "embassy-net-ipv6,embassy-net/medium-ip,log",
    "embassy-net-ipv4,embassy-net/medium-ip,defmt",
    "embassy-net-ipv6,embassy-net/medium-ip,defmt",
    ADAPTERS,
    FULL,
    FULL + ",shared-counters",
    FULL + ",log",
    FULL + ",defmt",
    FULL + "," + ADAPTERS,
    *MIXED_OWNED_ADAPTERS,
]
PROFILES += [*OWNED_FAMILY_PROFILES, OWNED_ADAPTERS + ",log", OWNED_ADAPTERS + ",defmt"]

# Absent-role, absent-block1 and adapter-only cases expose test gating mistakes.
HOST_TEST_PROFILES = [
    "",
    "server",
    "server,multicast",
    "client",
    "block",
    "block1",
    "observe",
    "link-format",
    "proxy",
    "server,client,block",
    "server,client,link-format",
    "server,client,software-crypto",
    "server,client,edhoc,software-crypto,proxy",
    "embassy-net-xarxa-ipv4,embassy-net-xarxa/medium-ip",
]


def run(command, **kwargs):
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True, **kwargs)


def msrv_checks():
    if not OWNED_BUILD_PROFILES:
        raise RuntimeError("no owned-adapter MSRV profiles")
    base = ["cargo", "check", "--locked", "--lib", "--no-default-features"]
    run(base)
    run(base + ["--features", FULL + ",std," + LEGACY_EMBASSY + ",embassy-time"])
    run(base + ["--target", "thumbv6m-none-eabi", "--features", FULL])
    for features in OWNED_BUILD_PROFILES:
        for target in [[], ["--target", "thumbv6m-none-eabi"]]:
            run(base + target + ["--features", features])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--target", help="Cross-check a no_std target instead of the host"
    )
    mode.add_argument(
        "--msrv",
        action="store_true",
        help="run minimum-version profiles with the selected Rust toolchain",
    )
    parser.add_argument("--docs", action="store_true")
    parser.add_argument("--test", action="store_true")
    mode.add_argument(
        "--list-owned-profiles",
        action="store_true",
        help="print the shared owned-adapter build profiles without running checks",
    )
    args = parser.parse_args()
    if (args.msrv or args.list_owned_profiles) and (args.docs or args.test):
        parser.error("--docs/--test require the normal feature matrix")
    if args.list_owned_profiles:
        print("\n".join(OWNED_BUILD_PROFILES))
        return
    if args.msrv:
        msrv_checks()
        return
    profiles = [(features, "--lib") for features in PROFILES]
    if not args.target:
        profiles += [(features, "--tests") for features in HOST_TEST_PROFILES]
    for features, selection in profiles:
        command = [
            "cargo",
            "clippy",
            "--locked",
            selection,
            "--no-default-features",
        ]
        if args.target:
            command += ["--target", args.target]
        if features:
            command += ["--features", features]
        run(command + ["--", "-D", "warnings"])
    if not args.target:
        run(
            [
                "cargo",
                "clippy",
                "--locked",
                "--all-targets",
                "--features",
                FULL + ",shared-counters,std," + ADAPTERS + ",log",
                "--",
                "-D",
                "warnings",
            ]
        )
        run(
            [
                "cargo",
                "clippy",
                "--locked",
                "--test",
                "counters_disabled",
                "--features",
                FULL + ",std," + ADAPTERS + ",log",
                "--",
                "-D",
                "warnings",
            ]
        )
        invalid_profiles = [
            ("log,defmt", "log and defmt are mutually exclusive"),
            (
                "embassy-net,embassy-net/proto-ipv4,embassy-net/medium-ip",
                "embassy-net requires embassy-net-ipv4 or embassy-net-ipv6",
            ),
            (
                "embassy-net,embassy-net/proto-ipv6,embassy-net/medium-ip",
                "embassy-net requires embassy-net-ipv4 or embassy-net-ipv6",
            ),
            (
                "xarxa,xarxa/ipv4,xarxa/medium-ip",
                "xarxa requires xarxa-ipv4 or xarxa-ipv6 (TR-6)",
            ),
            (
                "embassy-net-xarxa,embassy-net-xarxa/ipv4,embassy-net-xarxa/medium-ip",
                "embassy-net-xarxa requires embassy-net-xarxa-ipv4 or embassy-net-xarxa-ipv6 (TR-6)",
            ),
        ]
        for features, diagnostic in invalid_profiles:
            invalid = subprocess.run(
                [
                    "cargo",
                    "check",
                    "--locked",
                    "--lib",
                    "--no-default-features",
                    "--features",
                    features,
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            if invalid.returncode == 0 or diagnostic not in invalid.stderr:
                raise RuntimeError(
                    f"{features} must fail with: {diagnostic}\n{invalid.stderr}"
                )
    if args.docs:
        for features in [
            "",
            "server",
            FULL,
            FULL + ",shared-counters",
            FULL + ",std," + ADAPTERS,
            FULL + ",defmt",
        ]:
            for private in [False, True]:
                command = [
                    "cargo",
                    "doc",
                    "--locked",
                    "--no-deps",
                    "--no-default-features",
                ]
                if features:
                    command += ["--features", features]
                if private:
                    command += ["--document-private-items"]
                run(command, env=dict(os.environ, RUSTDOCFLAGS="-D warnings"))
    if args.test:
        run(["cargo", "test", "--locked", "--features", "server,multicast", "--lib"])
        run(
            [
                "cargo",
                "test",
                "--locked",
                "--features",
                "server,observe",
                "--test",
                "server_send_acceptance",
                "--test",
                "deferred_delivery",
            ]
        )
        run(["cargo", "test", "--locked", "--features", FULL + ",std"])
        run(["cargo", "test", "--locked", "--features", FULL + ",shared-counters,std"])
        run(
            [
                "cargo",
                "test",
                "--locked",
                "--features",
                "std,server,client,observe,embassy-time," + OWNED_ADAPTERS,
                "--lib",
                "--test",
                "owned_driver",
                "--test",
                "resource_bounds",
                "--test",
                "xarxa_transport",
            ]
        )
        for features in MIXED_OWNED_ADAPTERS:
            for selection in [
                ["--lib", "transport::xarxa::tests"],
                ["--test", "xarxa_transport"],
            ]:
                run(
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--no-default-features",
                        "--features",
                        features + ",log",
                        *selection,
                    ]
                )
        run(
            [
                "cargo",
                "test",
                "--locked",
                "--features",
                "server,shared-counters",
                "--test",
                "counters",
            ]
        )
        for adapter, other_family in [
            ("embassy-net-ipv4", "proto-ipv6"),
            ("embassy-net-ipv6", "proto-ipv4"),
        ]:
            run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--lib",
                    "--no-default-features",
                    "--features",
                    f"{adapter},embassy-net/{other_family},embassy-net/medium-ip,log",
                    "transport::embassy::tests",
                ]
            )


if __name__ == "__main__":
    main()
