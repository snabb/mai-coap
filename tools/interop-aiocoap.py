#!/usr/bin/env python3
"""Black-box aiocoap 0.4.17 tests using documented APIs and RFC 9529 test keys.

Run with: uv run --with 'aiocoap[oscore]==0.4.17' tools/interop-aiocoap.py
The fixed keys below are test vectors and must never secure application traffic.
"""

import argparse
import asyncio
import errno
import json
import logging
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

import aiocoap
import aiocoap.credentials
import cbor2
from aiocoap import resource
from aiocoap.oscore_sitewrapper import OscoreSiteWrapper
from aiocoap.proxy.client import ProxyForwarder

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests/fixtures/rfc9529.json").read_text())


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Process:
    def __init__(self, args, port=None, env=None):
        self.args = args
        self.port = port
        self.env = env

    def __enter__(self):
        self.child = subprocess.Popen(
            self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env
        )
        if self.port is not None:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and self.child.poll() is None:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind(("127.0.0.1", self.port))
                    except OSError as error:
                        if error.errno == errno.EADDRINUSE:
                            return self.child
                        raise
                time.sleep(0.01)
            self.__exit__(None, None, None)
            raise RuntimeError(f"peer readiness deadline: {self.stderr!r}")
        if not select.select([self.child.stdout], [], [], 10)[0]:
            self.__exit__(None, None, None)
            raise RuntimeError("server readiness deadline")
        line = self.child.stdout.readline()
        if not line.startswith(b"LISTEN "):
            self.__exit__(None, None, None)
            raise RuntimeError(f"server failed to start: {line!r} {self.stderr!r}")
        return self.child

    def __exit__(self, *_):
        failed = self.child.poll() not in (None, 0)
        if self.child.poll() is None:
            self.child.terminate()
        try:
            _, self.stderr = self.child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.child.kill()
            _, self.stderr = self.child.communicate(timeout=5)
        if failed:
            print(self.stderr.decode(errors="replace"), file=sys.stderr)


def identity_files(directory, role, profile):
    if profile == "minimal-ccs":
        name = "client-kid-01" if role == "i" else "node-empty-kid"
        ccs = (ROOT / f"tests/fixtures/{name}.ccs").read_bytes()
    else:
        ccs = bytes.fromhex(VECTORS[f"cred_{role}"])
    private = bytes.fromhex(VECTORS[f"sk_{role}"])
    ccs_path = directory / f"{role}.ccs"
    private_path = directory / f"{role}.raw"
    key_path = directory / f"{role}.cosekey"
    ccs_path.write_bytes(ccs)
    private_path.write_bytes(private)
    key = {1: 2, -1: 1, -4: private}
    key_path.write_bytes(cbor2.dumps(key))
    os.chmod(private_path, 0o600)
    os.chmod(key_path, 0o600)
    return ccs_path, private_path, key_path


def edhoc_credentials(origin, directory, role, server=False, combined=True):
    other = "r" if role == "i" else "i"
    own = {14: cbor2.loads((directory / f"{role}.ccs").read_bytes())}
    peer = {14: cbor2.loads((directory / f"{other}.ccs").read_bytes())}
    own_settings = {
        "suite": 2,
        "method": 3,
        "own_cred_style": "by-key-id",
        "own_cred": own,
        "private_key_file": str(directory / f"{role}.cosekey"),
    }
    if not server:
        own_settings["peer_cred"] = peer
        own_settings["use_combined_edhoc"] = combined
    values = {origin + "/*": {"edhoc-oscore": own_settings}}
    if server:
        values[":peer"] = {"edhoc-oscore": {"suite": 2, "method": 3, "peer_cred": peer}}
    credentials = aiocoap.credentials.CredentialsMap()
    credentials.load_from_dict(values)
    return credentials


async def independent_client(directory, combined, host, xarxa=False):
    port = free_port()
    origin = f"coap://{host}:{port}"
    server = ROOT / "target/debug/examples/secured-server"
    command = [
        str(server),
        # Hostname resolution may prefer either loopback address family.
        f"127.0.0.1:{port}" if xarxa else f"[::]:{port}",
        str(directory / "r.ccs"),
        str(directory / "r.raw"),
        str(directory / "i.ccs"),
    ]
    with Process(
        command, env=dict(os.environ, MAI_COAP_XARXA=xarxa) if xarxa else None
    ):
        context = await aiocoap.Context.create_client_context(
            transports=["oscore", "udp6"]
        )
        interface = context
        try:
            denied = await asyncio.wait_for(
                interface.request(
                    aiocoap.Message(code=aiocoap.GET, uri=origin + "/hello")
                ).response,
                8,
            )
            assert denied.code == aiocoap.UNAUTHORIZED
            context.client_credentials = edhoc_credentials(
                origin, directory, "i", combined=combined
            )
            response = await asyncio.wait_for(
                interface.request(
                    aiocoap.Message(code=aiocoap.GET, uri=origin + "/hello")
                ).response,
                10,
            )
            assert response.payload == b"hello secured", (
                response.code,
                response.payload,
            )
            payload = b"protected POST"
            response = await asyncio.wait_for(
                interface.request(
                    aiocoap.Message(
                        code=aiocoap.POST,
                        uri=origin + "/echo",
                        payload=payload,
                        content_format=0,
                    )
                ).response,
                10,
            )
            assert response.code.is_successful() and response.payload == payload
            for szx in [0, 6]:
                message = aiocoap.Message(code=aiocoap.GET, uri=origin + "/large")
                message.opt.block2 = (0, False, szx)
                response = await asyncio.wait_for(
                    interface.request(message).response, 10
                )
                assert response.payload == b"z" * 3000
            message = aiocoap.Message(
                code=aiocoap.GET, uri=origin + "/clock", observe=0
            )
            observation = context.request(message)
            first = await asyncio.wait_for(observation.response, 10)
            assert first.opt.observe is not None
            values = [int(first.payload)]
            async with asyncio.timeout(5):
                async for notification in observation.observation:
                    values.append(int(notification.payload))
                    if len(values) == 4:
                        break
            observation.observation.cancel()
            assert values == sorted(set(values)), values
        finally:
            await context.shutdown()
    print(
        f"aiocoap client -> mai-coap server: combined={combined}, host={host}, transport={xarxa or 'linux'}: PASS",
        flush=True,
    )


class Echo(resource.Resource):
    async def render_get(self, request):
        assert request.remote.authenticated_claims
        return aiocoap.Message(payload=b"hello secured", content_format=0)

    async def render_post(self, request):
        assert request.remote.authenticated_claims
        return aiocoap.Message(
            code=aiocoap.CHANGED, payload=request.payload, content_format=0
        )


class Large(resource.Resource):
    async def render_get(self, request):
        assert request.remote.authenticated_claims
        return aiocoap.Message(payload=b"z" * 3000, content_format=0, etag=b"fixed")


class Clock(resource.ObservableResource):
    def __init__(self):
        super().__init__()
        self.value = 0

    async def render_get(self, request):
        assert request.remote.authenticated_claims
        return aiocoap.Message(
            payload=str(self.value).encode(), max_age=1, content_format=0
        )

    async def tick(self):
        while True:
            await asyncio.sleep(0.3)
            self.value += 1
            self.updated_state()


async def independent_server(directory, combined):
    port = free_port()
    origin = f"coap://127.0.0.1:{port}"
    site = resource.Site()
    site.add_resource(["hello"], Echo())
    site.add_resource(["echo"], Echo())
    site.add_resource(["large"], Large())
    clock = Clock()
    site.add_resource(["clock"], clock)
    credentials = edhoc_credentials(origin, directory, "r", server=True)
    context = await aiocoap.Context.create_server_context(
        OscoreSiteWrapper(site, credentials),
        bind=("127.0.0.1", port),
        server_credentials=credentials,
        transports=["oscore", "udp6"],
    )
    ticker = asyncio.create_task(clock.tick())
    try:
        base = [
            str(ROOT / "target/debug/examples/secured-client"),
            f"127.0.0.1:{port}",
            str(directory / "i.ccs"),
            str(directory / "i.raw"),
            str(directory / "r.ccs"),
            str(combined).lower(),
        ]
        for args, expected in [
            (["/hello"], b"hello secured"),
            (["/echo", "protected POST"], b"protected POST"),
            (["/large"], b"z" * 3000),
            (["/clock", "observe"], None),
        ]:
            child = await asyncio.create_subprocess_exec(
                *base,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(child.communicate(), 15)
            except BaseException:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
                raise
            assert child.returncode == 0, stderr.decode()
            if expected is not None:
                assert stdout == expected, (len(stdout), stderr.decode())
            else:
                values = [int(line) for line in stdout.splitlines()]
                assert len(values) == 3 and values == sorted(set(values)), values
    finally:
        ticker.cancel()
        await asyncio.gather(ticker, return_exceptions=True)
        await context.shutdown()
    print(f"mai-coap client -> aiocoap server: combined={combined}: PASS", flush=True)


class PublicEcho(resource.Resource):
    async def render_get(self, request):
        return aiocoap.Message(payload=b"public through proxy", content_format=0)

    async def render_post(self, request):
        return aiocoap.Message(
            code=aiocoap.CHANGED, payload=request.payload, content_format=0
        )


async def run_cli(arguments, timeout=30):
    child = await asyncio.create_subprocess_exec(
        str(ROOT / "cli/target/debug/mai-coap"),
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(child.communicate(), timeout)
    except BaseException:
        if child.returncode is None:
            child.kill()
            await child.wait()
        raise
    return child.returncode, stdout, stderr.decode()


async def command_line_client(directory, combined):
    port = free_port()
    origin = f"coap://127.0.0.1:{port}"
    site = resource.Site()
    site.add_resource(["hello"], Echo())
    site.add_resource(["echo"], Echo())
    site.add_resource(["large"], Large())
    clock = Clock()
    site.add_resource(["clock"], clock)
    credentials = edhoc_credentials(origin, directory, "r", server=True)
    context = await aiocoap.Context.create_server_context(
        OscoreSiteWrapper(site, credentials),
        bind=("127.0.0.1", port),
        server_credentials=credentials,
        transports=["oscore", "udp6"],
    )
    ticker = asyncio.create_task(clock.tick())
    secured = [
        "--identity",
        str(directory / "i.ccs"),
        "--key",
        str(directory / "i.raw"),
        "--peer",
        str(directory / "r.ccs"),
    ]
    if not combined:
        secured.append("--sequential-edhoc")
    try:
        code, stdout, stderr = await run_cli([*secured, f"{origin}/hello"])
        assert (code, stdout) == (0, b"hello secured"), (code, stdout, stderr)
        code, stdout, stderr = await run_cli(
            [*secured, "-m", "post", "-t", "plain", "-e", "sealed", f"{origin}/echo"]
        )
        assert (code, stdout) == (0, b"sealed"), (code, stdout, stderr)
        code, stdout, stderr = await run_cli([*secured, f"{origin}/large"])
        assert (code, stdout) == (0, b"z" * 3000), (code, len(stdout), stderr)
        code, stdout, stderr = await run_cli(
            [*secured, "-s", "2", "-w", f"{origin}/clock"]
        )
        values = [int(line) for line in stdout.splitlines()]
        assert code == 0 and len(values) >= 2, (code, stdout, stderr)
        assert values == sorted(set(values)), values
        code, stdout, stderr = await run_cli(
            [*secured, "-B", "20", f"{origin}/no-such-resource"]
        )
        assert code == 1 and "4.04" in stderr, (code, stdout, stderr)
    finally:
        ticker.cancel()
        await asyncio.gather(ticker, return_exceptions=True)
        await context.shutdown()
    print(f"mai-coap CLI -> aiocoap server: combined={combined}: PASS", flush=True)


async def independent_proxy(directory, combined):
    origin_port = free_port()
    proxy_port = free_port()
    origin = f"coap://127.0.0.1:{origin_port}"
    proxy = f"127.0.0.1:{proxy_port}"
    peer_proxy = str(pathlib.Path(sys.executable).with_name("aiocoap-proxy"))
    env = dict(
        os.environ, AIOCOAP_SERVER_TRANSPORT="udp6", AIOCOAP_CLIENT_TRANSPORT="udp6"
    )
    server = [
        str(ROOT / "target/debug/examples/secured-server"),
        f"127.0.0.1:{origin_port}",
        str(directory / "r.ccs"),
        str(directory / "r.raw"),
        str(directory / "i.ccs"),
    ]
    with (
        Process(server),
        Process([peer_proxy, "--forward", "--bind", proxy], port=proxy_port, env=env),
    ):
        base = [
            str(ROOT / "target/debug/examples/secured-client"),
            proxy,
            str(directory / "i.ccs"),
            str(directory / "i.raw"),
            str(directory / "r.ccs"),
            str(combined).lower(),
        ]
        for args, expected in [
            ([origin + "/hello"], b"hello secured"),
            ([origin + "/echo", "through proxy"], b"through proxy"),
        ]:
            child = await asyncio.create_subprocess_exec(
                *base,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(child.communicate(), 15)
            except BaseException:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
                raise
            assert child.returncode == 0, stderr.decode()
            assert stdout == expected
    print(
        f"mai-coap client -> aiocoap proxy -> mai-coap server: combined={combined}: PASS",
        flush=True,
    )
    origin_port = free_port()
    proxy_port = free_port()
    origin = f"coap://localhost:{origin_port}"
    site = resource.Site()
    site.add_resource(["public"], PublicEcho())
    server_context = await aiocoap.Context.create_server_context(
        site, bind=("127.0.0.1", origin_port), transports=["udp6"]
    )
    try:
        with Process(
            [
                str(ROOT / "target/debug/examples/proxy"),
                f"127.0.0.1:{proxy_port}",
                origin,
            ]
        ):
            context = await aiocoap.Context.create_client_context(transports=["udp6"])
            try:
                interface = ProxyForwarder(f"coap://127.0.0.1:{proxy_port}", context)
                for method, payload, expected in [
                    (aiocoap.GET, b"", b"public through proxy"),
                    (aiocoap.POST, b"through proxy", b"through proxy"),
                ]:
                    response = await asyncio.wait_for(
                        interface.request(
                            aiocoap.Message(
                                code=method, uri=origin + "/public", payload=payload
                            )
                        ).response,
                        10,
                    )
                    assert (
                        response.code.is_successful() and response.payload == expected
                    )
            finally:
                await context.shutdown()
    finally:
        await server_context.shutdown()
    print("aiocoap client -> mai-coap proxy -> aiocoap server: PASS", flush=True)


class HandshakeGate(asyncio.DatagramProtocol):
    """Hold both message_2 replies downstream of the proxy's congestion control."""

    def __init__(self, proxy, pending):
        self.proxy = proxy
        self.pending = pending
        self.peer = None
        self.released = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if address != self.proxy:
            self.peer = address
            self.transport.sendto(data, self.proxy)
        elif self.released or data[1] >> 5 != 2:
            self.transport.sendto(data, self.peer)
        else:
            self.pending[self] = data
            if len(self.pending) == 2:
                for gate, reply in self.pending.items():
                    gate.released = True
                    gate.transport.sendto(reply, gate.peer)


async def concurrent_proxy_clients(directory, combined):
    origin_port = free_port()
    proxy_port = free_port()
    pending = {}
    gates = []
    origin = f"coap://127.0.0.1:{origin_port}"
    peer_proxy = str(pathlib.Path(sys.executable).with_name("aiocoap-proxy"))
    env = dict(
        os.environ, AIOCOAP_SERVER_TRANSPORT="udp6", AIOCOAP_CLIENT_TRANSPORT="udp6"
    )

    async def client(payload):
        gate = HandshakeGate(("127.0.0.1", proxy_port), pending)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: gate, local_addr=("127.0.0.1", 0)
        )
        gates.append(transport)
        command = [
            str(ROOT / "target/debug/examples/secured-client"),
            f"127.0.0.1:{transport.get_extra_info('sockname')[1]}",
            str(directory / "i.ccs"),
            str(directory / "i.raw"),
            str(directory / "r.ccs"),
            str(combined).lower(),
            origin + "/echo",
            payload,
        ]
        child = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(child.communicate(), 15)
            assert child.returncode == 0, stderr.decode()
            assert stdout == payload.encode()
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    try:
        with (
            Process(
                [
                    str(ROOT / "target/debug/examples/secured-server"),
                    f"127.0.0.1:{origin_port}",
                    str(directory / "r.ccs"),
                    str(directory / "r.raw"),
                    str(directory / "i.ccs"),
                ]
            ),
            Process(
                [peer_proxy, "--forward", "--bind", f"127.0.0.1:{proxy_port}"],
                port=proxy_port,
                env=env,
            ),
        ):
            results = await asyncio.gather(
                client("first"), client("second"), return_exceptions=True
            )
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            assert len(pending) == 2 and all(gate.released for gate in pending)
    finally:
        for transport in gates:
            transport.close()
    print(
        f"concurrent clients -> aiocoap proxy -> one server: combined={combined}: PASS",
        flush=True,
    )


async def main(profile, xarxa=None, command_line=False):
    with tempfile.TemporaryDirectory(prefix="mai-coap-interop-") as temporary:
        directory = pathlib.Path(temporary)
        for role in ["i", "r"]:
            identity_files(directory, role, profile)
        if command_line:
            for combined in [True, False]:
                await command_line_client(directory, combined)
            return
        if xarxa:
            for combined in [True, False]:
                await independent_client(directory, combined, "127.0.0.1", xarxa=xarxa)
            return
        for combined in [True, False]:
            for host in ["127.0.0.1", "[::1]", "localhost"]:
                await independent_client(directory, combined, host)
            await independent_server(directory, combined)
            await independent_proxy(directory, combined)
            await concurrent_proxy_clients(directory, combined)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile", choices=["rfc9529", "minimal-ccs"], default="rfc9529"
    )
    parser.add_argument(
        "--xarxa",
        nargs="?",
        const="native",
        choices=["native", "embassy"],
        help="exercise xarxa through the IPv4 loopback UDP/IP test link",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="exercise cli/target/debug/mai-coap against an aiocoap server",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    asyncio.run(main(args.profile, args.xarxa, args.cli))
