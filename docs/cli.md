# Command-line client

Copyright (c) 2026 mai-coap contributors.

`mai-coap` is a curl-like client for CoAP over UDP, with optional EDHOC and OSCORE
security. It runs on Linux.

```sh
cargo install --locked --git https://github.com/snabb/mai-coap mai-coap-cli
```

## Requests

The argument is a full `coap://` URI. The payload goes to stdout, and status goes to
stderr.

```sh
mai-coap coap://192.0.2.1/temperature
mai-coap -m post -t json -e '{"on":true}' coap://node.example/lamp
mai-coap -m put -t binary -f image.bin -o reply.txt coap://[2001:db8::1]:5700/image
mai-coap -m fetch -t cbor --payload @query.cbor -A cbor coap://node.example/log
```

Bodies of any size use block-wise transfer automatically. Link-local addresses take a
zone: `coap://[fe80::1%25eth0]/x`.

| Purpose | Flags |
|---|---|
| Method | `-m`, `--method`: `get`, `post`, `put`, `delete`, `fetch`, `patch`, `ipatch`, or a number |
| Payload | `-e TEXT` (percent-decoded), `-f FILE` or `-f -`, `--payload X`, `--payload @FILE`, `--payload @-` |
| Content formats | `-t`, `--content-format` and `-A`, `--accept`: a number, MIME type, or `plain`, `link`, `xml`, `binary`, `exi`, `json`, `cbor` |
| Non-confirmable | `-N`, `--non` |
| Observe | `-s SECONDS`, `--observe` |
| Block size | `-b [NUM,]SIZE` (`NUM` resumes a GET or FETCH at that block), `--payload-initial-szx SZX` |
| Forward proxy | `-P`, `--proxy URI` |
| Raw option | `-O NUM,TEXT` or `-O NUM,0xHEX`, repeatable |
| Repeat | `-G COUNT`, a second apart, under one security context |
| Addressing | `-a ADDRESS`, `-p PORT`, `-4`, `-6`, `-U`/`--no-set-hostname` |
| Timeout | `-B SECONDS` |
| Output | `-o FILE`, `-o -`, `-w` (append a newline), `--max-size BYTES` (default 64 MiB) |
| Diagnostics | `-v`, `-vv`, `-q` |

`-O` refuses options that the library or another flag manages: Uri-\*, Proxy-\*, Block\*,
Size\*, Observe and OSCORE. An unknown elective option is sent, but a server may ignore it.

Uri-Host and Uri-Port are sent only when they differ from the destination, as RFC 7252
section 6.4 describes, so `coap://node.example/x` sends Uri-Host and `coap://192.0.2.1/x`
doesn't. `-U` never sends them.

## Secured requests

EDHOC authenticates both sides with raw public keys and sets up OSCORE. Create an identity
and give its `.ccs` file to the server:

```sh
mai-coap --generate-identity client
```

This writes `client.ccs` and `client.cosekey`, and never replaces existing files. Get the
server's `.ccs` file, then pass all three:

```sh
mai-coap --identity client.ccs --key client.cosekey --peer server.ccs coap://node.example/lamp
```

- `--key` is a COSE_Key file in the form `aiocoap-keygen` writes, so keys work in both
  tools. One that others can read is refused. Other encodings of a COSE_Key, such as with
  extra entries, aren't recognized.
- The server must match `--peer`. The hostname in the URI plays no part in that decision.
- A request never falls back to no protection. An unprotected answer exits with code 4.
- `--sequential-edhoc` runs the handshake before the first request instead of combining
  them, for servers without RFC 9668 support.
- Each process runs its own handshake, because contexts live only in memory. A loop over
  a small device repeats that work and uses up its context slots. `-G` reuses one context
  within a process.
- Static OSCORE contexts aren't supported.

## Observing

`-s SECONDS` observes for that long, and `--observe` until interrupted or until the server
ends the observation. Each notification is written as it arrives, and a newline follows it
on a terminal or with `-w`. A slow reader sees the latest value, not every value.

On expiry, SIGINT or SIGTERM, the client sends the deregistration and waits up to five
seconds for it, even if a reader has stopped reading its output. If a server doesn't accept
the observation, its normal response is written with a note on stderr, and the client exits.

## Output and exit codes

| Code | Meaning |
|---|---|
| 0 | 2.xx response, or `-s` ended |
| 1 | 4.xx or 5.xx response; its diagnostic payload goes to stdout |
| 2 | Usage or local error, including `--max-size` |
| 3 | Timeout, reset or other network failure |
| 4 | Protection or EDHOC failure |
| 130 | Interrupted |

- A body is written only once complete, so a resource changing mid-transfer can't produce
  a mix of versions.
- Binary data isn't written to a terminal unless you pass `-o -` or `-o FILE`. Text with
  control characters counts as binary, so a server can't send terminal escape sequences.
- `-v` shows the response code and options on stderr, with tokens shortened. `-vv` adds
  library logs, which the protocol driver writes directly, so keep stderr drained with it.
- A final error message waits at most a second for a stalled stderr and is then dropped, so
  the exit code still arrives.

## Timeouts

Confirmable requests give up by CoAP's own retransmission limits, within about 93 seconds
by default. `-B` sets a shorter overall limit. A lost `-N` request is never retransmitted, so
it waits for the full 247-second exchange lifetime unless you pass `-B`. `-B` doesn't apply
to observations, which `-s` limits.

## Differences from coap-client and aiocoap-client

Most flags work the same, but these don't:

- `-v` counts (`-vv`), as in aiocoap, rather than taking a number. `-q` is quiet, and `-h`
  is help.
- `--payload` sends a non-file argument as given. With a CBOR format it is refused, rather
  than read as CBOR diagnostic notation.
- Credentials are explicit flags, not an aiocoap credentials file.
- Not available: `coaps://` and other transports (DTLS, TLS, TCP, WebSocket), `-E` static
  OSCORE, `-T` tokens, `-l` loss simulation, `-K` pings, `--interactive`, pretty-printing
  and multicast.
- A FETCH needs a Content-Format, as RFC 8132 requires.
