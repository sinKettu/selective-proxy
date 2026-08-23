#!/usr/bin/env python3
"""PoC: selectively tunnel local HTTP/HTTPS TCP connections via an HTTP proxy.

Linux nftables redirects locally-created TCP connections for ports 80 and 443
to this process.  The process reads HTTP Host or TLS SNI and either connects
directly or opens an HTTP CONNECT tunnel through the configured proxy.

This is deliberately a PoC, not a production security boundary.  In
particular, ECH, QUIC/HTTP3, non-HTTP traffic, certificate-free IP matching,
authentication beyond Basic, and already-established connections are outside
its scope.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fnmatch
import os
import pwd
import re
import signal
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


NFT_TABLE = "selective_proxy_poc"
SO_ORIGINAL_DST = 80
PEEK_LIMIT = 64 * 1024
READ_TIMEOUT = 5.0


@dataclass(frozen=True)
class Proxy:
    host: str
    port: int
    authorization: str | None = None


def parse_proxy(value: str) -> Proxy:
    parsed = urlsplit(value if "://" in value else f"http://{value}")
    if parsed.scheme != "http" or not parsed.hostname:
        raise argparse.ArgumentTypeError("proxy must be http://[user:pass@]host:port")
    try:
        port = parsed.port or 8080
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    authorization = None
    if parsed.username is not None:
        credentials = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
        authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
    return Proxy(parsed.hostname, port, authorization)


class DomainRules:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.patterns: tuple[str, ...] = ()
        self.mtime_ns = -1
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        stat = self.path.stat()
        if not force and stat.st_mtime_ns == self.mtime_ns:
            return
        patterns: list[str] = []
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            value = raw.split("#", 1)[0].strip().rstrip(".").lower()
            if not value:
                continue
            # A plain domain includes the domain itself and all subdomains.
            patterns.append(value if any(ch in value for ch in "*?[") else f"*.{value}")
            if not any(ch in value for ch in "*?["):
                patterns.append(value)
        self.patterns = tuple(dict.fromkeys(patterns))
        self.mtime_ns = stat.st_mtime_ns
        print(f"loaded {len(self.patterns)} domain rules from {self.path}", file=sys.stderr)

    def matches(self, host: str | None) -> bool:
        if not host:
            return False
        with contextlib.suppress(OSError):
            self.reload()
        normalized = host.rstrip(".").lower()
        return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in self.patterns)


def original_destination(sock: socket.socket) -> tuple[str, int]:
    """Return the destination saved by nft REDIRECT (IPv4 PoC)."""
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    # sockaddr_in uses host byte order for sin_family, but network byte order
    # for sin_port.  Reading both fields as big-endian turns AF_INET (2) into
    # 512 on little-endian Linux hosts.
    family = struct.unpack_from("=H", raw, 0)[0]
    port = struct.unpack_from("!H", raw, 2)[0]
    if family != socket.AF_INET:
        raise OSError(f"unsupported original address family: {family}")
    return socket.inet_ntoa(raw[4:8]), port


def http_host(data: bytes) -> str | None:
    if b"\r\n\r\n" not in data:
        return None
    match = re.search(br"\r\nHost\s*:\s*([^\r\n]+)", b"\r\n" + data, re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).strip().decode("ascii", "ignore")
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    return value.rsplit(":", 1)[0]


def tls_sni(data: bytes) -> str | None:
    """Extract SNI from a complete-enough TLS ClientHello without decrypting it."""
    try:
        if len(data) < 5 or data[0] != 22:
            return None
        record_length = int.from_bytes(data[3:5], "big")
        body = memoryview(data)[5 : 5 + record_length]
        if len(body) < 4 or body[0] != 1:
            return None
        pos = 4 + 2 + 32
        pos += 1 + body[pos]  # session id
        pos += 2 + int.from_bytes(body[pos : pos + 2], "big")  # cipher suites
        pos += 1 + body[pos]  # compression methods
        extensions_length = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        end = min(len(body), pos + extensions_length)
        while pos + 4 <= end:
            extension_type = int.from_bytes(body[pos : pos + 2], "big")
            extension_length = int.from_bytes(body[pos + 2 : pos + 4], "big")
            pos += 4
            extension = body[pos : pos + extension_length]
            pos += extension_length
            if extension_type != 0 or len(extension) < 5:
                continue
            name_type = extension[2]
            name_length = int.from_bytes(extension[3:5], "big")
            if name_type == 0 and 5 + name_length <= len(extension):
                return bytes(extension[5 : 5 + name_length]).decode("idna").lower()
    except (IndexError, UnicodeError, ValueError):
        return None
    return None


async def read_initial(reader: asyncio.StreamReader, port: int) -> tuple[bytes, str | None]:
    data = bytearray()
    deadline = asyncio.get_running_loop().time() + READ_TIMEOUT
    while len(data) < PEEK_LIMIT:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        chunk = await asyncio.wait_for(reader.read(min(4096, PEEK_LIMIT - len(data))), remaining)
        if not chunk:
            break
        data.extend(chunk)
        host = tls_sni(data) if port == 443 else http_host(data)
        if host:
            return bytes(data), host
        if port == 80 and b"\r\n\r\n" in data:
            break
        if port == 443 and len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big"):
            break
    return bytes(data), tls_sni(data) if port == 443 else http_host(data)


async def connect_via_proxy(proxy: Proxy, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
    authority = f"{host}:{port}"
    lines = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: keep-alive",
    ]
    if proxy.authorization:
        lines.append(f"Proxy-Authorization: {proxy.authorization}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT)
    status = response.split(b"\r\n", 1)[0].split()
    if len(status) < 2 or status[1] != b"200":
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"proxy CONNECT failed: {response.splitlines()[0].decode(errors='replace')}")
    return reader, writer


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(64 * 1024):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.write_eof()


async def relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    rules: DomainRules,
    proxy: Proxy,
) -> None:
    peer = client_writer.get_extra_info("peername")
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        sock = client_writer.get_extra_info("socket")
        destination_host, destination_port = original_destination(sock)
        initial, requested_host = await read_initial(client_reader, destination_port)
        use_proxy = rules.matches(requested_host)
        if use_proxy:
            upstream_reader, upstream_writer = await connect_via_proxy(
                proxy, requested_host or destination_host, destination_port
            )
        else:
            upstream_reader, upstream_writer = await asyncio.open_connection(destination_host, destination_port)
        route = "PROXY" if use_proxy else "DIRECT"
        print(f"{route:6} {peer} -> {requested_host or destination_host}:{destination_port}", file=sys.stderr)
        upstream_writer.write(initial)
        await upstream_writer.drain()
        tasks = [
            asyncio.create_task(pipe(client_reader, upstream_writer)),
            asyncio.create_task(pipe(upstream_reader, client_writer)),
        ]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as exc:
        print(f"ERROR  {peer}: {exc}", file=sys.stderr)
    finally:
        if upstream_writer:
            upstream_writer.close()
            with contextlib.suppress(Exception):
                await upstream_writer.wait_closed()
        client_writer.close()
        with contextlib.suppress(Exception):
            await client_writer.wait_closed()


def nft_script(action: str, port: int, uid: int) -> str:
    if action == "remove":
        return f"delete table inet {NFT_TABLE}\n"
    return f"""add table inet {NFT_TABLE}
add chain inet {NFT_TABLE} output {{ type nat hook output priority dstnat; policy accept; }}
add rule inet {NFT_TABLE} output meta skuid {uid} return
add rule inet {NFT_TABLE} output ip daddr 127.0.0.0/8 return
add rule inet {NFT_TABLE} output ip daddr 0.0.0.0/8 return
add rule inet {NFT_TABLE} output tcp dport {{ 80, 443 }} redirect to :{port}
"""


def configure_nft(action: str, port: int, user: str) -> None:
    if os.geteuid() != 0:
        raise SystemExit("nft setup/removal requires root")
    uid = pwd.getpwnam(user).pw_uid
    if action == "install":
        subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], stderr=subprocess.DEVNULL)
    result = subprocess.run(["nft", "-f", "-"], input=nft_script(action, port, uid), text=True)
    if result.returncode:
        raise SystemExit(result.returncode)
    print(f"nftables rules {action}ed; excluded service user is {user} (uid {uid})")


async def run(args: argparse.Namespace) -> None:
    if os.geteuid() == 0:
        raise SystemExit(f"refusing to run as root; run the service as --user {args.user}")
    expected_uid = pwd.getpwnam(args.user).pw_uid
    if os.geteuid() != expected_uid:
        raise SystemExit(f"run as user {args.user}; its traffic is excluded from redirection")
    rules = DomainRules(args.domains)
    server = await asyncio.start_server(
        lambda r, w: relay(r, w, rules, args.proxy), "127.0.0.1", args.port
    )
    print(f"listening on 127.0.0.1:{args.port}; press Ctrl-C to stop", file=sys.stderr)
    async with server:
        await server.serve_forever()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("action", choices=("install", "run", "remove"))
    result.add_argument("--domains", type=Path, default=Path("domains.txt"))
    result.add_argument("--proxy", type=parse_proxy, help="http://[user:pass@]host:port")
    result.add_argument("--port", type=int, default=12345, help="local transparent listener port")
    result.add_argument(
        "--user",
        default="selective-proxy",
        help="account whose outbound traffic bypasses interception (must own this process and upstream proxy)",
    )
    return result


def main() -> None:
    args = parser().parse_args()
    if args.action in {"install", "remove"}:
        configure_nft(args.action, args.port, args.user)
        return
    if not args.proxy:
        raise SystemExit("run requires --proxy")
    try:
        asyncio.run(run(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    main()
