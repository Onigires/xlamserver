#!/usr/bin/env python3
"""
Xlam Connect coordination/relay server.

Compatible with the Xlam Connect Windows client protocol (version 1).
Standard library only. Requires Python 3.10+.

Run:
    python xlam_server.py --port 7777

Open the same port for TCP and UDP in the VPS firewall/security group.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import signal
import struct
import time
from pathlib import Path
from typing import Any

VERSION = 1
T_STUN_REQ = 0x10
T_STUN_RES = 0x11
T_RELAY_OUT = 0x20
T_RELAY_IN = 0x21


def ip_to_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value & 0xFFFFFFFF))


def json_line(obj: dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


class Client:
    def __init__(self, server: "XlamServer", reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, token: bytes):
        self.server = server
        self.reader = reader
        self.writer = writer
        self.token = token
        self.token_hex = token.hex()
        peer = writer.get_extra_info("peername")
        self.remote = peer[0] if peer else "unknown"
        self.nonce = secrets.token_bytes(16)
        self.authed = False
        self.network: Network | None = None
        self.id = 0
        self.pub = ""
        self.nick = ""
        self.lan: list[str] = []
        self.pub_ep: str | None = None
        self.udp: tuple[str, int] | None = None
        self.last_seen = time.monotonic()
        self.tokens = float(server.relay_bytes_per_sec)
        self.token_at = time.monotonic()
        self.closed = False

    async def send(self, obj: dict[str, Any]) -> None:
        if self.closed or self.writer.is_closing():
            return
        try:
            self.writer.write(json_line(obj))
            await self.writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            await self.close()

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.server.remove_client(self)
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass


class Network:
    def __init__(self, name: str, auth_key: bytes,
                 leases: dict[str, int] | None = None):
        self.name = name
        self.auth_key = auth_key
        self.leases: dict[str, int] = leases or {}
        self.members: dict[int, Client] = {}


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: "XlamServer"):
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.server.udp_transport = self.transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.server.handle_udp(data, addr)

    def error_received(self, exc: Exception) -> None:
        self.server.log(f"udp error: {exc}")


class XlamServer:
    def __init__(self, args: argparse.Namespace):
        self.host = args.host
        self.port = args.port
        self.subnet = ipaddress.ip_network(args.subnet, strict=False)
        self.prefix = self.subnet.prefixlen
        self.base_int = int(self.subnet.network_address)
        self.max_peers = args.max_peers
        self.relay_bytes_per_sec = max(1, args.relay_mbps) * 125000
        self.state_path = None if args.no_state else Path(args.state)
        self.quiet = args.quiet
        self.networks: dict[str, Network] = {}
        self.clients: dict[str, Client] = {}
        self.next_id = 1
        self.failures: dict[str, dict[str, float]] = {}
        self.tcp_server: asyncio.AbstractServer | None = None
        self.udp_transport: asyncio.DatagramTransport | None = None
        self.load_state()

    def log(self, *parts: Any) -> None:
        if not self.quiet:
            print(time.strftime("%H:%M:%S"), *parts, flush=True)

    def load_state(self) -> None:
        if not self.state_path:
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            for item in raw.get("networks", []):
                leases = {str(k): int(v) for k, v in item.get("leases", [])}
                network = Network(item["name"], bytes.fromhex(item["authKey"]), leases)
                self.networks[item["name"].lower()] = network
            self.log(f"state loaded: {len(self.networks)} network(s)")
        except FileNotFoundError:
            pass
        except Exception as exc:
            self.log(f"state load failed: {exc}")

    def save_state(self) -> None:
        if not self.state_path:
            return
        data = {"networks": [
            {"name": n.name, "authKey": n.auth_key.hex(),
             "leases": [[k, v] for k, v in n.leases.items()]}
            for n in self.networks.values()
        ]}
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.state_path)
        except Exception as exc:
            self.log(f"state save failed: {exc}")

    async def start(self) -> None:
        self.tcp_server = await asyncio.start_server(
            self.handle_connection, self.host, self.port,
            limit=65536, reuse_address=True
        )
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(
            lambda: UDPProtocol(self), local_addr=(self.host, self.port)
        )
        self.log(f"Xlam server on {self.host}:{self.port} (tcp+udp), subnet {self.subnet}")

    async def stop(self) -> None:
        for client in list(self.clients.values()):
            await client.close()
        if self.tcp_server:
            self.tcp_server.close()
            await self.tcp_server.wait_closed()
        if self.udp_transport:
            self.udp_transport.close()
        self.save_state()

    async def handle_connection(self, reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter) -> None:
        remote_info = writer.get_extra_info("peername")
        remote = remote_info[0] if remote_info else "unknown"
        failure = self.failures.get(remote)
        if failure and failure.get("blocked_until", 0) > time.monotonic():
            writer.close()
            await writer.wait_closed()
            return
        token = secrets.token_bytes(8)
        client = Client(self, reader, writer, token)
        self.clients[client.token_hex] = client
        try:
            await client.send({"t": "hello", "v": VERSION,
                               "nonce": client.nonce.hex(),
                               "token": client.token_hex, "udpPort": self.port})
            line = await asyncio.wait_for(reader.readline(), 10)
            if not line or len(line) > 65536:
                return
            await self.handle_message(client, json.loads(line))
            if not client.authed:
                return
            while not reader.at_eof() and not client.closed:
                line = await reader.readline()
                if not line:
                    break
                if len(line) > 65536:
                    break
                client.last_seen = time.monotonic()
                try:
                    await self.handle_message(client, json.loads(line))
                except Exception as exc:
                    self.log(f"msg error: {exc}")
                    break
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                ConnectionError, OSError, json.JSONDecodeError):
            pass
        finally:
            await client.close()

    async def handle_message(self, client: Client, msg: dict[str, Any]) -> None:
        msg_type = msg.get("t")
        if msg_type == "auth":
            await self.authenticate(client, msg)
        elif msg_type == "ping":
            await client.send({"t": "pong", "ts": msg.get("ts")})
        elif msg_type == "lan" and client.authed and isinstance(msg.get("lan"), list):
            client.lan = self.clean_eps(msg["lan"])
            await self.announce(client)

    def clean_eps(self, values: list[Any]) -> list[str]:
        result = []
        for value in values:
            if not isinstance(value, str):
                continue
            try:
                host, port = value.rsplit(":", 1)
                ipaddress.IPv4Address(host)
                if 1 <= int(port) <= 65535:
                    result.append(f"{host}:{int(port)}")
            except (ValueError, TypeError):
                continue
            if len(result) >= 8:
                break
        return result

    async def fail(self, client: Client, code: str, message: str) -> None:
        now = time.monotonic()
        item = self.failures.setdefault(client.remote, {"n": 0, "first": now, "blocked_until": 0})
        if now - item["first"] > 60:
            item.update(n=0, first=now)
        item["n"] += 1
        if item["n"] >= 12:
            item["blocked_until"] = now + 60
        await client.send({"t": "err", "code": code, "msg": message})
        await client.close()

    async def authenticate(self, client: Client, msg: dict[str, Any]) -> None:
        if client.authed:
            return
        if msg.get("v") != VERSION:
            return await self.fail(client, "version", "Client/server protocol mismatch")
        name = str(msg.get("net", "")).strip()
        if not 3 <= len(name) <= 32 or any(ord(c) < 32 for c in name):
            return await self.fail(client, "badname", "Network name must be 3-32 characters")
        pub = str(msg.get("pub", ""))
        if len(pub) != 64 or any(c not in "0123456789abcdef" for c in pub):
            return await self.fail(client, "badreq", "bad key")
        key = name.lower()
        network = self.networks.get(key)
        mode = msg.get("mode")
        if mode == "create":
            if network:
                return await self.fail(client, "exists", "A network with this name already exists")
            auth_hex = str(msg.get("authKey", ""))
            if len(auth_hex) != 64 or any(c not in "0123456789abcdef" for c in auth_hex):
                return await self.fail(client, "badreq", "bad auth key")
            network = Network(name, bytes.fromhex(auth_hex))
            self.networks[key] = network
            self.log(f"network created: {name}")
        elif mode != "join":
            return await self.fail(client, "badreq", "bad mode")
        elif not network:
            return await self.fail(client, "notfound", "Network not found")
        try:
            got = bytes.fromhex(str(msg.get("proof", "")))
        except ValueError:
            got = b""
        expected = hmac.new(network.auth_key, client.nonce + bytes.fromhex(pub), hashlib.sha256).digest()
        if len(got) != 32 or not hmac.compare_digest(expected, got):
            if mode == "create":
                self.networks.pop(key, None)
            return await self.fail(client, "badauth", "Wrong password")
        for other in list(network.members.values()):
            if other.pub == pub:
                await other.send({"t": "err", "code": "replaced", "msg": "Signed in from another place"})
                await other.close()
        if len(network.members) >= self.max_peers:
            return await self.fail(client, "full", "Network is full")
        ip_value = network.leases.get(pub)
        if ip_value is None:
            used = set(network.leases.values())
            for host in range(1, self.subnet.num_addresses - 1):
                candidate = self.base_int + host
                if candidate not in used:
                    ip_value = candidate
                    break
            if ip_value is None:
                return await self.fail(client, "full", "No free addresses")
            network.leases[pub] = ip_value
        client.authed = True
        client.network = network
        client.pub = pub
        client.id = self.next_id
        self.next_id += 1
        client.nick = "".join(c for c in str(msg.get("nick", "peer")) if ord(c) >= 32)[:24] or "peer"
        client.lan = self.clean_eps(msg.get("lan", [])) if isinstance(msg.get("lan", []), list) else []
        network.members[client.id] = client
        self.save_state()
        await client.send({"t": "ok", "id": client.id, "ip": int_to_ip(ip_value),
                           "prefix": self.prefix, "net": network.name,
                           "peers": [self.peer_info(p) for p in network.members.values() if p is not client]})
        await self.announce(client)
        self.log(f'+ {client.nick} ({int_to_ip(ip_value)}) joined "{network.name}" [{len(network.members)}]')

    def peer_info(self, client: Client) -> dict[str, Any]:
        ip_value = client.network.leases[client.pub] if client.network else 0
        eps = ([client.pub_ep] if client.pub_ep else []) + client.lan
        return {"id": client.id, "pub": client.pub, "nick": client.nick,
                "ip": int_to_ip(ip_value), "eps": eps}

    async def announce(self, client: Client) -> None:
        if not client.authed or not client.network:
            return
        message = {"t": "peer", "peer": self.peer_info(client)}
        await asyncio.gather(*(p.send(message) for p in client.network.members.values() if p is not client), return_exceptions=True)

    def remove_client(self, client: Client) -> None:
        self.clients.pop(client.token_hex, None)
        if client.authed and client.network and client.network.members.get(client.id) is client:
            client.network.members.pop(client.id, None)
            for other in list(client.network.members.values()):
                asyncio.create_task(other.send({"t": "gone", "id": client.id}))
            self.log(f'- {client.nick} left "{client.network.name}" [{len(client.network.members)}]')

    def handle_udp(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 9:
            return
        client = self.clients.get(data[1:9].hex())
        if not client:
            return
        packet_type = data[0]
        if packet_type == T_STUN_REQ:
            if not self.udp_transport:
                return
            address, port = addr
            out = bytes([T_STUN_RES]) + struct.pack("!IH", ip_to_int(address), port)
            self.udp_transport.sendto(out, addr)
            client.udp = addr
            endpoint = f"{address}:{port}"
            if client.pub_ep != endpoint:
                client.pub_ep = endpoint
                asyncio.create_task(self.announce(client))
        elif packet_type == T_RELAY_OUT and client.authed and len(data) > 13:
            now = time.monotonic()
            client.tokens = min(self.relay_bytes_per_sec, client.tokens + (now - client.token_at) * self.relay_bytes_per_sec)
            client.token_at = now
            if client.tokens < len(data):
                return
            client.tokens -= len(data)
            destination_id = struct.unpack("!I", data[9:13])[0]
            destination = client.network.members.get(destination_id) if client.network else None
            if not destination or not destination.udp or not self.udp_transport:
                return
            out = bytes([T_RELAY_IN]) + data[13:]
            self.udp_transport.sendto(out, destination.udp)

    async def sweeper(self) -> None:
        while True:
            await asyncio.sleep(5)
            now = time.monotonic()
            for client in list(self.clients.values()):
                if now - client.last_seen > 45:
                    await client.close()
            for remote, item in list(self.failures.items()):
                if now - item["first"] > 120 and item["blocked_until"] < now:
                    self.failures.pop(remote, None)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Xlam Connect TCP+UDP coordination server")
    parser.add_argument("--host", default=os.getenv("XLAM_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("XLAM_PORT", "7777")))
    parser.add_argument("--subnet", default=os.getenv("XLAM_SUBNET", "10.26.0.0/16"))
    parser.add_argument("--max-peers", type=int, default=int(os.getenv("XLAM_MAX_PEERS", "64")))
    parser.add_argument("--relay-mbps", type=int, default=int(os.getenv("XLAM_RELAY_MBPS", "40")))
    parser.add_argument("--state", default=os.getenv("XLAM_STATE", "xlam-state.json"))
    parser.add_argument("--no-state", action="store_true", help="keep networks and leases in memory")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    server = XlamServer(args)
    await server.start()
    sweeper_task = asyncio.create_task(server.sweeper())
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except (NotImplementedError, RuntimeError):
                pass
    try:
        await stop_event.wait()
    finally:
        sweeper_task.cancel()
        await server.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
