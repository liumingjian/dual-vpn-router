"""A private-domain DNS relay with per-tunnel upstream socket binding."""

import ipaddress
import socket
import socketserver
import struct
import threading


def question_name(packet):
    if len(packet) < 12 or struct.unpack("!H", packet[4:6])[0] != 1:
        raise ValueError("Expected one DNS question.")
    offset, labels = 12, []
    while True:
        if offset >= len(packet):
            raise ValueError("Truncated DNS name.")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ValueError("Unsupported DNS question encoding.")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("Truncated DNS question.")
    return ".".join(labels).lower()


def answer_addresses(packet):
    def skip_name(offset):
        for _ in range(128):
            if offset >= len(packet):
                raise ValueError("Truncated DNS record.")
            size = packet[offset]
            offset += 1
            if size == 0:
                return offset
            if size & 0xC0 == 0xC0:
                if offset >= len(packet):
                    raise ValueError("Truncated DNS pointer.")
                return offset + 1
            if size > 63 or offset + size > len(packet):
                raise ValueError("Invalid DNS name.")
            offset += size
        raise ValueError("DNS name exceeds bounds.")

    if len(packet) < 12:
        raise ValueError("Truncated DNS header.")
    qd, an, ns, ar = struct.unpack("!HHHH", packet[4:12])
    offset, addresses = 12, []
    for _ in range(qd):
        offset = skip_name(offset) + 4
    for _ in range(an + ns + ar):
        offset = skip_name(offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS record header.")
        kind, cls, _, size = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        if offset + size > len(packet):
            raise ValueError("Truncated DNS record data.")
        if kind == 1 and cls == 1 and size == 4:
            addresses.append(str(ipaddress.IPv4Address(packet[offset : offset + size])))
        offset += size
    return addresses


def failure(packet, code=2):
    if len(packet) < 12:
        return b""
    flags = struct.unpack("!H", packet[2:4])[0]
    return (
        packet[:2]
        + struct.pack("!H", 0x8000 | (flags & 0x7900) | code)
        + packet[4:6]
        + b"\0" * 6
        + packet[12:]
    )


def owner(name, gateways):
    matches = [
        (len(domain), g["name"])
        for g in gateways
        for domain in g.get("domains", [])
        if name == domain or name.endswith("." + domain)
    ]
    return max(matches)[1] if matches else None


def receive_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise OSError("Truncated DNS TCP response.")
        result.extend(part)
    return bytes(result)


def forward(packet, server, interface, tcp=False, port=53, bind=True):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        if bind:
            sock.setsockopt(
                socket.IPPROTO_IP,
                getattr(socket, "IP_BOUND_IF", 25),
                socket.if_nametoindex(interface),
            )
        sock.connect((server, port))
        if tcp:
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            response = receive_exact(sock, struct.unpack("!H", receive_exact(sock, 2))[0])
        else:
            sock.send(packet)
            response = sock.recv(65535)
        if len(response) < 12 or response[:2] != packet[:2] or not response[2] & 0x80:
            raise OSError("Invalid upstream DNS response.")
        if not tcp and response[2] & 2:
            return forward(packet, server, interface, tcp=True, port=port, bind=bind)
        return response


class Relay:
    def __init__(self, gateways, state, upstream=forward, on_response=None):
        self.gateways, self.state, self.upstream = gateways, state, upstream
        self.on_response = on_response
        relay = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                packet, sock = self.request
                response = relay.answer(packet)
                if response:
                    sock.sendto(response, self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                try:
                    while True:
                        size = struct.unpack("!H", receive_exact(self.request, 2))[0]
                        response = relay.answer(receive_exact(self.request, size), tcp=True)
                        if not response:
                            return
                        self.request.sendall(struct.pack("!H", len(response)) + response)
                except (OSError, ValueError):
                    return

        class UDPServer(socketserver.ThreadingUDPServer):
            daemon_threads = True

        class TCPServer(socketserver.ThreadingTCPServer):
            daemon_threads = True

        self.udp = UDPServer(("127.0.0.1", 0), UDP)
        self.port = self.udp.server_address[1]
        try:
            self.tcp = TCPServer(("127.0.0.1", self.port), TCP)
        except BaseException:
            self.udp.server_close()
            raise

    def answer(self, packet, tcp=False):
        try:
            name = owner(question_name(packet), self.gateways)
            if name is None:
                return failure(packet, 5)
            state = self.state(name)
            if state.get("state") != "connected" or not state.get("interface"):
                return failure(packet)
            for server in state.get("dns_servers", []):
                try:
                    response = self.upstream(packet, server, state["interface"], tcp=tcp)
                    if self.on_response:
                        self.on_response(name, state["interface"], answer_addresses(response))
                    return response
                except OSError:
                    continue
                except RuntimeError:
                    return failure(packet)
        except (ValueError, UnicodeError):
            return failure(packet, 1)
        return failure(packet)

    def start(self):
        for server in (self.udp, self.tcp):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def close(self):
        for server in (self.udp, self.tcp):
            server.shutdown()
            server.server_close()
