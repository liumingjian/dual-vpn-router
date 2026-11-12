import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_CONFIG = Path.home() / ".config/dual-vpn-router/config.json"
NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")


def validate(config):
    gateways = config.get("gateways", [])
    if not isinstance(gateways, list) or not gateways:
        raise ValueError("Configure at least one gateway.")
    names, networks, domains = set(), [], set()
    for g in gateways:
        name = g.get("name", "")
        if not NAME.fullmatch(name) or name in names:
            raise ValueError("Gateway names must be unique lowercase identifiers.")
        names.add(name)
        url = urlsplit(g["url"])
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.hostname.startswith("-")
        ):
            raise ValueError(f"{name}: use an HTTPS URL without credentials or query parameters.")
        _ = url.port
        if g.get("trust", "system") not in ("system", "presented"):
            raise ValueError(f"{name}: trust must be system or presented.")
        if not g.get("routes"):
            raise ValueError(f"{name}: configure explicit resource routes first.")
        for value in g["routes"]:
            net = ipaddress.ip_network(value, strict=True)
            if net.version != 4 or net.prefixlen == 0 or not net.is_private:
                raise ValueError(
                    f"{name}: only explicit private IPv4 resource routes are supported."
                )
            for other, owner in networks:
                if net.overlaps(other):
                    raise ValueError(
                        f"Conflicting route ownership: {net} ({name}) and {other} ({owner})."
                    )
            networks.append((net, name))
        for domain in g.get("domains", []):
            if not DOMAIN.fullmatch(domain) or ".." in domain or domain in domains:
                raise ValueError("DNS domains must be unique lowercase domain names.")
            domains.add(domain)
        for server in g.get("dns_servers", []):
            if ipaddress.ip_address(server).version != 4:
                raise ValueError("Only IPv4 DNS upstreams are supported.")
        for probe in g.get("probes", []):
            if probe.get("kind") not in ("tcp", "http"):
                raise ValueError("Probe kind must be tcp or http.")
            if probe["kind"] == "tcp":
                if not probe.get("host") or not 1 <= int(probe["port"]) <= 65535:
                    raise ValueError("TCP probes require host and port.")
            elif urlsplit(probe["url"]).scheme not in ("http", "https"):
                raise ValueError("HTTP probes require HTTP or HTTPS URLs.")
    return config


def load(path):
    return validate(json.loads(Path(path).read_text()))


def save(path, data):
    validate(data)
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
