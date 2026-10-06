#!/usr/bin/env python3
"""cartographer v2 — architectural layer mapper using curl."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, re, socket, ssl, sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cartographer_layers import KNOWN_LAYERS, HEADER_ORDER_HINTS
from cartographer_normalization import build_probes as build_norm_probes
from cartographer_smuggle import build_smuggle_probes
from cartographer_cache import UNKEYED_HEADERS, CACHE_VALUES
from cartographer_ct import build_ct_probes


@dataclass
class LayerHit:
    name: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class LayerMap:
    target: str
    detected: List[LayerHit] = field(default_factory=list)
    header_chain: List[str] = field(default_factory=list)
    tls_fingerprints: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class Divergence:
    kind: str
    probe: str
    layer_a: str
    layer_b: str
    input_sent: str
    response_a: str
    response_b: str
    interpretation: str
    confidence: float


@dataclass
class CartoReport:
    target: str
    started: str
    finished: str
    layer_map: Optional[LayerMap] = None
    divergences: List[Divergence] = field(default_factory=list)
    reach_points: List[str] = field(default_factory=list)
    summary: str = ""


async def _curl(url: str, method: str = "GET",
                headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None,
                timeout: int = 15) -> Tuple[int, int, str, str]:
    """Execute curl as a subprocess. Returns (status, body_len, body_hash, meta)."""
    cmd = ["curl", "-sS", "-k", "--path-as-is", "--max-time", str(timeout),
           "-o", "-", "-w", "\n__CURLMETA__%{http_code}__%{size_download}__%{content_type}"]
    if method != "GET":
        cmd += ["-X", method]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if body is not None:
        cmd += ["--data-binary", "@-"]
    cmd.append(url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if body is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=body)
        await proc.wait()
    except Exception as e:
        return 0, 0, "", f"exec_error:{e}"

    # Verify curl exited cleanly. A partial body means we lost data.
    if proc.returncode != 0:
        return 0, 0, "", f"curl_rc={proc.returncode} stderr={stderr[:120]!r}"

    if not stdout:
        return 0, 0, "", f"empty_stdout stderr={stderr[:120]!r}"

    marker = b"\n__CURLMETA__"
    idx = stdout.rfind(marker)
    if idx < 0:
        return 0, 0, "", f"no_marker len={len(stdout)}"

    body_bytes = stdout[:idx]
    meta = stdout[idx + len(marker):].decode("latin-1", errors="replace")
    parts = meta.split("__")
    if len(parts) < 3:
        return 0, 0, "", f"bad_meta:{meta[:60]}"

    try:
        status = int(parts[0])
    except ValueError:
        status = 0
    bhash = hashlib.sha256(body_bytes).hexdigest()[:8]
    return status, len(body_bytes), bhash, meta[:120]


def _match_any(patterns: List[str], text: str) -> List[str]:
    return [p for p in patterns if re.search(p, text, re.I)]


async def fingerprint_layers(target: str) -> LayerMap:
    lm = LayerMap(target=target)
    status, blen, bhash, meta = await _curl(target)
    if status == 0:
        lm.notes.append(f"unreachable: {meta}")
        return lm

    # Fetch headers via a separate HEAD request
    cmd_headers = await asyncio.create_subprocess_exec(
        "curl", "-sS", "-k", "-I", "--max-time", "10", target,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    hout, _ = await cmd_headers.communicate()
    header_blob = hout.decode("latin-1", errors="replace")
    server = ""
    m = re.search(r"^Server:\s*(.+)$", header_blob, re.I | re.M)
    if m:
        server = m.group(1).strip()

    for layer in KNOWN_LAYERS:
        hits = _match_any(layer.header_re, header_blob) + _match_any(layer.server_re, server)
        if hits:
            conf = min(0.95, 0.5 + 0.15 * len(hits))
            lm.detected.append(LayerHit(layer.name, conf, hits))

    for hname, adder in HEADER_ORDER_HINTS:
        if re.search(rf"^{hname}:", header_blob, re.I | re.M):
            lm.header_chain.append(f"{hname} <- {adder}")

    host = urlparse(target).netloc.split(":")[0]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                if cert:
                    lm.tls_fingerprints.append({
                        "cert_sha256": hashlib.sha256(cert).hexdigest()[:24],
                        "cipher": cipher[0] if cipher else "",
                        "version": ssock.version(),
                    })
    except Exception as e:
        lm.notes.append(f"tls_fingerprint: {e}")
    return lm


async def probe_normalization(target: str) -> List[Divergence]:
    divergences: List[Divergence] = []
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    probes = build_norm_probes(origin)

    results: Dict[str, Tuple[int, int, str]] = {}

    async def one(p):
        url = origin + p["path"]
        status, blen, bhash, _ = await _curl(url)
        results[p["label"]] = (status, blen, bhash)

    for i in range(0, len(probes), 20):
        batch = probes[i:i+20]
        await asyncio.gather(*(one(p) for p in batch))

    by_base: Dict[str, Dict[str, Tuple[int, int, str]]] = {}
    for p in probes:
        by_base.setdefault(p["base"], {})[p["chain"]] = results[p["label"]]

    for base, chains in by_base.items():
        raw = chains.get("raw")
        if not raw or raw[0] == 0:
            continue
        raw_status, raw_len, raw_hash = raw

        sigs = {c: s for c, s in chains.items() if c != "raw" and s[0] != 0}
        if not sigs:
            continue

        uniq = set(sigs.values())
        # uniform rejection: skip
        if len(uniq) == 1:
            only = list(uniq)[0]
            if raw_status in (200, 201) and only[0] in (400, 403, 404):
                continue
            if raw_status in (400, 403, 404) and only[0] in (400, 403, 404):
                continue

        for chain, (st, bl, bh) in sigs.items():
            if (st, bl, bh) == (raw_status, raw_len, raw_hash):
                continue
            conf = 0.5
            interp = f"{chain}-encoded {base} differed from raw"
            if st == 200 and raw_status in (403, 404):
                conf = 0.9
                interp = (f"{chain}-encoded {base} reached origin as 200 while raw was {raw_status}")
            elif st in (301, 302) and raw_status == 200:
                conf = 0.7
                interp = f"{chain}-encoded {base} triggered redirect"
            elif raw_status == 200 and st in (400, 403):
                conf = 0.6
                interp = f"{chain}-encoded {base} was rejected while raw succeeded"
            divergences.append(Divergence(
                kind="normalization", probe=f"{base}|{chain}",
                layer_a="client-encoder", layer_b="edge-or-origin",
                input_sent=base,
                response_a=f"{raw_status} len={raw_len} hash={raw_hash}",
                response_b=f"{st} len={bl} hash={bh}",
                interpretation=interp, confidence=conf,
            ))
    return divergences


async def probe_content_type(target: str) -> List[Divergence]:
    divergences: List[Divergence] = []
    probes = build_ct_probes()[:40]

    async def one(p):
        status, blen, bhash, _ = await _curl(
            target, method="POST",
            headers={"Content-Type": p["content_type"]},
            body=p["body"].encode())
        return p["body_name"], p["content_type"], status, blen

    results = []
    for i in range(0, len(probes), 10):
        batch = probes[i:i+10]
        results.extend(await asyncio.gather(*(one(p) for p in batch)))

    by_body: Dict[str, List[Tuple[str, int, int]]] = {}
    for bname, ct, st, bl in results:
        if st == 0:
            continue
        by_body.setdefault(bname, []).append((ct, st, bl))

    for bname, entries in by_body.items():
        # Signature = (status, body_len). Ignore body_hash entirely.
        # Hash differs per request on any target with per-request nonces.
        sigs = {(e[1], e[2]) for e in entries}
        if len(sigs) > 1:
            e1 = entries[0]
            e2 = next(
                (e for e in entries[1:] if (e[1], e[2]) != (e1[1], e1[2])),
                None,
            )
            if not e2:
                continue
            len_diff = abs(e1[2] - e2[2])
            # Require meaningful length difference (>= 20 bytes) to
            # avoid sub-byte noise from variable whitespace or dates.
            if len_diff < 20 and e1[1] == e2[1]:
                continue
            divergences.append(Divergence(
                kind="content_type", probe=f"body={bname}",
                layer_a=f"CT='{e1[0]}'", layer_b=f"CT='{e2[0]}'",
                input_sent=bname,
                response_a=f"status={e1[1]} len={e1[2]}",
                response_b=f"status={e2[1]} len={e2[2]}",
                interpretation=(
                    f"body '{bname}' with CT '{e1[0]}' gave "
                    f"{e1[1]}/{e1[2]} bytes; CT '{e2[0]}' gave "
                    f"{e2[1]}/{e2[2]} bytes ({len_diff} byte delta)"
                ),
                confidence=0.7,
            ))
    return divergences


async def probe_unkeyed_headers(target: str) -> List[Divergence]:
    divergences: List[Divergence] = []
    # Baseline: 3 passes to know the stable signature.
    base_sigs = set()
    for _ in range(3):
        st, bl, _, _ = await _curl(target)
        base_sigs.add((st, bl))
    if not base_sigs:
        return divergences
    # Pick the most common baseline sig.
    base_sig = max(base_sigs, key=lambda x: list(base_sigs).count(x))

    sample = UNKEYED_HEADERS[:60]
    val = "webptprobe"

    async def one(hname):
        # Two passes to reject per-request nonces.
        sigs = []
        for _ in range(2):
            st, bl, _, _ = await _curl(target, headers={hname: val})
            sigs.append((st, bl))
        return hname, sigs

    for i in range(0, len(sample), 10):
        batch = sample[i:i+10]
        for hname, sigs in await asyncio.gather(*(one(h) for h in batch)):
            # Both passes must agree for a stable finding.
            if sigs[0] != sigs[1]:
                continue
            sig = sigs[0]
            if sig[0] == 0:
                continue
            if sig == base_sig:
                continue
            # Length difference must be structural (>= 10 bytes) OR
            # status class must change. Hash-only deltas ignored.
            len_diff = abs(sig[1] - base_sig[1])
            status_changed = sig[0] != base_sig[0]
            if not status_changed and len_diff < 10:
                continue
            divergences.append(Divergence(
                kind="unkeyed_delta", probe=hname,
                layer_a="baseline", layer_b="with-header",
                input_sent=f"{hname}: {val}",
                response_a=f"status={base_sig[0]} len={base_sig[1]}",
                response_b=f"status={sig[0]} len={sig[1]}",
                interpretation=(
                    f"header {hname}={val!r}: baseline "
                    f"{base_sig[0]}/{base_sig[1]} → with-header "
                    f"{sig[0]}/{sig[1]} ({len_diff} byte delta)"
                ),
                confidence=0.75,
            ))
    return divergences


def derive_reach_points(divs: List[Divergence]) -> List[str]:
    out = []
    seen = set()
    for d in divs:
        if d.confidence < 0.6:
            continue
        if d.kind in ("unkeyed_delta", "normalization", "content_type"):
            key = (d.kind, d.probe)
        else:
            key = (d.kind, d.layer_a, d.layer_b)
        if key in seen:
            continue
        seen.add(key)
        if d.kind == "normalization":
            out.append(f"[normalization] {d.layer_a} vs {d.layer_b}: {d.interpretation}")
        elif d.kind == "content_type":
            out.append(f"[content-type] {d.interpretation}")
        elif d.kind == "unkeyed_delta":
            out.append(f"[unkeyed-header] header {d.probe} influences response")
        elif d.kind == "smuggle_primitive_accepted":
            out.append(f"[framing] {d.interpretation}")
    return out


async def run(target: str, args) -> CartoReport:
    rep = CartoReport(target=target,
                      started=datetime.now(timezone.utc).isoformat(),
                      finished="")
    print(f"[*] Fingerprinting layers on {target}")
    lm = await fingerprint_layers(target)
    rep.layer_map = lm
    for lh in lm.detected:
        print(f"    layer: {lh.name:15} conf={lh.confidence:.2f} {lh.evidence[:2]}")

    print(f"[*] Normalization matrix")
    nd = await probe_normalization(target)
    print(f"    {len(nd)} divergences")
    rep.divergences.extend(nd)

    print(f"[*] Content-Type matrix")
    ctd = await probe_content_type(target)
    print(f"    {len(ctd)} divergences")
    rep.divergences.extend(ctd)

    print(f"[*] Unkeyed header sample")
    ud = await probe_unkeyed_headers(target)
    print(f"    {len(ud)} divergences")
    rep.divergences.extend(ud)

    rep.reach_points = derive_reach_points(rep.divergences)
    rep.finished = datetime.now(timezone.utc).isoformat()
    rep.summary = (f"target={target} layers={len(lm.detected)} "
                   f"divergences={len(rep.divergences)} "
                   f"reach_points={len(rep.reach_points)}")
    return rep


def render(rep: CartoReport) -> str:
    out = ["=" * 78,
           "cartographer — architectural layer map",
           f"target  : {rep.target}",
           f"started : {rep.started}",
           f"finished: {rep.finished}",
           "=" * 78, ""]
    out.append("## Summary")
    out.append("  " + rep.summary)
    out.append("")
    if rep.layer_map:
        out.append(f"## Detected layers ({len(rep.layer_map.detected)})")
        for lh in rep.layer_map.detected:
            out.append(f"  {lh.name:15} conf={lh.confidence:.2f}")
            for e in lh.evidence[:4]:
                out.append(f"      {e}")
        out.append("")
        if rep.layer_map.header_chain:
            out.append("## Header chain")
            for line in rep.layer_map.header_chain:
                out.append(f"  {line}")
            out.append("")
        if rep.layer_map.tls_fingerprints:
            out.append("## TLS fingerprints")
            for tf in rep.layer_map.tls_fingerprints:
                out.append(f"  {tf}")
            out.append("")
    out.append(f"## Reach points ({len(rep.reach_points)})")
    if not rep.reach_points:
        out.append("  (none)")
    for rp in rep.reach_points:
        out.append(f"  - {rp}")
    out.append("")
    out.append(f"## Divergences ({len(rep.divergences)})")
    for i, d in enumerate(rep.divergences, 1):
        out.append(f"  [{i:03d}] {d.kind} conf={d.confidence:.2f}")
        out.append(f"        probe  : {d.probe}")
        out.append(f"        layers : {d.layer_a} <> {d.layer_b}")
        out.append(f"        sent   : {d.input_sent}")
        out.append(f"        A      : {d.response_a}")
        out.append(f"        B      : {d.response_b}")
        out.append(f"        note   : {d.interpretation}")
    out.append("")
    out.append("=" * 78)
    return "\n".join(out)


async def amain(args):
    rep = await run(args.target, args)
    Path(args.o).write_text(render(rep))
    Path(args.j).write_text(json.dumps(asdict(rep), indent=2, default=str))
    print()
    print(render(rep))
    print(f"\n[+] {args.o}")
    print(f"[+] {args.j}")
    return 1 if rep.reach_points else 0


def main():
    ap = argparse.ArgumentParser(prog="cartographer")
    ap.add_argument("target")
    ap.add_argument("-o", default="cartographer_report.txt")
    ap.add_argument("-j", default="cartographer_report.json")
    ap.add_argument("-c", type=int, default=6)
    args = ap.parse_args()
    sys.exit(asyncio.run(amain(args)))


if __name__ == "__main__":
    main()
