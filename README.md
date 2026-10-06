# cartographer v2

Architectural layer mapper for HTTP targets. Emits divergences between
client-side encoding, edge, and origin.

## Method

- HTTP client: `curl 8.5.0` via `asyncio.create_subprocess_exec`
- `--path-as-is` prevents curl from normalizing `%2e%2e`, `%2f`, `\`
- Signature = `(status_code, body_len)`. Body hash is never used —
  CDNs inject per-request nonces (CF-Ray, CSRF tokens) that change the
  hash on every call.
- Baseline: 3 passes, mode signature.
- Probe: 2 passes, both must agree. Otherwise dropped.
- Divergence triggers:
  - status class change (200 -> 403)
  - abs(len_a - len_b) >= 10 with identical status
- proc.returncode != 0 -> discarded (guards against truncated pipes).

## Probes

- probe_normalization — 10 base paths x 10 encoding chains
- probe_content_type — 40 (body, CT) pairs
- probe_unkeyed_headers — 60 header candidates

## Verified results

| target | layers | divergences | reach points |
|--------|--------|-------------|--------------|
| real-paper-doll.europe1.hackviser.space | nginx | 0 | 0 |
| www.cloudflare.com | cloudflare | 3 | 3 |

Cloudflare findings, all reproducible with plain curl:

    CF-Connecting-IP: webptprobe  ->  403 / 17 bytes      baseline 200
    X-Original-URL:   webptprobe  ->  403 / 4840 bytes    baseline 200
    X-Rewrite-URL:    webptprobe  ->  403 / 4840 bytes    baseline 200

Edge-enforcement behaviors. cartographer reports them as reach points;
classification is the operator's.

## Anti-patterns refused

- Divergence on hash-only delta
- Divergence when all encodings give the same response (uniform
  rejection != architectural disagreement)
- Divergence from a partial read (proc.returncode != 0 -> discarded)

## Files

- cartographer.py — main
- cartographer_layers.py — KNOWN_LAYERS, header order hints
- cartographer_normalization.py — encoding chains
- cartographer_smuggle.py — CL/TE probes
- cartographer_cache.py — UNKEYED_HEADERS, CACHE_VALUES
- cartographer_ct.py — CT probe bodies

## Requirements

    curl >= 8.0
    python >= 3.10

No aiohttp. No dnspython. No third-party Python packages.

## Run

    python cartographer.py 'https://target/' -c 2

-c = subprocess concurrency. 2 safe on any target. 6 viable on
localhost fixtures. High concurrency + large bodies can starve the
stdout pipe — the proc.returncode check discards those runs.
