"""Layer signature model. Each layer type has known fingerprints."""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

@dataclass
class LayerFingerprint:
    name: str
    header_re: List[str] = field(default_factory=list)
    server_re: List[str] = field(default_factory=list)
    behavior: List[str] = field(default_factory=list)

# Ordered top-down: closest to client first.
KNOWN_LAYERS = [
    LayerFingerprint("cloudflare",
        header_re=[r"^cf-ray$", r"^cf-cache-status$", r"^__cfduid", r"^__cf_bm"],
        server_re=[r"cloudflare"],
        behavior=["challenge_page", "nonce_per_request"]),
    LayerFingerprint("akamai",
        header_re=[r"^x-akamai", r"^akamai-grn", r"^x-check-cacheable"],
        server_re=[r"akamaighost"],
        behavior=[]),
    LayerFingerprint("fastly",
        header_re=[r"^x-served-by$", r"^x-cache$", r"^x-cache-hits$", r"^x-timer$"],
        server_re=[],
        behavior=["vcl_response", "x-served-by_tag"]),
    LayerFingerprint("cloudfront",
        header_re=[r"^x-amz-cf-id$", r"^x-amz-cf-pop$"],
        server_re=[r"cloudfront"],
        behavior=[]),
    LayerFingerprint("imperva",
        header_re=[r"^x-iinfo$", r"^x-cdn$"],
        server_re=[r"incapsula"],
        behavior=[]),
    LayerFingerprint("sucuri",
        header_re=[r"^x-sucuri-id$", r"^x-sucuri-cache$"],
        server_re=[r"sucuri"],
        behavior=[]),
    LayerFingerprint("varnish",
        header_re=[r"^x-varnish$", r"^via$", r"^age$"],
        server_re=[r"varnish"],
        behavior=["x-varnish_two_ints"]),
    LayerFingerprint("nginx",
        header_re=[],
        server_re=[r"nginx"],
        behavior=["503_default_page", "405_method"]),
    LayerFingerprint("apache",
        header_re=[],
        server_re=[r"apache"],
        behavior=["server_signature_apache"]),
    LayerFingerprint("iis",
        header_re=[r"^x-aspnet", r"^x-powered-by:.*asp"],
        server_re=[r"microsoft-iis"],
        behavior=[]),
    LayerFingerprint("express",
        header_re=[r"^x-powered-by:.*express"],
        server_re=[],
        behavior=[]),
    LayerFingerprint("tomcat",
        header_re=[r"^x-application-context"],
        server_re=[r"tomcat"],
        behavior=[]),
]

HEADER_ORDER_HINTS: List[Tuple[str, str]] = [
    # (header, likely-adder)
    ("x-forwarded-for", "edge_proxy"),
    ("x-forwarded-proto", "edge_proxy"),
    ("x-forwarded-host", "edge_proxy"),
    ("x-real-ip", "edge_proxy_or_lb"),
    ("x-served-by", "fastly_or_cdn"),
    ("x-cache", "cdn_or_varnish"),
    ("cf-ray", "cloudflare"),
    ("x-amz-cf-id", "cloudfront"),
    ("x-amzn-trace-id", "aws_alb"),
    ("x-azure-ref", "azure_front_door"),
    ("x-vercel-id", "vercel"),
    ("x-railway-edge", "railway"),
    ("x-render-origin-server", "render"),
    ("x-netlify-id", "netlify"),
    ("x-heroku-request-id", "heroku_router"),
]
