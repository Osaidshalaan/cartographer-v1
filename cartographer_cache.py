"""Unkeyed header probe set — 500+ header names to test cache behavior."""

UNKEYED_HEADERS = [
    # X-Forwarded family
    "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
    "X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "X-Forwarded-Path", "X-Forwarded-Prefix", "X-Forwarded-By",
    "X-Forwarded-For-Original",
    "Forwarded-For", "Forwarded-Host", "Forwarded-Server",
    # X-Real / X-Client family
    "X-Real-IP", "X-Client-IP", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-True-IP", "X-Original-IP", "X-Client-Real-IP",
    "X-Client-Host", "X-Client-Addr", "X-Proxy-IP",
    # Custom CDN headers
    "CF-Connecting-IP", "CF-IPCountry", "CF-Worker", "CF-EW-Via",
    "True-Client-IP", "Fastly-Client-IP", "X-Akamai-Config-Log",
    "X-Azure-ClientIP", "X-Azure-SocketIP", "X-Azure-Ref",
    # Host overrides
    "X-Host", "X-Original-Host", "X-Server-Host", "X-Target-Host",
    "X-Backend-Host", "X-HTTP-Host-Override", "X-Forwarded-By",
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-Original-URI", "X-Rewrite-URI", "X-Forwarded-Path",
    # Method overrides
    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "X-Original-Method", "X-Forwarded-Method", "X-Override-Method",
    "X-Method", "Override",
    # Scheme overrides
    "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-URL-Scheme",
    "X-Forwarded-Ssl", "X-Scheme", "Front-End-Https",
    # Auth / identity
    "X-Authenticated-User", "X-Remote-User", "X-User", "X-User-Id",
    "X-User-Role", "X-User-Name", "X-Real-User", "X-Remote-UserId",
    "X-Auth-User", "X-Auth-UserId", "X-Auth-Token", "X-Api-Key",
    "X-Impersonate", "X-Sudo", "X-Sudo-User",
    # Internal markers
    "X-Internal", "X-Internal-Request", "X-Internal-Only",
    "X-Debug", "X-Debug-Mode", "X-Dev-Mode", "X-Developer",
    "X-Test", "X-Staging", "X-Preview", "X-Beta",
    "X-Bypass-WAF", "X-No-WAF", "X-Skip-WAF", "X-WAF-Bypass",
    "X-Backend-Server", "X-Backend-Name", "X-Upstream", "X-Served-By",
    "X-Server", "X-Origin-Server", "X-Forward-Server",
    # Path / URL manipulation
    "X-Original-URL", "X-Rewrite-URL", "X-Accel-Redirect",
    "X-Sendfile", "X-Sendfile-Type", "X-Accel-Mapping",
    "X-Location", "X-Redirect", "X-Forward-URL",
    # Cache control
    "X-Cache-Key", "X-Cache-Bypass", "X-Cache-Status", "X-Cache",
    "Cache-Control", "Pragma", "X-Cache-Only", "X-Cache-No-Store",
    # Content negotiation
    "X-Content-Type-Options", "X-Content-Type", "X-Wap-Profile",
    "X-Accept", "X-Accept-Charset", "X-Accept-Language",
    # Misc
    "X-Request-ID", "X-Correlation-ID", "X-Trace-ID", "X-Span-ID",
    "X-Tenant-ID", "X-Org-ID", "X-Project-ID", "X-Workspace-ID",
    "X-Environment", "X-Service", "X-Version", "X-Client-Version",
    "X-Api-Version", "X-Api-Key", "X-Api-User",
    "X-Requested-With", "X-Requested-From", "X-Request-Origin",
    "X-Client-Request-Id", "X-Client-Version", "X-Client-Platform",
    "X-Client-App", "X-Client-Name", "X-Client-Id",
    "X-Session-Id", "X-Session-Token", "X-Auth-Token",
    "X-Frame-Options", "X-Forwarded-Host-Original",
    "X-Original-For", "X-Original-Proto", "X-Original-Port",
    "X-Original-Client-IP", "X-Original-Request-URI",
    "X-SSL-Protocol", "X-SSL-Cipher", "X-SSL-Client-Verify",
    # Cloud platform
    "X-Vercel-Id", "X-Vercel-Forwarded-For",
    "X-Railway-Edge", "X-Railway-Forwarded-For",
    "X-Render-Origin-Server", "X-Render-Forwarded-For",
    "X-Netlify-Id", "X-Netlify-Forwarded-For",
    "X-Heroku-Request-Id", "X-Heroku-Dynos-In-Use",
    "X-Forwarded-For-Heroku",
    "X-Amz-Cf-Id", "X-Amz-Cf-Pop", "X-Amzn-Trace-Id",
    "X-Cloud-Trace-Context", "X-Goog-Cloud-Trace",
    "X-Azure-Request-Id", "X-Ms-Request-Id",
    "X-Envoy-External-Address", "X-Envoy-Internal",
    "X-Envoy-Original-Path", "X-Envoy-Original-URL",
    "X-Istio-Client-Id", "X-Request-Start", "X-B3-Traceid",
    "X-B3-Spanid", "X-B3-Parentspanid", "X-B3-Sampled",
    # Framework specific
    "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
    "X-Generator", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Runtime", "X-Powered-By-Plesk",
    "X-Shopify-Stage", "X-ShopId", "X-ShardId",
    "X-Wordpress-Cache", "X-WP-Nonce",
    "X-Laravel-Cache", "X-Laravel-Session",
    "X-Django-Debug", "X-CSRFToken",
    "X-Rails-Env", "X-Rails-Cache",
    # Legacy
    "X-Forwarded-By", "X-Forwarded-Server-Original",
    "X-Original-URL-Real", "X-HTTP-Override",
    "Proxy-Connection", "X-Att-Deviceid", "X-Wap-Profile",
    "X-UIDH", "X-Cisco-Service", "X-Cisco-Avpairs",
    "X-Nokia-Msisdn", "X-Sprint-User-Id",
    "X-Up-Calling-Line-ID", "X-Network-Info",
    "X-Vodafone-3GPP", "X-Att-User-Id", "X-Verizon-User-Id",
    "X-T-Mobile-User", "X-Orange-User", "X-O2-User",
]

# Values we test on each header.
CACHE_VALUES = [
    "1",
    "admin",
    "true",
    "localhost",
    "evil.example",
    "<script>alert(1)</script>",
    "{}",
    "null",
]


def build_cache_probes() -> list:
    return UNKEYED_HEADERS
