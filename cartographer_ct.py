"""Content-Type confusion matrix."""

CONTENT_TYPES = [
    "application/json",
    "application/json; charset=utf-8",
    "application/json; charset=UTF-8",
    "application/json;charset=utf-8",
    "application/JSON",
    "APPLICATION/JSON",
    "application/json ",
    "application/json\t",
    "application/json\n",
    "application/json\r",
    " application/json",
    "application/xml",
    "text/xml",
    "text/plain",
    "text/plain; application/json",
    "application/x-www-form-urlencoded",
    "application/x-www-form-urlencoded; charset=utf-8",
    "multipart/form-data",
    "text/json",
    "text/x-json",
    "application/vnd.api+json",
    "application/ld+json",
    "application/hal+json",
    "application/problem+json",
    "application/merge-patch+json",
    "application/json-patch+json",
    "application/graphql+json",
    "application/json5",
    "application/x-json",
    "application/json; boundary=x",
    "text/html; application/json",
    "text/xml; application/json",
    "application/xml; application/json",
    "application/x-www-form-urlencoded; application/json",
    "charset=utf-8; application/json",
    "application/json; profile=\"https://x\"",
]

BODIES = {
    "json_object": '{"a":1}',
    "json_admin": '{"admin":true,"role":"admin"}',
    "xml_entity": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "y">]><r>&e;</r>',
    "form_admin": "admin=true&role=admin",
}


def build_ct_probes() -> list:
    out = []
    for ct in CONTENT_TYPES:
        for body_name in BODIES:
            out.append({
                "label": f"ct={ct}|body={body_name}",
                "content_type": ct,
                "body": BODIES[body_name],
                "body_name": body_name,
            })
    return out
