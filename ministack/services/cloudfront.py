"""
Amazon CloudFront Emulator.
REST/XML API — service credential scope: cloudfront.

Supports:
  Distributions:  CreateDistribution, GetDistribution, ListDistributions,
                  UpdateDistribution (via PUT config), DeleteDistribution,
                  GetDistributionConfig
  Invalidations:  CreateInvalidation, GetInvalidation, ListInvalidations
  OAI:            CreateCloudFrontOriginAccessIdentity,
                  GetCloudFrontOriginAccessIdentity,
                  ListCloudFrontOriginAccessIdentities,
                  DeleteCloudFrontOriginAccessIdentity
  OAC:            CreateOriginAccessControl, GetOriginAccessControl,
                  ListOriginAccessControls, DeleteOriginAccessControl
  Tags:           TagResource, UntagResource, ListTagsForResource

Wire protocol:
  All requests/responses use XML with namespace
  http://cloudfront.amazonaws.com/doc/2020-05-31/
  Paths are under /2020-05-31/
"""

import re
import string
import random
import threading
import logging
from datetime import datetime, timezone
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring

from ministack.core.responses import new_uuid

logger = logging.getLogger("cloudfront")

NS = "http://cloudfront.amazonaws.com/doc/2020-05-31/"
API_VERSION = "2020-05-31"
ACCOUNT_ID = "000000000000"

# ─── in-memory state ──────────────────────────────────────────────────────────

_distributions: dict = {}     # dist_id -> distribution dict
_invalidations: dict = {}     # dist_id -> {inv_id -> invalidation dict}
_oai: dict = {}               # oai_id -> oai dict
_oac: dict = {}               # oac_id -> oac dict
_tags: dict = {}              # resource_arn -> {key: value}
_etags: dict = {}             # dist_id -> etag string
_lock = threading.Lock()


def reset():
    global _distributions, _invalidations, _oai, _oac, _tags, _etags
    with _lock:
        _distributions = {}
        _invalidations = {}
        _oai = {}
        _oac = {}
        _tags = {}
        _etags = {}


# ─── ID / name generators ─────────────────────────────────────────────────────

_ID_CHARS = string.ascii_uppercase + string.digits


def _dist_id() -> str:
    """Generate a CloudFront distribution ID (14 uppercase alphanumeric)."""
    return "".join(random.choices(_ID_CHARS, k=14))


def _domain_name(dist_id: str) -> str:
    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{prefix}.cloudfront.net"


def _oai_id() -> str:
    return "".join(random.choices(_ID_CHARS, k=14))


def _oac_id() -> str:
    return new_uuid()


def _inv_id() -> str:
    return "".join(random.choices(_ID_CHARS, k=14))


def _new_etag() -> str:
    return "E" + "".join(random.choices(_ID_CHARS, k=13))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _dist_arn(dist_id: str) -> str:
    return f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/{dist_id}"


def _oai_arn(oai_id: str) -> str:
    return f"arn:aws:cloudfront::{ACCOUNT_ID}:origin-access-identity/{oai_id}"


# ─── XML helpers ─────────────────────────────────────────────────────────────

def _xml_response(root_tag: str, builder_fn, status: int = 200,
                  extra_headers: dict = None) -> tuple:
    root = Element(root_tag, xmlns=NS)
    builder_fn(root)
    body = b'<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(
        root, encoding="unicode"
    ).encode("utf-8")
    headers = {"Content-Type": "text/xml"}
    if extra_headers:
        headers.update(extra_headers)
    return status, headers, body


def _error_response(code: str, message: str, status: int = 400) -> tuple:
    root = Element("ErrorResponse", xmlns=NS)
    err = SubElement(root, "Error")
    SubElement(err, "Code").text = code
    SubElement(err, "Message").text = message
    SubElement(root, "RequestId").text = new_uuid()
    body = b'<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(
        root, encoding="unicode"
    ).encode("utf-8")
    return status, {"Content-Type": "text/xml"}, body


def _find(el, tag):
    for child in el:
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if local == tag:
            return child
    return None


def _findall(el, tag):
    return [
        c for c in el
        if (c.tag.split("}")[-1] if "}" in c.tag else c.tag) == tag
    ]


def _text(el, tag, default=""):
    child = _find(el, tag)
    return child.text or default if child is not None else default


def _parse_body(body: bytes):
    if not body:
        return None
    try:
        return fromstring(body.decode("utf-8"))
    except Exception:
        return None


# ─── distribution config parsing ─────────────────────────────────────────────

def _parse_origins(origins_el):
    if origins_el is None:
        return []
    items_el = _find(origins_el, "Items")
    if items_el is None:
        return []
    result = []
    for origin_el in _findall(items_el, "Origin"):
        origin = {
            "Id": _text(origin_el, "Id"),
            "DomainName": _text(origin_el, "DomainName"),
            "OriginPath": _text(origin_el, "OriginPath", ""),
            "ConnectionAttempts": _text(origin_el, "ConnectionAttempts", "3"),
            "ConnectionTimeout": _text(origin_el, "ConnectionTimeout", "10"),
        }
        s3_origin_el = _find(origin_el, "S3OriginConfig")
        if s3_origin_el is not None:
            origin["S3OriginConfig"] = {
                "OriginAccessIdentity": _text(s3_origin_el, "OriginAccessIdentity", ""),
            }
        custom_el = _find(origin_el, "CustomOriginConfig")
        if custom_el is not None:
            origin["CustomOriginConfig"] = {
                "HTTPPort": _text(custom_el, "HTTPPort", "80"),
                "HTTPSPort": _text(custom_el, "HTTPSPort", "443"),
                "OriginProtocolPolicy": _text(custom_el, "OriginProtocolPolicy", "https-only"),
                "OriginSSLProtocols": _parse_ssl_protocols(custom_el),
            }
        result.append(origin)
    return result


def _parse_ssl_protocols(parent_el):
    ssl_el = _find(parent_el, "OriginSSLProtocols")
    if ssl_el is None:
        return ["TLSv1.2"]
    items_el = _find(ssl_el, "Items")
    if items_el is None:
        return ["TLSv1.2"]
    return [_text(item, "SslProtocol") or item.text or "TLSv1.2"
            for item in _findall(items_el, "SslProtocol")]


def _parse_default_cache_behavior(dcb_el):
    if dcb_el is None:
        return {}
    return {
        "TargetOriginId": _text(dcb_el, "TargetOriginId"),
        "ViewerProtocolPolicy": _text(dcb_el, "ViewerProtocolPolicy", "allow-all"),
        "CachePolicyId": _text(dcb_el, "CachePolicyId", ""),
        "OriginRequestPolicyId": _text(dcb_el, "OriginRequestPolicyId", ""),
        "Compress": _text(dcb_el, "Compress", "false"),
        "AllowedMethods": _parse_allowed_methods(dcb_el),
        "CachedMethods": _parse_cached_methods(dcb_el),
    }


def _parse_allowed_methods(parent_el):
    am_el = _find(parent_el, "AllowedMethods")
    if am_el is None:
        return ["GET", "HEAD"]
    items_el = _find(am_el, "Items")
    if items_el is None:
        return ["GET", "HEAD"]
    return [m.text for m in _findall(items_el, "Method") if m.text]


def _parse_cached_methods(parent_el):
    am_el = _find(parent_el, "AllowedMethods")
    if am_el is None:
        return ["GET", "HEAD"]
    cached_el = _find(am_el, "CachedMethods")
    if cached_el is None:
        return ["GET", "HEAD"]
    items_el = _find(cached_el, "Items")
    if items_el is None:
        return ["GET", "HEAD"]
    return [m.text for m in _findall(items_el, "Method") if m.text]


def _parse_aliases(aliases_el):
    if aliases_el is None:
        return []
    items_el = _find(aliases_el, "Items")
    if items_el is None:
        return []
    return [c.text for c in _findall(items_el, "CNAME") if c.text]


def _parse_viewer_certificate(vc_el):
    if vc_el is None:
        return {"CloudFrontDefaultCertificate": "true", "MinimumProtocolVersion": "TLSv1"}
    return {
        "CloudFrontDefaultCertificate": _text(vc_el, "CloudFrontDefaultCertificate", "false"),
        "ACMCertificateArn": _text(vc_el, "ACMCertificateArn", ""),
        "IAMCertificateId": _text(vc_el, "IAMCertificateId", ""),
        "SSLSupportMethod": _text(vc_el, "SSLSupportMethod", ""),
        "MinimumProtocolVersion": _text(vc_el, "MinimumProtocolVersion", "TLSv1"),
        "Certificate": _text(vc_el, "Certificate", ""),
        "CertificateSource": _text(vc_el, "CertificateSource", "cloudfront"),
    }


def _parse_restrictions(rest_el):
    if rest_el is None:
        return {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0, "Items": []}}
    gr_el = _find(rest_el, "GeoRestriction")
    if gr_el is None:
        return {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0, "Items": []}}
    items_el = _find(gr_el, "Items")
    locs = []
    if items_el is not None:
        locs = [c.text for c in _findall(items_el, "Location") if c.text]
    return {
        "GeoRestriction": {
            "RestrictionType": _text(gr_el, "RestrictionType", "none"),
            "Quantity": len(locs),
            "Items": locs,
        }
    }


def _parse_distribution_config(root_el):
    return {
        "CallerReference": _text(root_el, "CallerReference"),
        "Origins": _parse_origins(_find(root_el, "Origins")),
        "DefaultCacheBehavior": _parse_default_cache_behavior(
            _find(root_el, "DefaultCacheBehavior")
        ),
        "Comment": _text(root_el, "Comment", ""),
        "Enabled": _text(root_el, "Enabled", "true").lower() == "true",
        "Aliases": _parse_aliases(_find(root_el, "Aliases")),
        "PriceClass": _text(root_el, "PriceClass", "PriceClass_All"),
        "HttpVersion": _text(root_el, "HttpVersion", "http2"),
        "IsIPV6Enabled": _text(root_el, "IsIPV6Enabled", "true").lower() == "true",
        "DefaultRootObject": _text(root_el, "DefaultRootObject", ""),
        "WebACLId": _text(root_el, "WebACLId", ""),
        "ViewerCertificate": _parse_viewer_certificate(_find(root_el, "ViewerCertificate")),
        "Restrictions": _parse_restrictions(_find(root_el, "Restrictions")),
    }


# ─── XML builders ─────────────────────────────────────────────────────────────

def _build_origins(parent: Element, origins: list):
    origins_el = SubElement(parent, "Origins")
    SubElement(origins_el, "Quantity").text = str(len(origins))
    if origins:
        items_el = SubElement(origins_el, "Items")
        for o in origins:
            origin_el = SubElement(items_el, "Origin")
            SubElement(origin_el, "Id").text = o.get("Id", "")
            SubElement(origin_el, "DomainName").text = o.get("DomainName", "")
            SubElement(origin_el, "OriginPath").text = o.get("OriginPath", "")
            SubElement(origin_el, "ConnectionAttempts").text = o.get("ConnectionAttempts", "3")
            SubElement(origin_el, "ConnectionTimeout").text = o.get("ConnectionTimeout", "10")
            if "S3OriginConfig" in o:
                s3_el = SubElement(origin_el, "S3OriginConfig")
                SubElement(s3_el, "OriginAccessIdentity").text = o["S3OriginConfig"].get(
                    "OriginAccessIdentity", ""
                )
            elif "CustomOriginConfig" in o:
                coc = o["CustomOriginConfig"]
                coc_el = SubElement(origin_el, "CustomOriginConfig")
                SubElement(coc_el, "HTTPPort").text = coc.get("HTTPPort", "80")
                SubElement(coc_el, "HTTPSPort").text = coc.get("HTTPSPort", "443")
                SubElement(coc_el, "OriginProtocolPolicy").text = coc.get(
                    "OriginProtocolPolicy", "https-only"
                )
                ssl_el = SubElement(coc_el, "OriginSSLProtocols")
                protos = coc.get("OriginSSLProtocols", ["TLSv1.2"])
                SubElement(ssl_el, "Quantity").text = str(len(protos))
                items_inner = SubElement(ssl_el, "Items")
                for p in protos:
                    SubElement(items_inner, "SslProtocol").text = p


def _build_default_cache_behavior(parent: Element, dcb: dict):
    dcb_el = SubElement(parent, "DefaultCacheBehavior")
    SubElement(dcb_el, "TargetOriginId").text = dcb.get("TargetOriginId", "")
    SubElement(dcb_el, "ViewerProtocolPolicy").text = dcb.get("ViewerProtocolPolicy", "allow-all")
    SubElement(dcb_el, "CachePolicyId").text = dcb.get("CachePolicyId", "")
    SubElement(dcb_el, "OriginRequestPolicyId").text = dcb.get("OriginRequestPolicyId", "")
    SubElement(dcb_el, "Compress").text = str(dcb.get("Compress", "false")).lower()
    am_el = SubElement(dcb_el, "AllowedMethods")
    allowed = dcb.get("AllowedMethods", ["GET", "HEAD"])
    SubElement(am_el, "Quantity").text = str(len(allowed))
    am_items = SubElement(am_el, "Items")
    for m in allowed:
        SubElement(am_items, "Method").text = m
    cached = dcb.get("CachedMethods", ["GET", "HEAD"])
    cm_el = SubElement(am_el, "CachedMethods")
    SubElement(cm_el, "Quantity").text = str(len(cached))
    cm_items = SubElement(cm_el, "Items")
    for m in cached:
        SubElement(cm_items, "Method").text = m


def _build_aliases(parent: Element, aliases: list):
    aliases_el = SubElement(parent, "Aliases")
    SubElement(aliases_el, "Quantity").text = str(len(aliases))
    if aliases:
        items_el = SubElement(aliases_el, "Items")
        for a in aliases:
            SubElement(items_el, "CNAME").text = a


def _build_viewer_certificate(parent: Element, vc: dict):
    vc_el = SubElement(parent, "ViewerCertificate")
    SubElement(vc_el, "CloudFrontDefaultCertificate").text = vc.get(
        "CloudFrontDefaultCertificate", "true"
    )
    if vc.get("ACMCertificateArn"):
        SubElement(vc_el, "ACMCertificateArn").text = vc["ACMCertificateArn"]
    if vc.get("IAMCertificateId"):
        SubElement(vc_el, "IAMCertificateId").text = vc["IAMCertificateId"]
    if vc.get("SSLSupportMethod"):
        SubElement(vc_el, "SSLSupportMethod").text = vc["SSLSupportMethod"]
    SubElement(vc_el, "MinimumProtocolVersion").text = vc.get("MinimumProtocolVersion", "TLSv1")
    SubElement(vc_el, "CertificateSource").text = vc.get("CertificateSource", "cloudfront")


def _build_restrictions(parent: Element, restrictions: dict):
    rest_el = SubElement(parent, "Restrictions")
    gr = restrictions.get("GeoRestriction", {})
    gr_el = SubElement(rest_el, "GeoRestriction")
    SubElement(gr_el, "RestrictionType").text = gr.get("RestrictionType", "none")
    locs = gr.get("Items", [])
    SubElement(gr_el, "Quantity").text = str(len(locs))
    if locs:
        items_el = SubElement(gr_el, "Items")
        for loc in locs:
            SubElement(items_el, "Location").text = loc


def _build_distribution_config(parent: Element, config: dict):
    SubElement(parent, "CallerReference").text = config.get("CallerReference", "")
    _build_aliases(parent, config.get("Aliases", []))
    SubElement(parent, "DefaultRootObject").text = config.get("DefaultRootObject", "")
    _build_origins(parent, config.get("Origins", []))
    _build_default_cache_behavior(parent, config.get("DefaultCacheBehavior", {}))
    SubElement(parent, "Comment").text = config.get("Comment", "")
    SubElement(parent, "PriceClass").text = config.get("PriceClass", "PriceClass_All")
    SubElement(parent, "Enabled").text = str(config.get("Enabled", True)).lower()
    _build_viewer_certificate(parent, config.get("ViewerCertificate", {
        "CloudFrontDefaultCertificate": "true", "MinimumProtocolVersion": "TLSv1"
    }))
    _build_restrictions(parent, config.get("Restrictions", {
        "GeoRestriction": {"RestrictionType": "none", "Quantity": 0, "Items": []}
    }))
    SubElement(parent, "WebACLId").text = config.get("WebACLId", "")
    SubElement(parent, "HttpVersion").text = config.get("HttpVersion", "http2")
    SubElement(parent, "IsIPV6Enabled").text = str(config.get("IsIPV6Enabled", True)).lower()


def _build_distribution(parent: Element, dist: dict):
    SubElement(parent, "Id").text = dist["Id"]
    SubElement(parent, "ARN").text = dist["ARN"]
    SubElement(parent, "Status").text = dist["Status"]
    SubElement(parent, "DomainName").text = dist["DomainName"]
    SubElement(parent, "LastModifiedTime").text = dist["LastModifiedTime"]
    active_trusted_el = SubElement(parent, "ActiveTrustedSigners")
    SubElement(active_trusted_el, "Enabled").text = "false"
    SubElement(active_trusted_el, "Quantity").text = "0"
    dist_config_el = SubElement(parent, "DistributionConfig")
    _build_distribution_config(dist_config_el, dist["DistributionConfig"])


def _build_distribution_summary(parent: Element, dist: dict):
    summary_el = SubElement(parent, "DistributionSummary")
    SubElement(summary_el, "Id").text = dist["Id"]
    SubElement(summary_el, "ARN").text = dist["ARN"]
    SubElement(summary_el, "Status").text = dist["Status"]
    SubElement(summary_el, "DomainName").text = dist["DomainName"]
    SubElement(summary_el, "LastModifiedTime").text = dist["LastModifiedTime"]
    config = dist["DistributionConfig"]
    _build_aliases(summary_el, config.get("Aliases", []))
    _build_origins(summary_el, config.get("Origins", []))
    _build_default_cache_behavior(summary_el, config.get("DefaultCacheBehavior", {}))
    SubElement(summary_el, "Comment").text = config.get("Comment", "")
    SubElement(summary_el, "PriceClass").text = config.get("PriceClass", "PriceClass_All")
    SubElement(summary_el, "Enabled").text = str(config.get("Enabled", True)).lower()
    _build_viewer_certificate(summary_el, config.get("ViewerCertificate", {
        "CloudFrontDefaultCertificate": "true", "MinimumProtocolVersion": "TLSv1"
    }))
    _build_restrictions(summary_el, config.get("Restrictions", {
        "GeoRestriction": {"RestrictionType": "none", "Quantity": 0, "Items": []}
    }))
    SubElement(summary_el, "WebACLId").text = config.get("WebACLId", "")
    SubElement(summary_el, "HttpVersion").text = config.get("HttpVersion", "http2")
    SubElement(summary_el, "IsIPV6Enabled").text = str(config.get("IsIPV6Enabled", True)).lower()


# ─── distribution handlers ────────────────────────────────────────────────────

def _create_distribution(body: bytes) -> tuple:
    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)

    # The root element may be DistributionConfig directly or wrapped
    local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if local == "DistributionConfig":
        config_el = root
    else:
        config_el = _find(root, "DistributionConfig") or root

    config = _parse_distribution_config(config_el)

    if not config.get("CallerReference"):
        return _error_response("MissingParameter", "CallerReference is required", 400)
    if not config.get("Origins"):
        return _error_response("MissingParameter", "Origins is required", 400)

    # Check CallerReference idempotency
    with _lock:
        for existing in _distributions.values():
            if existing["DistributionConfig"].get("CallerReference") == config["CallerReference"]:
                dist = existing
                etag = _etags[dist["Id"]]
                return _xml_response(
                    "Distribution",
                    lambda root: _build_distribution(root, dist),
                    200,
                    {"ETag": etag,
                     "Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/distribution/{dist['Id']}"},
                )

        dist_id = _dist_id()
        while dist_id in _distributions:
            dist_id = _dist_id()

        etag = _new_etag()
        dist = {
            "Id": dist_id,
            "ARN": _dist_arn(dist_id),
            "Status": "Deployed",
            "DomainName": _domain_name(dist_id),
            "LastModifiedTime": _now_iso(),
            "DistributionConfig": config,
        }
        _distributions[dist_id] = dist
        _invalidations[dist_id] = {}
        _etags[dist_id] = etag

    return _xml_response(
        "Distribution",
        lambda root: _build_distribution(root, dist),
        201,
        {
            "ETag": etag,
            "Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/distribution/{dist_id}",
        },
    )


def _get_distribution(dist_id: str) -> tuple:
    with _lock:
        dist = _distributions.get(dist_id)
        if not dist:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        etag = _etags.get(dist_id, "")
        dist_copy = dict(dist)

    return _xml_response(
        "Distribution",
        lambda root: _build_distribution(root, dist_copy),
        200,
        {"ETag": etag},
    )


def _get_distribution_config(dist_id: str) -> tuple:
    with _lock:
        dist = _distributions.get(dist_id)
        if not dist:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        etag = _etags.get(dist_id, "")
        config = dict(dist["DistributionConfig"])

    def build(root):
        _build_distribution_config(root, config)

    return _xml_response("DistributionConfig", build, 200, {"ETag": etag})


def _update_distribution(dist_id: str, body: bytes, if_match: str) -> tuple:
    with _lock:
        dist = _distributions.get(dist_id)
        if not dist:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        current_etag = _etags.get(dist_id, "")
        if if_match and if_match != current_etag:
            return _error_response("InvalidIfMatchVersion",
                                   "If-Match header does not match current ETag", 412)

    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)

    local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if local == "DistributionConfig":
        config_el = root
    else:
        config_el = _find(root, "DistributionConfig") or root

    new_config = _parse_distribution_config(config_el)

    with _lock:
        dist["DistributionConfig"] = new_config
        dist["LastModifiedTime"] = _now_iso()
        new_etag = _new_etag()
        _etags[dist_id] = new_etag
        dist_copy = dict(dist)

    return _xml_response(
        "Distribution",
        lambda root: _build_distribution(root, dist_copy),
        200,
        {"ETag": new_etag},
    )


def _delete_distribution(dist_id: str, if_match: str) -> tuple:
    with _lock:
        dist = _distributions.get(dist_id)
        if not dist:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        current_etag = _etags.get(dist_id, "")
        if if_match and if_match != current_etag:
            return _error_response("InvalidIfMatchVersion",
                                   "If-Match header does not match current ETag", 412)
        if dist["DistributionConfig"].get("Enabled", True):
            return _error_response(
                "DistributionNotDisabled",
                "The distribution must be disabled before it can be deleted.",
                409,
            )
        del _distributions[dist_id]
        _invalidations.pop(dist_id, None)
        _etags.pop(dist_id, None)

    return 204, {}, b""


def _list_distributions() -> tuple:
    with _lock:
        dists = list(_distributions.values())

    def build(root):
        SubElement(root, "Marker").text = ""
        SubElement(root, "MaxItems").text = "100"
        SubElement(root, "IsTruncated").text = "false"
        SubElement(root, "Quantity").text = str(len(dists))
        if dists:
            items_el = SubElement(root, "Items")
            for dist in dists:
                _build_distribution_summary(items_el, dist)

    return _xml_response("DistributionList", build)


# ─── invalidation handlers ────────────────────────────────────────────────────

def _parse_invalidation_batch(root_el):
    paths_el = _find(root_el, "Paths")
    items = []
    if paths_el is not None:
        items_el = _find(paths_el, "Items")
        if items_el is not None:
            items = [c.text for c in _findall(items_el, "Path") if c.text]
    caller_ref = _text(root_el, "CallerReference", "")
    return {"Paths": items, "CallerReference": caller_ref}


def _build_invalidation(parent: Element, inv: dict):
    SubElement(parent, "Id").text = inv["Id"]
    SubElement(parent, "Status").text = inv["Status"]
    SubElement(parent, "CreateTime").text = inv["CreateTime"]
    ib_el = SubElement(parent, "InvalidationBatch")
    paths = inv["InvalidationBatch"]["Paths"]
    paths_el = SubElement(ib_el, "Paths")
    SubElement(paths_el, "Quantity").text = str(len(paths))
    if paths:
        items_el = SubElement(paths_el, "Items")
        for p in paths:
            SubElement(items_el, "Path").text = p
    SubElement(ib_el, "CallerReference").text = inv["InvalidationBatch"].get("CallerReference", "")


def _create_invalidation(dist_id: str, body: bytes) -> tuple:
    with _lock:
        if dist_id not in _distributions:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)

    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)

    local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    batch_el = root if local == "InvalidationBatch" else _find(root, "InvalidationBatch") or root
    batch = _parse_invalidation_batch(batch_el)

    inv_id = _inv_id()
    inv = {
        "Id": inv_id,
        "Status": "Completed",
        "CreateTime": _now_iso(),
        "InvalidationBatch": batch,
    }

    with _lock:
        if dist_id not in _invalidations:
            _invalidations[dist_id] = {}
        _invalidations[dist_id][inv_id] = inv

    return _xml_response(
        "Invalidation",
        lambda root: _build_invalidation(root, inv),
        201,
        {"Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/distribution/{dist_id}/invalidation/{inv_id}"},
    )


def _get_invalidation(dist_id: str, inv_id: str) -> tuple:
    with _lock:
        if dist_id not in _distributions:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        dist_invs = _invalidations.get(dist_id, {})
        inv = dist_invs.get(inv_id)
        if not inv:
            return _error_response("NoSuchInvalidation", f"Invalidation {inv_id} not found", 404)
        inv_copy = dict(inv)

    return _xml_response("Invalidation", lambda root: _build_invalidation(root, inv_copy))


def _list_invalidations(dist_id: str) -> tuple:
    with _lock:
        if dist_id not in _distributions:
            return _error_response("NoSuchDistribution", f"Distribution {dist_id} not found", 404)
        invs = list(_invalidations.get(dist_id, {}).values())

    def build(root):
        SubElement(root, "Marker").text = ""
        SubElement(root, "MaxItems").text = "100"
        SubElement(root, "IsTruncated").text = "false"
        SubElement(root, "Quantity").text = str(len(invs))
        if invs:
            items_el = SubElement(root, "Items")
            for inv in invs:
                summary = SubElement(items_el, "InvalidationSummary")
                SubElement(summary, "Id").text = inv["Id"]
                SubElement(summary, "CreateTime").text = inv["CreateTime"]
                SubElement(summary, "Status").text = inv["Status"]

    return _xml_response("InvalidationList", build)


# ─── OAI handlers ─────────────────────────────────────────────────────────────

def _parse_oai_config(root_el):
    local = root_el.tag.split("}")[-1] if "}" in root_el.tag else root_el.tag
    config_el = root_el if local == "CloudFrontOriginAccessIdentityConfig" else (
        _find(root_el, "CloudFrontOriginAccessIdentityConfig") or root_el
    )
    return {
        "CallerReference": _text(config_el, "CallerReference", ""),
        "Comment": _text(config_el, "Comment", ""),
    }


def _build_oai(parent: Element, oai: dict):
    SubElement(parent, "Id").text = oai["Id"]
    SubElement(parent, "S3CanonicalUserId").text = oai["S3CanonicalUserId"]
    config_el = SubElement(parent, "CloudFrontOriginAccessIdentityConfig")
    SubElement(config_el, "CallerReference").text = oai["Config"]["CallerReference"]
    SubElement(config_el, "Comment").text = oai["Config"]["Comment"]


def _create_oai(body: bytes) -> tuple:
    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)
    config = _parse_oai_config(root)
    if not config.get("CallerReference"):
        return _error_response("MissingParameter", "CallerReference is required", 400)

    with _lock:
        for existing in _oai.values():
            if existing["Config"]["CallerReference"] == config["CallerReference"]:
                etag = existing.get("ETag", "")
                oai_copy = dict(existing)
                return _xml_response(
                    "CloudFrontOriginAccessIdentity",
                    lambda root: _build_oai(root, oai_copy),
                    200,
                    {"ETag": etag,
                     "Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/origin-access-identity/cloudfront/{oai_copy['Id']}"},
                )

        oai_id = _oai_id()
        while oai_id in _oai:
            oai_id = _oai_id()
        etag = _new_etag()
        oai = {
            "Id": oai_id,
            "S3CanonicalUserId": "".join(random.choices("0123456789abcdef", k=96)),
            "Config": config,
            "ETag": etag,
        }
        _oai[oai_id] = oai

    return _xml_response(
        "CloudFrontOriginAccessIdentity",
        lambda root: _build_oai(root, oai),
        201,
        {
            "ETag": etag,
            "Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/origin-access-identity/cloudfront/{oai_id}",
        },
    )


def _get_oai(oai_id: str) -> tuple:
    with _lock:
        oai = _oai.get(oai_id)
        if not oai:
            return _error_response(
                "NoSuchCloudFrontOriginAccessIdentity",
                f"OAI {oai_id} not found",
                404,
            )
        etag = oai.get("ETag", "")
        oai_copy = dict(oai)

    return _xml_response(
        "CloudFrontOriginAccessIdentity",
        lambda root: _build_oai(root, oai_copy),
        200,
        {"ETag": etag},
    )


def _list_oais() -> tuple:
    with _lock:
        oais = list(_oai.values())

    def build(root):
        SubElement(root, "Marker").text = ""
        SubElement(root, "MaxItems").text = "100"
        SubElement(root, "IsTruncated").text = "false"
        SubElement(root, "Quantity").text = str(len(oais))
        if oais:
            items_el = SubElement(root, "Items")
            for oai in oais:
                summary = SubElement(items_el, "CloudFrontOriginAccessIdentitySummary")
                SubElement(summary, "Id").text = oai["Id"]
                SubElement(summary, "S3CanonicalUserId").text = oai["S3CanonicalUserId"]
                SubElement(summary, "Comment").text = oai["Config"].get("Comment", "")

    return _xml_response("CloudFrontOriginAccessIdentityList", build)


def _delete_oai(oai_id: str, if_match: str) -> tuple:
    with _lock:
        oai = _oai.get(oai_id)
        if not oai:
            return _error_response(
                "NoSuchCloudFrontOriginAccessIdentity",
                f"OAI {oai_id} not found",
                404,
            )
        current_etag = oai.get("ETag", "")
        if if_match and if_match != current_etag:
            return _error_response("InvalidIfMatchVersion",
                                   "If-Match header does not match current ETag", 412)
        del _oai[oai_id]
    return 204, {}, b""


# ─── OAC handlers ─────────────────────────────────────────────────────────────

def _parse_oac_config(root_el):
    local = root_el.tag.split("}")[-1] if "}" in root_el.tag else root_el.tag
    config_el = root_el if local == "OriginAccessControlConfig" else (
        _find(root_el, "OriginAccessControlConfig") or root_el
    )
    return {
        "Name": _text(config_el, "Name", ""),
        "Description": _text(config_el, "Description", ""),
        "SigningProtocol": _text(config_el, "SigningProtocol", "sigv4"),
        "SigningBehavior": _text(config_el, "SigningBehavior", "always"),
        "OriginAccessControlOriginType": _text(
            config_el, "OriginAccessControlOriginType", "s3"
        ),
    }


def _build_oac(parent: Element, oac: dict):
    SubElement(parent, "Id").text = oac["Id"]
    config_el = SubElement(parent, "OriginAccessControlConfig")
    SubElement(config_el, "Name").text = oac["Config"]["Name"]
    SubElement(config_el, "Description").text = oac["Config"].get("Description", "")
    SubElement(config_el, "SigningProtocol").text = oac["Config"].get("SigningProtocol", "sigv4")
    SubElement(config_el, "SigningBehavior").text = oac["Config"].get("SigningBehavior", "always")
    SubElement(config_el, "OriginAccessControlOriginType").text = oac["Config"].get(
        "OriginAccessControlOriginType", "s3"
    )


def _create_oac(body: bytes) -> tuple:
    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)
    config = _parse_oac_config(root)
    if not config.get("Name"):
        return _error_response("MissingParameter", "Name is required", 400)

    oac_id = _oac_id()
    etag = _new_etag()
    oac = {"Id": oac_id, "Config": config, "ETag": etag}

    with _lock:
        _oac[oac_id] = oac

    return _xml_response(
        "OriginAccessControl",
        lambda root: _build_oac(root, oac),
        201,
        {
            "ETag": etag,
            "Location": f"https://cloudfront.amazonaws.com/{API_VERSION}/origin-access-control/{oac_id}",
        },
    )


def _get_oac(oac_id: str) -> tuple:
    with _lock:
        oac = _oac.get(oac_id)
        if not oac:
            return _error_response("NoSuchOriginAccessControl",
                                   f"OAC {oac_id} not found", 404)
        etag = oac.get("ETag", "")
        oac_copy = dict(oac)

    return _xml_response(
        "OriginAccessControl",
        lambda root: _build_oac(root, oac_copy),
        200,
        {"ETag": etag},
    )


def _list_oacs() -> tuple:
    with _lock:
        oacs = list(_oac.values())

    def build(root):
        SubElement(root, "Marker").text = ""
        SubElement(root, "MaxItems").text = "100"
        SubElement(root, "IsTruncated").text = "false"
        SubElement(root, "Quantity").text = str(len(oacs))
        if oacs:
            items_el = SubElement(root, "Items")
            for oac in oacs:
                summary = SubElement(items_el, "OriginAccessControlSummary")
                SubElement(summary, "Id").text = oac["Id"]
                SubElement(summary, "Name").text = oac["Config"]["Name"]
                SubElement(summary, "Description").text = oac["Config"].get("Description", "")
                SubElement(summary, "SigningProtocol").text = oac["Config"].get("SigningProtocol", "sigv4")
                SubElement(summary, "SigningBehavior").text = oac["Config"].get("SigningBehavior", "always")
                SubElement(summary, "OriginAccessControlOriginType").text = oac["Config"].get(
                    "OriginAccessControlOriginType", "s3"
                )

    return _xml_response("OriginAccessControlList", build)


def _delete_oac(oac_id: str, if_match: str) -> tuple:
    with _lock:
        oac = _oac.get(oac_id)
        if not oac:
            return _error_response("NoSuchOriginAccessControl",
                                   f"OAC {oac_id} not found", 404)
        current_etag = oac.get("ETag", "")
        if if_match and if_match != current_etag:
            return _error_response("InvalidIfMatchVersion",
                                   "If-Match header does not match current ETag", 412)
        del _oac[oac_id]
    return 204, {}, b""


# ─── tagging handlers ─────────────────────────────────────────────────────────

def _list_tags(resource_arn: str) -> tuple:
    with _lock:
        tag_dict = dict(_tags.get(resource_arn, {}))

    def build(root):
        if tag_dict:
            items_el = SubElement(root, "Items")
            for k, v in tag_dict.items():
                tag_el = SubElement(items_el, "Tag")
                SubElement(tag_el, "Key").text = k
                SubElement(tag_el, "Value").text = v

    return _xml_response("Tags", build)


def _tag_resource(resource_arn: str, body: bytes) -> tuple:
    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)

    local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    tags_el = root if local == "Tags" else _find(root, "Tags") or root
    items_el = _find(tags_el, "Items")
    new_tags = {}
    if items_el is not None:
        for tag_el in _findall(items_el, "Tag"):
            key = _text(tag_el, "Key")
            val = _text(tag_el, "Value", "")
            if key:
                new_tags[key] = val

    with _lock:
        existing = _tags.get(resource_arn, {})
        existing.update(new_tags)
        _tags[resource_arn] = existing

    return 204, {}, b""


def _untag_resource(resource_arn: str, body: bytes) -> tuple:
    root = _parse_body(body)
    if root is None:
        return _error_response("MissingBody", "Request body is required", 400)

    local = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    tag_keys_el = root if local == "TagKeys" else _find(root, "TagKeys") or root
    items_el = _find(tag_keys_el, "Items")
    keys_to_remove = []
    if items_el is not None:
        keys_to_remove = [c.text for c in _findall(items_el, "Key") if c.text]

    with _lock:
        existing = _tags.get(resource_arn, {})
        for k in keys_to_remove:
            existing.pop(k, None)
        _tags[resource_arn] = existing

    return 204, {}, b""


# ─── main request handler ─────────────────────────────────────────────────────

_PATH_RE = re.compile(
    r"^/2020-05-31/"
    r"(?P<resource>distribution|origin-access-identity/cloudfront|origin-access-control|tagging)"
    r"(?:/(?P<id>[^/]+))?(?:/(?P<subresource>config|invalidation)(?:/(?P<subid>[^/]+))?)?$"
)


async def handle_request(method: str, path: str, headers: dict, body: bytes,
                         query_params: dict) -> tuple:
    if_match = headers.get("if-match", "")

    m = _PATH_RE.match(path)
    if not m:
        return _error_response("InvalidRequest", f"Unrecognized path: {path}", 400)

    resource = m.group("resource")
    res_id = m.group("id")
    subresource = m.group("subresource")
    subid = m.group("subid")

    # ── distributions ──
    if resource == "distribution":
        if not res_id:
            if method == "GET":
                return _list_distributions()
            if method == "POST":
                return _create_distribution(body)
        elif subresource == "config":
            if method == "GET":
                return _get_distribution_config(res_id)
            if method == "PUT":
                return _update_distribution(res_id, body, if_match)
        elif subresource == "invalidation":
            if not subid:
                if method == "GET":
                    return _list_invalidations(res_id)
                if method == "POST":
                    return _create_invalidation(res_id, body)
            else:
                if method == "GET":
                    return _get_invalidation(res_id, subid)
        else:
            if method == "GET":
                return _get_distribution(res_id)
            if method == "DELETE":
                return _delete_distribution(res_id, if_match)

    # ── origin access identity ──
    elif resource == "origin-access-identity/cloudfront":
        if not res_id:
            if method == "GET":
                return _list_oais()
            if method == "POST":
                return _create_oai(body)
        else:
            if method == "GET":
                return _get_oai(res_id)
            if method == "DELETE":
                return _delete_oai(res_id, if_match)

    # ── origin access control ──
    elif resource == "origin-access-control":
        if not res_id:
            if method == "GET":
                return _list_oacs()
            if method == "POST":
                return _create_oac(body)
        else:
            if method == "GET":
                return _get_oac(res_id)
            if method == "DELETE":
                return _delete_oac(res_id, if_match)

    # ── tagging ──
    elif resource == "tagging":
        operation = (query_params.get("Operation", [""])[0]
                     if isinstance(query_params.get("Operation"), list)
                     else query_params.get("Operation", ""))
        resource_arn = (query_params.get("Resource", [""])[0]
                        if isinstance(query_params.get("Resource"), list)
                        else query_params.get("Resource", ""))
        if method == "GET":
            return _list_tags(resource_arn)
        if method == "POST" and operation == "Tag":
            return _tag_resource(resource_arn, body)
        if method == "POST" and operation == "Untag":
            return _untag_resource(resource_arn, body)

    return _error_response("InvalidRequest",
                           f"Unsupported {method} {path}", 400)
