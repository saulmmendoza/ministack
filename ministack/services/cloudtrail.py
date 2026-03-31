"""
CloudTrail Service Emulator.
JSON-based API via X-Amz-Target (CloudTrail_20131101).
Supports: CreateTrail, DeleteTrail, DescribeTrails, GetTrail, ListTrails,
          GetTrailStatus, StartLogging, StopLogging,
          PutEventSelectors, GetEventSelectors,
          PutInsightSelectors, GetInsightSelectors,
          LookupEvents,
          AddTags, RemoveTags, ListTags.
"""

import json
import time
import logging

from ministack.core.responses import json_response, error_response_json, new_uuid, now_iso

logger = logging.getLogger("cloudtrail")

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"

_trails: dict = {}   # name -> trail dict
_trail_status: dict = {}   # trail_arn -> status dict
_event_selectors: dict = {}   # trail_arn -> list of event selector dicts
_insight_selectors: dict = {}   # trail_arn -> list of insight selector dicts
_tags: dict = {}   # trail_arn -> list of {Key, Value}
_events: list = []   # list of recorded event dicts (for LookupEvents)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _trail_arn(name: str) -> str:
    return f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/{name}"


def _resolve(trail_name_or_arn: str):
    """Return (name, trail_dict) by name or ARN, or (None, None) if not found."""
    if not trail_name_or_arn:
        return None, None
    if trail_name_or_arn in _trails:
        return trail_name_or_arn, _trails[trail_name_or_arn]
    for name, t in _trails.items():
        if t["TrailARN"] == trail_name_or_arn:
            return name, t
    return None, None


def _trail_out(trail: dict) -> dict:
    """Return the public representation of a trail."""
    result = {
        "Name": trail["Name"],
        "S3BucketName": trail["S3BucketName"],
        "IncludeGlobalServiceEvents": trail.get("IncludeGlobalServiceEvents", True),
        "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
        "HomeRegion": trail.get("HomeRegion", REGION),
        "TrailARN": trail["TrailARN"],
        "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
        "HasCustomEventSelectors": trail.get("HasCustomEventSelectors", False),
        "HasInsightSelectors": trail.get("HasInsightSelectors", False),
        "IsOrganizationTrail": trail.get("IsOrganizationTrail", False),
    }
    for opt in ("S3KeyPrefix", "SnsTopicName", "SnsTopicARN",
                "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn", "KMSKeyId"):
        if trail.get(opt):
            result[opt] = trail[opt]
    return result


# ---------------------------------------------------------------------------
# Trail lifecycle
# ---------------------------------------------------------------------------

def _create_trail(data: dict):
    name = data.get("Name", "").strip()
    if not name:
        return error_response_json("InvalidTrailNameException", "Trail name is required.", 400)
    if name in _trails:
        return error_response_json(
            "TrailAlreadyExistsException",
            f"Trail {name} already exists.", 400,
        )
    bucket = data.get("S3BucketName", "").strip()
    if not bucket:
        return error_response_json("S3BucketDoesNotExistException", "S3BucketName is required.", 400)

    arn = _trail_arn(name)
    trail = {
        "Name": name,
        "S3BucketName": bucket,
        "S3KeyPrefix": data.get("S3KeyPrefix", ""),
        "SnsTopicName": data.get("SnsTopicName", ""),
        "SnsTopicARN": (
            f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:{data['SnsTopicName']}"
            if data.get("SnsTopicName") else ""
        ),
        "IncludeGlobalServiceEvents": data.get("IncludeGlobalServiceEvents", True),
        "IsMultiRegionTrail": data.get("IsMultiRegionTrail", False),
        "EnableLogFileValidation": data.get("EnableLogFileValidation", False),
        "LogFileValidationEnabled": data.get("EnableLogFileValidation", False),
        "CloudWatchLogsLogGroupArn": data.get("CloudWatchLogsLogGroupArn", ""),
        "CloudWatchLogsRoleArn": data.get("CloudWatchLogsRoleArn", ""),
        "KMSKeyId": data.get("KMSKeyId", ""),
        "IsOrganizationTrail": data.get("IsOrganizationTrail", False),
        "HomeRegion": REGION,
        "TrailARN": arn,
        "HasCustomEventSelectors": False,
        "HasInsightSelectors": False,
    }
    _trails[name] = trail
    _trail_status[arn] = {
        "IsLogging": False,
        "LatestDeliveryError": "",
        "LatestNotificationError": "",
        "LatestDeliveryTime": None,
        "LatestNotificationTime": None,
        "StartLoggingTime": None,
        "StopLoggingTime": None,
    }
    _event_selectors[arn] = []
    _insight_selectors[arn] = []
    _tags[arn] = list(data.get("TagsList", []))

    return json_response(_trail_out(trail))


def _delete_trail(data: dict):
    name, trail = _resolve(data.get("Name", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('Name')} not found.", 404,
        )
    arn = trail["TrailARN"]
    del _trails[name]
    _trail_status.pop(arn, None)
    _event_selectors.pop(arn, None)
    _insight_selectors.pop(arn, None)
    _tags.pop(arn, None)
    return json_response({})


def _describe_trails(data: dict):
    trail_name_list = data.get("trailNameList", [])
    include_shadow = data.get("includeShadowTrails", True)
    if trail_name_list:
        results = []
        for ref in trail_name_list:
            _, t = _resolve(ref)
            if t:
                results.append(_trail_out(t))
    else:
        results = [_trail_out(t) for t in _trails.values()]
    return json_response({"trailList": results})


def _get_trail(data: dict):
    name, trail = _resolve(data.get("Name", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('Name')} not found.", 404,
        )
    return json_response({"Trail": _trail_out(trail)})


def _list_trails(data: dict):
    results = [{"TrailARN": t["TrailARN"], "Name": t["Name"], "HomeRegion": t["HomeRegion"]}
               for t in _trails.values()]
    return json_response({"Trails": results})


# ---------------------------------------------------------------------------
# Logging control
# ---------------------------------------------------------------------------

def _get_trail_status(data: dict):
    name, trail = _resolve(data.get("Name", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('Name')} not found.", 404,
        )
    status = _trail_status.get(trail["TrailARN"], {})
    result = {
        "IsLogging": status.get("IsLogging", False),
        "LatestDeliveryError": status.get("LatestDeliveryError", ""),
        "LatestNotificationError": status.get("LatestNotificationError", ""),
    }
    for ts_key in ("LatestDeliveryTime", "LatestNotificationTime",
                   "StartLoggingTime", "StopLoggingTime"):
        if status.get(ts_key) is not None:
            result[ts_key] = status[ts_key]
    return json_response(result)


def _start_logging(data: dict):
    name, trail = _resolve(data.get("Name", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('Name')} not found.", 404,
        )
    arn = trail["TrailARN"]
    _trail_status[arn]["IsLogging"] = True
    _trail_status[arn]["StartLoggingTime"] = now_iso()
    return json_response({})


def _stop_logging(data: dict):
    name, trail = _resolve(data.get("Name", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('Name')} not found.", 404,
        )
    arn = trail["TrailARN"]
    _trail_status[arn]["IsLogging"] = False
    _trail_status[arn]["StopLoggingTime"] = now_iso()
    return json_response({})


# ---------------------------------------------------------------------------
# Event selectors
# ---------------------------------------------------------------------------

def _put_event_selectors(data: dict):
    name, trail = _resolve(data.get("TrailName", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('TrailName')} not found.", 404,
        )
    arn = trail["TrailARN"]
    selectors = data.get("EventSelectors", [])
    advanced = data.get("AdvancedEventSelectors", [])

    _event_selectors[arn] = selectors
    trail["HasCustomEventSelectors"] = bool(selectors or advanced)

    return json_response({
        "TrailARN": arn,
        "EventSelectors": selectors,
        "AdvancedEventSelectors": advanced,
    })


def _get_event_selectors(data: dict):
    name, trail = _resolve(data.get("TrailName", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('TrailName')} not found.", 404,
        )
    arn = trail["TrailARN"]
    selectors = _event_selectors.get(arn, [])
    return json_response({
        "TrailARN": arn,
        "EventSelectors": selectors,
        "AdvancedEventSelectors": [],
    })


# ---------------------------------------------------------------------------
# Insight selectors
# ---------------------------------------------------------------------------

def _put_insight_selectors(data: dict):
    name, trail = _resolve(data.get("TrailName", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('TrailName')} not found.", 404,
        )
    arn = trail["TrailARN"]
    selectors = data.get("InsightSelectors", [])
    _insight_selectors[arn] = selectors
    trail["HasInsightSelectors"] = bool(selectors)
    return json_response({
        "TrailARN": arn,
        "InsightSelectors": selectors,
    })


def _get_insight_selectors(data: dict):
    name, trail = _resolve(data.get("TrailName", ""))
    if not trail:
        return error_response_json(
            "TrailNotFoundException",
            f"Trail {data.get('TrailName')} not found.", 404,
        )
    arn = trail["TrailARN"]
    selectors = _insight_selectors.get(arn, [])
    return json_response({
        "TrailARN": arn,
        "InsightSelectors": selectors,
    })


# ---------------------------------------------------------------------------
# LookupEvents
# ---------------------------------------------------------------------------

def _lookup_events(data: dict):
    lookup_attrs = data.get("LookupAttributes", [])
    start_time = data.get("StartTime")
    end_time = data.get("EndTime")
    max_results = data.get("MaxResults", 50)

    results = list(_events)

    # Filter by lookup attributes
    for attr in lookup_attrs:
        key = attr.get("AttributeKey", "")
        val = attr.get("AttributeValue", "")
        if key and val:
            results = [
                e for e in results
                if str(e.get(key, "")) == val
            ]

    # Filter by time range
    if start_time:
        results = [e for e in results if e.get("EventTime", 0) >= start_time]
    if end_time:
        results = [e for e in results if e.get("EventTime", 0) <= end_time]

    results = results[:max_results]
    return json_response({"Events": results, "NextToken": None})


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

def _add_tags(data: dict):
    arn = data.get("ResourceId", "")
    new_tags = data.get("TagsList", [])
    if arn not in _tags:
        # might be a name
        _, trail = _resolve(arn)
        if not trail:
            return error_response_json(
                "CloudTrailARNInvalidException",
                f"Resource {arn} not found.", 404,
            )
        arn = trail["TrailARN"]

    existing = {t["Key"]: t for t in _tags.get(arn, [])}
    for tag in new_tags:
        existing[tag["Key"]] = tag
    _tags[arn] = list(existing.values())
    return json_response({})


def _remove_tags(data: dict):
    arn = data.get("ResourceId", "")
    remove_tags = data.get("TagsList", [])
    if arn not in _tags:
        _, trail = _resolve(arn)
        if not trail:
            return error_response_json(
                "CloudTrailARNInvalidException",
                f"Resource {arn} not found.", 404,
            )
        arn = trail["TrailARN"]

    keys_to_remove = {t["Key"] for t in remove_tags}
    _tags[arn] = [t for t in _tags.get(arn, []) if t["Key"] not in keys_to_remove]
    return json_response({})


def _list_tags(data: dict):
    arns = data.get("ResourceIdList", [])
    result = []
    for arn in arns:
        actual_arn = arn
        if actual_arn not in _tags:
            _, trail = _resolve(arn)
            if trail:
                actual_arn = trail["TrailARN"]
        tags = _tags.get(actual_arn, [])
        result.append({"ResourceId": actual_arn, "TagsList": tags})
    return json_response({"ResourceTagList": result})


# ---------------------------------------------------------------------------
# Request dispatcher
# ---------------------------------------------------------------------------

async def handle_request(method, path, headers, body, query_params):
    target = headers.get("x-amz-target", "")
    action = target.split(".")[-1] if "." in target else ""

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return error_response_json("SerializationException", "Invalid JSON", 400)

    handlers = {
        "CreateTrail": _create_trail,
        "DeleteTrail": _delete_trail,
        "DescribeTrails": _describe_trails,
        "GetTrail": _get_trail,
        "ListTrails": _list_trails,
        "GetTrailStatus": _get_trail_status,
        "StartLogging": _start_logging,
        "StopLogging": _stop_logging,
        "PutEventSelectors": _put_event_selectors,
        "GetEventSelectors": _get_event_selectors,
        "PutInsightSelectors": _put_insight_selectors,
        "GetInsightSelectors": _get_insight_selectors,
        "LookupEvents": _lookup_events,
        "AddTags": _add_tags,
        "RemoveTags": _remove_tags,
        "ListTags": _list_tags,
    }

    handler = handlers.get(action)
    if not handler:
        return error_response_json("InvalidAction", f"Unknown action: {action}", 400)
    return handler(data)


def reset():
    _trails.clear()
    _trail_status.clear()
    _event_selectors.clear()
    _insight_selectors.clear()
    _tags.clear()
    _events.clear()
