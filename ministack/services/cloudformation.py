"""
CloudFormation Emulator.
Query-based API (Action=... in form body/query params), XML responses.
Supports: CreateStack, DescribeStacks, DeleteStack, UpdateStack, ListStacks,
          GetTemplate, ValidateTemplate, GetTemplateSummary,
          ListStackResources, DescribeStackResources, DescribeStackResource,
          DescribeStackEvents,
          CreateChangeSet, DescribeChangeSet, ExecuteChangeSet, DeleteChangeSet,
          ListChangeSets,
          ListExports, ListImports.
"""

import base64
import copy
import html
import json
import logging
import os
import re
import time
from urllib.parse import parse_qs

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from ministack.core.responses import new_uuid, now_iso

logger = logging.getLogger("cloudformation")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACCOUNT_ID = os.environ.get("MINISTACK_ACCOUNT_ID", "000000000000")
REGION = os.environ.get("MINISTACK_REGION", "us-east-1")
CFN_NS = "http://cloudformation.amazonaws.com/doc/2010-05-15/"

_STACK_NAME_RE = re.compile(r"^[a-zA-Z][-a-zA-Z0-9]*$")
_MAX_STACK_NAME_LEN = 128

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_stacks: dict = {}        # stack_name -> stack record
_events: dict = {}        # stack_name -> [event records]
_change_sets: dict = {}   # change_set_id -> change set record
_exports: dict = {}       # export_name -> {"Value": ..., "ExportingStackId": ...}


def reset():
    """Wipe all in-memory state (used by /_ministack/reset)."""
    _stacks.clear()
    _events.clear()
    _change_sets.clear()
    _exports.clear()


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _p(params, key, default=""):
    """Extract first value from parameter dict (handles query string lists)."""
    v = params.get(key, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v


def _esc(s):
    """XML-escape a value."""
    if s is None:
        return ""
    return html.escape(str(s))


def _xml(status, root_tag, inner):
    """Build a standard CloudFormation XML response."""
    body = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<{root_tag} xmlns="{CFN_NS}">'
        f'{inner}'
        f'<ResponseMetadata><RequestId>{new_uuid()}</RequestId></ResponseMetadata>'
        f'</{root_tag}>'
    ).encode("utf-8")
    return status, {"Content-Type": "application/xml"}, body


def _error(code, message, status=400):
    """Build a CloudFormation XML error response."""
    etype = "Sender" if status < 500 else "Receiver"
    body = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<ErrorResponse xmlns="{CFN_NS}">'
        f'<Error><Type>{etype}</Type><Code>{_esc(code)}</Code>'
        f'<Message>{_esc(message)}</Message></Error>'
        f'<RequestId>{new_uuid()}</RequestId>'
        f'</ErrorResponse>'
    ).encode("utf-8")
    return status, {"Content-Type": "application/xml"}, body


def _collect_indexed(params, prefix):
    """Collect Key/Value pairs from indexed parameters like Tags.member.N."""
    items = []
    idx = 1
    while True:
        key_param = f"{prefix}.member.{idx}.Key"
        val_param = f"{prefix}.member.{idx}.Value"
        key = _p(params, key_param, None)
        if key is None:
            key_param2 = f"{prefix}.{idx}.Key"
            val_param2 = f"{prefix}.{idx}.Value"
            key = _p(params, key_param2, None)
            if key is None:
                break
            val = _p(params, val_param2, "")
        else:
            val = _p(params, val_param, "")
        items.append({"Key": key, "Value": val})
        idx += 1
    return items


def _collect_parameters(params):
    """Collect Parameters.member.N.ParameterKey / ParameterValue."""
    result = []
    idx = 1
    while True:
        pk = _p(params, f"Parameters.member.{idx}.ParameterKey", None)
        if pk is None:
            break
        pv = _p(params, f"Parameters.member.{idx}.ParameterValue", "")
        result.append({"ParameterKey": pk, "ParameterValue": pv})
        idx += 1
    return result


def _collect_list(params, prefix):
    """Collect a simple list from prefix.member.N."""
    result = []
    idx = 1
    while True:
        v = _p(params, f"{prefix}.member.{idx}", None)
        if v is None:
            break
        result.append(v)
        idx += 1
    return result


def _make_stack_arn(name, uid=None):
    """Build a CloudFormation stack ARN."""
    uid = uid or new_uuid()
    return f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}:stack/{name}/{uid}"


def _find_stack(name_or_id):
    """Look up a stack by name or ARN. Returns (stack_name, stack_record) or (None, None)."""
    if name_or_id in _stacks:
        return name_or_id, _stacks[name_or_id]
    for sname, rec in _stacks.items():
        if rec.get("StackId") == name_or_id:
            return sname, rec
    return None, None


def _find_active_stack(name_or_id):
    """Find a stack that is NOT DELETE_COMPLETE."""
    sname, rec = _find_stack(name_or_id)
    if rec and rec.get("StackStatus") == "DELETE_COMPLETE":
        return None, None
    return sname, rec


def _add_event(stack_name, stack_id, resource_type, logical_id, physical_id,
               status, reason=""):
    """Append an event to the stack's event list."""
    if stack_name not in _events:
        _events[stack_name] = []
    _events[stack_name].insert(0, {
        "EventId": new_uuid(),
        "StackId": stack_id,
        "StackName": stack_name,
        "LogicalResourceId": logical_id,
        "PhysicalResourceId": physical_id,
        "ResourceType": resource_type,
        "ResourceStatus": status,
        "ResourceStatusReason": reason,
        "Timestamp": now_iso(),
    })


def _bool_str(val):
    """Convert a boolean-ish value to lowercase string."""
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val).lower() if val else "false"


def _parse_bool(val, default=False):
    """Parse a boolean parameter."""
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    return str(val).lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Template parsing
# ---------------------------------------------------------------------------

def _parse_template(body_str):
    """Parse a CloudFormation template from JSON or YAML string.
    Returns a dict or raises ValueError.
    """
    if not body_str or not body_str.strip():
        raise ValueError("Template body is empty")
    text = body_str.strip()
    # Try JSON first
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    # Try YAML
    if yaml is not None:
        try:
            return yaml.safe_load(text)
        except Exception:
            pass
    raise ValueError("Template must be valid JSON or YAML")


def _validate_template_structure(template):
    """Validate basic template structure. Returns list of errors."""
    errors = []
    if not isinstance(template, dict):
        errors.append("Template must be a JSON/YAML object")
        return errors
    if "Resources" not in template and "AWSTemplateFormatVersion" not in template:
        errors.append("Template must contain a Resources section or AWSTemplateFormatVersion")
    resources = template.get("Resources", {})
    if resources and not isinstance(resources, dict):
        errors.append("Resources must be a mapping")
    return errors


# ---------------------------------------------------------------------------
# Intrinsic function resolution
# ---------------------------------------------------------------------------

def _resolve_value(value, ctx):
    """Resolve CloudFormation intrinsic functions recursively.

    ctx keys:
        params      - dict of ParameterKey -> ParameterValue
        resources   - dict of LogicalId -> resource record (with PhysicalResourceId)
        stack_name  - current stack name
        stack_id    - current stack ARN
        conditions  - dict of condition name -> bool
        mappings    - dict of map definitions
        template    - the full template dict
    """
    if value is None:
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, list):
        return [_resolve_value(item, ctx) for item in value]
    if not isinstance(value, dict):
        return value

    # Intrinsic functions are single-key dicts
    if len(value) == 1:
        key = next(iter(value))
        handler = _INTRINSIC_MAP.get(key)
        if handler:
            return handler(value[key], ctx)

    # Regular dict — resolve all values
    return {k: _resolve_value(v, ctx) for k, v in value.items()}


def _fn_ref(val, ctx):
    """Handle Ref intrinsic."""
    name = str(val)
    # Pseudo parameters
    pseudo = {
        "AWS::StackName": ctx.get("stack_name", ""),
        "AWS::StackId": ctx.get("stack_id", ""),
        "AWS::Region": REGION,
        "AWS::AccountId": ACCOUNT_ID,
        "AWS::NoValue": "",
        "AWS::URLSuffix": "amazonaws.com",
        "AWS::Partition": "aws",
        "AWS::NotificationARNs": ctx.get("notification_arns", []),
    }
    if name in pseudo:
        return pseudo[name]
    # Parameters
    params = ctx.get("params", {})
    if name in params:
        return params[name]
    # Resources — return PhysicalResourceId
    resources = ctx.get("resources", {})
    if name in resources:
        res = resources[name]
        return res.get("PhysicalResourceId", name)
    return name


def _fn_sub(val, ctx):
    """Handle Fn::Sub intrinsic."""
    if isinstance(val, list):
        template_str = str(val[0]) if val else ""
        extra_vars = val[1] if len(val) > 1 and isinstance(val[1], dict) else {}
    else:
        template_str = str(val)
        extra_vars = {}

    resolved_extra = {k: _resolve_value(v, ctx) for k, v in extra_vars.items()}

    def replacer(match):
        var_name = match.group(1)
        if var_name in resolved_extra:
            return str(resolved_extra[var_name])
        return str(_fn_ref(var_name, ctx))

    return re.sub(r"\$\{([^}]+)\}", replacer, template_str)


def _fn_join(val, ctx):
    """Handle Fn::Join intrinsic."""
    if not isinstance(val, list) or len(val) < 2:
        return ""
    delimiter = str(val[0])
    items = _resolve_value(val[1], ctx)
    if not isinstance(items, list):
        return str(items)
    return delimiter.join(str(i) for i in items)


def _fn_select(val, ctx):
    """Handle Fn::Select intrinsic."""
    if not isinstance(val, list) or len(val) < 2:
        return ""
    index = int(_resolve_value(val[0], ctx))
    items = _resolve_value(val[1], ctx)
    if isinstance(items, list) and 0 <= index < len(items):
        return items[index]
    return ""


def _fn_split(val, ctx):
    """Handle Fn::Split intrinsic."""
    if not isinstance(val, list) or len(val) < 2:
        return []
    delimiter = str(_resolve_value(val[0], ctx))
    source = str(_resolve_value(val[1], ctx))
    return source.split(delimiter)


def _fn_getatt(val, ctx):
    """Handle Fn::GetAtt intrinsic."""
    if isinstance(val, list) and len(val) >= 2:
        logical_id = str(val[0])
        attr_name = str(val[1])
    elif isinstance(val, str) and "." in val:
        parts = val.split(".", 1)
        logical_id = parts[0]
        attr_name = parts[1]
    else:
        return ""
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    if attr_name in attrs:
        return attrs[attr_name]
    if attr_name == "Arn":
        return res.get("PhysicalResourceId", "")
    return res.get("PhysicalResourceId", "")


def _fn_if(val, ctx):
    """Handle Fn::If intrinsic."""
    if not isinstance(val, list) or len(val) < 3:
        return ""
    cond_name = str(val[0])
    conditions = ctx.get("conditions", {})
    cond_result = conditions.get(cond_name, False)
    if cond_result:
        return _resolve_value(val[1], ctx)
    return _resolve_value(val[2], ctx)


def _fn_equals(val, ctx):
    """Handle Fn::Equals intrinsic."""
    if not isinstance(val, list) or len(val) < 2:
        return False
    a = str(_resolve_value(val[0], ctx))
    b = str(_resolve_value(val[1], ctx))
    return a == b


def _fn_and(val, ctx):
    """Handle Fn::And intrinsic."""
    if not isinstance(val, list):
        return False
    return all(_resolve_value(item, ctx) for item in val)


def _fn_or(val, ctx):
    """Handle Fn::Or intrinsic."""
    if not isinstance(val, list):
        return False
    return any(_resolve_value(item, ctx) for item in val)


def _fn_not(val, ctx):
    """Handle Fn::Not intrinsic."""
    if not isinstance(val, list) or len(val) < 1:
        return True
    return not _resolve_value(val[0], ctx)


def _fn_base64(val, ctx):
    """Handle Fn::Base64 intrinsic."""
    resolved = _resolve_value(val, ctx)
    return base64.b64encode(str(resolved).encode("utf-8")).decode("utf-8")


def _fn_find_in_map(val, ctx):
    """Handle Fn::FindInMap intrinsic."""
    if not isinstance(val, list) or len(val) < 3:
        return ""
    map_name = str(_resolve_value(val[0], ctx))
    first_key = str(_resolve_value(val[1], ctx))
    second_key = str(_resolve_value(val[2], ctx))
    mappings = ctx.get("mappings", {})
    mapping = mappings.get(map_name, {})
    first_level = mapping.get(first_key, {})
    return first_level.get(second_key, "")


def _fn_import_value(val, ctx):
    """Handle Fn::ImportValue intrinsic."""
    export_name = str(_resolve_value(val, ctx))
    export_rec = _exports.get(export_name)
    if export_rec:
        return export_rec.get("Value", "")
    return ""


def _fn_getazs(val, ctx):
    """Handle Fn::GetAZs intrinsic."""
    region = _resolve_value(val, ctx) if val else REGION
    if not region:
        region = REGION
    return [f"{region}a", f"{region}b", f"{region}c"]


_INTRINSIC_MAP = {
    "Ref": _fn_ref,
    "Fn::Sub": _fn_sub,
    "Fn::Join": _fn_join,
    "Fn::Select": _fn_select,
    "Fn::Split": _fn_split,
    "Fn::GetAtt": _fn_getatt,
    "Fn::If": _fn_if,
    "Fn::Equals": _fn_equals,
    "Fn::And": _fn_and,
    "Fn::Or": _fn_or,
    "Fn::Not": _fn_not,
    "Fn::Base64": _fn_base64,
    "Fn::FindInMap": _fn_find_in_map,
    "Fn::ImportValue": _fn_import_value,
    "Fn::GetAZs": _fn_getazs,
}


def _evaluate_conditions(template, ctx):
    """Evaluate the Conditions section and populate ctx['conditions']."""
    conditions_section = template.get("Conditions", {})
    evaluated = {}
    for cond_name, cond_expr in conditions_section.items():
        evaluated[cond_name] = bool(_resolve_value(cond_expr, ctx))
    ctx["conditions"] = evaluated
    return evaluated


def _build_resolve_ctx(stack_rec):
    """Build a resolution context dict from a stack record."""
    params_dict = {}
    for p in stack_rec.get("Parameters", []):
        params_dict[p["ParameterKey"]] = p["ParameterValue"]

    template = {}
    try:
        template = _parse_template(stack_rec.get("TemplateBody", "{}"))
    except (ValueError, Exception):
        pass

    ctx = {
        "params": params_dict,
        "resources": stack_rec.get("Resources", {}),
        "stack_name": stack_rec.get("StackName", ""),
        "stack_id": stack_rec.get("StackId", ""),
        "conditions": {},
        "mappings": template.get("Mappings", {}),
        "template": template,
        "notification_arns": stack_rec.get("NotificationARNs", []),
    }
    _evaluate_conditions(template, ctx)
    return ctx


# ---------------------------------------------------------------------------
# Resource orchestration — provision and delete via service handlers
# ---------------------------------------------------------------------------

def _gateway_port():
    return os.environ.get("GATEWAY_PORT") or os.environ.get("EDGE_PORT") or "4566"


async def _provision_resource(resource_type, logical_id, properties, stack_name, ctx):
    """Provision a single resource by calling existing ministack service handlers.

    Returns (physical_id, attributes) tuple.
    """
    resolved_props = _resolve_value(properties, ctx) if properties else {}
    if not isinstance(resolved_props, dict):
        resolved_props = {}

    handler_fn = _RESOURCE_HANDLERS.get(resource_type)
    if handler_fn:
        try:
            return await handler_fn(logical_id, resolved_props, stack_name, ctx)
        except Exception as exc:
            logger.warning("Failed to provision %s/%s: %s", resource_type, logical_id, exc)
            return _fake_physical_id(resource_type, logical_id, stack_name), {}

    logger.warning("Unsupported resource type %s for %s — generating fake physical ID",
                   resource_type, logical_id)
    return _fake_physical_id(resource_type, logical_id, stack_name), {}


def _fake_physical_id(resource_type, logical_id, stack_name):
    """Generate a fake physical resource ID for unsupported types."""
    short = resource_type.split("::")[-1].lower() if "::" in resource_type else resource_type.lower()
    return f"{stack_name}-{logical_id}-{short}-{new_uuid()[:8]}"


async def _delete_resource(resource_type, logical_id, physical_id, properties, stack_name, ctx):
    """Delete a provisioned resource."""
    resolved_props = _resolve_value(properties, ctx) if properties else {}
    if not isinstance(resolved_props, dict):
        resolved_props = {}

    handler_fn = _RESOURCE_DELETE_HANDLERS.get(resource_type)
    if handler_fn:
        try:
            await handler_fn(logical_id, physical_id, resolved_props, stack_name, ctx)
        except Exception as exc:
            logger.warning("Failed to delete %s/%s (%s): %s",
                           resource_type, logical_id, physical_id, exc)
    else:
        logger.debug("No delete handler for %s/%s — skipping", resource_type, logical_id)


# -- S3 Bucket --

async def _provision_s3_bucket(logical_id, props, stack_name, ctx):
    from ministack.services import s3
    bucket_name = props.get("BucketName", f"{stack_name}-{logical_id}-{new_uuid()[:8]}".lower())
    await s3.handle_request("PUT", f"/{bucket_name}", {}, b"", {})
    arn = f"arn:aws:s3:::{bucket_name}"
    return bucket_name, {"Arn": arn, "DomainName": f"{bucket_name}.s3.amazonaws.com",
                          "RegionalDomainName": f"{bucket_name}.s3.{REGION}.amazonaws.com",
                          "WebsiteURL": f"http://{bucket_name}.s3-website-{REGION}.amazonaws.com"}


async def _delete_s3_bucket(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import s3
    await s3.handle_request("DELETE", f"/{physical_id}", {}, b"", {})


# -- SQS Queue --

async def _provision_sqs_queue(logical_id, props, stack_name, ctx):
    from ministack.services import sqs
    queue_name = props.get("QueueName", f"{stack_name}-{logical_id}")
    attrs = {}
    if props.get("VisibilityTimeout") is not None:
        attrs["VisibilityTimeout"] = str(props["VisibilityTimeout"])
    if props.get("DelaySeconds") is not None:
        attrs["DelaySeconds"] = str(props["DelaySeconds"])
    if props.get("MaximumMessageSize") is not None:
        attrs["MaximumMessageSize"] = str(props["MaximumMessageSize"])
    if props.get("MessageRetentionPeriod") is not None:
        attrs["MessageRetentionPeriod"] = str(props["MessageRetentionPeriod"])
    if props.get("FifoQueue"):
        attrs["FifoQueue"] = "true"
        if not queue_name.endswith(".fifo"):
            queue_name += ".fifo"
    if props.get("ContentBasedDeduplication"):
        attrs["ContentBasedDeduplication"] = "true"

    data = {"QueueName": queue_name}
    if attrs:
        data["Attributes"] = attrs

    hdrs = {"x-amz-target": "AmazonSQS.CreateQueue",
            "content-type": "application/x-amz-json-1.0"}
    status, _, resp_body = await sqs.handle_request("POST", "/", hdrs,
                                                    json.dumps(data).encode(), {})
    port = _gateway_port()
    queue_url = f"http://localhost:{port}/{ACCOUNT_ID}/{queue_name}"
    arn = f"arn:aws:sqs:{REGION}:{ACCOUNT_ID}:{queue_name}"
    if status < 300:
        try:
            resp = json.loads(resp_body)
            queue_url = resp.get("QueueUrl", queue_url)
        except Exception:
            pass
    return queue_url, {"Arn": arn, "QueueName": queue_name, "QueueUrl": queue_url}


async def _delete_sqs_queue(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import sqs
    data = {"QueueUrl": physical_id}
    hdrs = {"x-amz-target": "AmazonSQS.DeleteQueue",
            "content-type": "application/x-amz-json-1.0"}
    await sqs.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


# -- SNS Topic --

async def _provision_sns_topic(logical_id, props, stack_name, ctx):
    from ministack.services import sns
    topic_name = props.get("TopicName", f"{stack_name}-{logical_id}")
    body = f"Action=CreateTopic&Name={topic_name}"
    hdrs = {"content-type": "application/x-www-form-urlencoded"}
    await sns.handle_request("POST", "/", hdrs, body.encode(), {})
    arn = f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:{topic_name}"
    return arn, {"TopicName": topic_name}


async def _delete_sns_topic(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import sns
    body = f"Action=DeleteTopic&TopicArn={physical_id}"
    hdrs = {"content-type": "application/x-www-form-urlencoded"}
    await sns.handle_request("POST", "/", hdrs, body.encode(), {})


# -- DynamoDB Table --

async def _provision_dynamodb_table(logical_id, props, stack_name, ctx):
    from ministack.services import dynamodb
    table_name = props.get("TableName", f"{stack_name}-{logical_id}")
    data = {"TableName": table_name}
    if "KeySchema" in props:
        data["KeySchema"] = props["KeySchema"]
    else:
        data["KeySchema"] = [{"AttributeName": "id", "KeyType": "HASH"}]
    if "AttributeDefinitions" in props:
        data["AttributeDefinitions"] = props["AttributeDefinitions"]
    else:
        data["AttributeDefinitions"] = [{"AttributeName": "id", "AttributeType": "S"}]
    if "BillingMode" in props:
        data["BillingMode"] = props["BillingMode"]
    else:
        data["BillingMode"] = "PAY_PER_REQUEST"
    if "ProvisionedThroughput" in props:
        data["ProvisionedThroughput"] = props["ProvisionedThroughput"]
    if "GlobalSecondaryIndexes" in props:
        data["GlobalSecondaryIndexes"] = props["GlobalSecondaryIndexes"]
    if "LocalSecondaryIndexes" in props:
        data["LocalSecondaryIndexes"] = props["LocalSecondaryIndexes"]
    if "StreamSpecification" in props:
        data["StreamSpecification"] = props["StreamSpecification"]

    hdrs = {"x-amz-target": "DynamoDB_20120810.CreateTable",
            "content-type": "application/x-amz-json-1.0"}
    await dynamodb.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})
    arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT_ID}:table/{table_name}"
    return arn, {"Arn": arn, "TableName": table_name}


async def _delete_dynamodb_table(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import dynamodb
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    table_name = attrs.get("TableName") or props.get("TableName", logical_id)
    data = {"TableName": table_name}
    hdrs = {"x-amz-target": "DynamoDB_20120810.DeleteTable",
            "content-type": "application/x-amz-json-1.0"}
    await dynamodb.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


# -- CloudWatch Logs LogGroup --

async def _provision_log_group(logical_id, props, stack_name, ctx):
    from ministack.services import cloudwatch_logs
    group_name = props.get("LogGroupName", f"/aws/cloudformation/{stack_name}/{logical_id}")
    data = {"logGroupName": group_name}
    if "RetentionInDays" in props:
        data["retentionInDays"] = props["RetentionInDays"]
    hdrs = {"x-amz-target": "Logs_20140328.CreateLogGroup",
            "content-type": "application/x-amz-json-1.1"}
    await cloudwatch_logs.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})
    arn = f"arn:aws:logs:{REGION}:{ACCOUNT_ID}:log-group:{group_name}:*"
    return arn, {"Arn": arn, "LogGroupName": group_name}


async def _delete_log_group(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import cloudwatch_logs
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    group_name = attrs.get("LogGroupName") or props.get("LogGroupName", logical_id)
    data = {"logGroupName": group_name}
    hdrs = {"x-amz-target": "Logs_20140328.DeleteLogGroup",
            "content-type": "application/x-amz-json-1.1"}
    await cloudwatch_logs.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


# -- SSM Parameter --

async def _provision_ssm_parameter(logical_id, props, stack_name, ctx):
    from ministack.services import ssm
    param_name = props.get("Name", f"/{stack_name}/{logical_id}")
    param_value = props.get("Value", "")
    param_type = props.get("Type", "String")
    data = {
        "Name": param_name,
        "Value": param_value,
        "Type": param_type,
        "Overwrite": True,
    }
    if "Description" in props:
        data["Description"] = props["Description"]
    if "AllowedPattern" in props:
        data["AllowedPattern"] = props["AllowedPattern"]
    hdrs = {"x-amz-target": "AmazonSSM.PutParameter",
            "content-type": "application/x-amz-json-1.1"}
    await ssm.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})
    arn = f"arn:aws:ssm:{REGION}:{ACCOUNT_ID}:parameter{param_name}"
    return arn, {"Type": param_type, "Value": param_value}


async def _delete_ssm_parameter(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import ssm
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    param_name = props.get("Name") or attrs.get("Name") or f"/{stack_name}/{logical_id}"
    data = {"Name": param_name}
    hdrs = {"x-amz-target": "AmazonSSM.DeleteParameter",
            "content-type": "application/x-amz-json-1.1"}
    await ssm.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


# -- Secrets Manager Secret --

async def _provision_secret(logical_id, props, stack_name, ctx):
    from ministack.services import secretsmanager
    secret_name = props.get("Name", f"{stack_name}/{logical_id}")
    data = {"Name": secret_name}
    if "Description" in props:
        data["Description"] = props["Description"]
    if "SecretString" in props:
        data["SecretString"] = props["SecretString"]
    elif "GenerateSecretString" in props:
        import string as _string
        import secrets as _secrets
        length = props["GenerateSecretString"].get("PasswordLength", 32)
        charset = _string.ascii_letters + _string.digits + "!@#$%^&*()"
        data["SecretString"] = "".join(_secrets.choice(charset) for _ in range(int(length)))
    else:
        data["SecretString"] = new_uuid()
    if "Tags" in props and isinstance(props["Tags"], list):
        data["Tags"] = props["Tags"]
    hdrs = {"x-amz-target": "secretsmanager.CreateSecret",
            "content-type": "application/x-amz-json-1.1"}
    status, _, resp_body = await secretsmanager.handle_request("POST", "/", hdrs,
                                                               json.dumps(data).encode(), {})
    arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:secret:{secret_name}-{new_uuid()[:6]}"
    if status < 300:
        try:
            resp = json.loads(resp_body)
            arn = resp.get("ARN", arn)
        except Exception:
            pass
    return arn, {"SecretName": secret_name}


async def _delete_secret(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import secretsmanager
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    secret_name = attrs.get("SecretName") or props.get("Name", logical_id)
    data = {"SecretId": secret_name, "ForceDeleteWithoutRecovery": True}
    hdrs = {"x-amz-target": "secretsmanager.DeleteSecret",
            "content-type": "application/x-amz-json-1.1"}
    await secretsmanager.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


# -- EventBridge Rule --

async def _provision_events_rule(logical_id, props, stack_name, ctx):
    from ministack.services import eventbridge
    rule_name = props.get("Name", f"{stack_name}-{logical_id}")
    data = {"Name": rule_name}
    if "ScheduleExpression" in props:
        data["ScheduleExpression"] = props["ScheduleExpression"]
    if "EventPattern" in props:
        ep = props["EventPattern"]
        data["EventPattern"] = json.dumps(ep) if isinstance(ep, dict) else ep
    if "State" in props:
        data["State"] = props["State"]
    else:
        data["State"] = "ENABLED"
    if "Description" in props:
        data["Description"] = props["Description"]
    if "EventBusName" in props:
        data["EventBusName"] = props["EventBusName"]
    hdrs = {"x-amz-target": "AWSEvents.PutRule",
            "content-type": "application/x-amz-json-1.1"}
    status, _, resp_body = await eventbridge.handle_request("POST", "/", hdrs,
                                                            json.dumps(data).encode(), {})
    bus = props.get("EventBusName", "default")
    arn = f"arn:aws:events:{REGION}:{ACCOUNT_ID}:rule/{bus}/{rule_name}"
    if status < 300:
        try:
            resp = json.loads(resp_body)
            arn = resp.get("RuleArn", arn)
        except Exception:
            pass
    return arn, {"Arn": arn, "RuleName": rule_name}


async def _delete_events_rule(logical_id, physical_id, props, stack_name, ctx):
    from ministack.services import eventbridge
    resources = ctx.get("resources", {})
    res = resources.get(logical_id, {})
    attrs = res.get("Attributes", {})
    rule_name = attrs.get("RuleName") or props.get("Name", logical_id)
    data = {"Name": rule_name}
    if "EventBusName" in props:
        data["EventBusName"] = props["EventBusName"]
    hdrs = {"x-amz-target": "AWSEvents.DeleteRule",
            "content-type": "application/x-amz-json-1.1"}
    await eventbridge.handle_request("POST", "/", hdrs, json.dumps(data).encode(), {})


_RESOURCE_HANDLERS = {
    "AWS::S3::Bucket": _provision_s3_bucket,
    "AWS::SQS::Queue": _provision_sqs_queue,
    "AWS::SNS::Topic": _provision_sns_topic,
    "AWS::DynamoDB::Table": _provision_dynamodb_table,
    "AWS::Logs::LogGroup": _provision_log_group,
    "AWS::SSM::Parameter": _provision_ssm_parameter,
    "AWS::SecretsManager::Secret": _provision_secret,
    "AWS::Events::Rule": _provision_events_rule,
}

_RESOURCE_DELETE_HANDLERS = {
    "AWS::S3::Bucket": _delete_s3_bucket,
    "AWS::SQS::Queue": _delete_sqs_queue,
    "AWS::SNS::Topic": _delete_sns_topic,
    "AWS::DynamoDB::Table": _delete_dynamodb_table,
    "AWS::Logs::LogGroup": _delete_log_group,
    "AWS::SSM::Parameter": _delete_ssm_parameter,
    "AWS::SecretsManager::Secret": _delete_secret,
    "AWS::Events::Rule": _delete_events_rule,
}


# ---------------------------------------------------------------------------
# Stack resource provisioning orchestration
# ---------------------------------------------------------------------------

async def _provision_all_resources(stack_name, template, stack_rec):
    """Provision all resources defined in the template."""
    resources_section = template.get("Resources", {})
    if not resources_section:
        return

    ctx = _build_resolve_ctx(stack_rec)
    provisioned = {}

    # Simple topological ordering is not attempted; provision in template order
    for logical_id, res_def in resources_section.items():
        if not isinstance(res_def, dict):
            continue

        # Check Condition
        condition = res_def.get("Condition")
        if condition and not ctx.get("conditions", {}).get(condition, True):
            continue

        resource_type = res_def.get("Type", "")
        properties = res_def.get("Properties", {})

        stack_id = stack_rec["StackId"]
        _add_event(stack_name, stack_id, resource_type, logical_id, "",
                   "CREATE_IN_PROGRESS", "Resource creation initiated")

        physical_id, attributes = await _provision_resource(
            resource_type, logical_id, properties, stack_name, ctx
        )

        resource_record = {
            "LogicalResourceId": logical_id,
            "PhysicalResourceId": physical_id,
            "ResourceType": resource_type,
            "ResourceStatus": "CREATE_COMPLETE",
            "ResourceStatusReason": "",
            "Timestamp": now_iso(),
            "Description": res_def.get("Description", ""),
            "Attributes": attributes,
            "Properties": properties,
        }
        provisioned[logical_id] = resource_record

        # Update context so later Ref/GetAtt can see this resource
        ctx["resources"][logical_id] = resource_record

        _add_event(stack_name, stack_id, resource_type, logical_id, physical_id,
                   "CREATE_COMPLETE", "")

    stack_rec["Resources"] = provisioned

    # Resolve outputs now that all resources are provisioned
    _resolve_outputs(template, stack_rec, ctx)


async def _delete_all_resources(stack_name, stack_rec):
    """Delete all resources in reverse order."""
    resources = stack_rec.get("Resources", {})
    if not resources:
        return

    ctx = _build_resolve_ctx(stack_rec)
    template = {}
    try:
        template = _parse_template(stack_rec.get("TemplateBody", "{}"))
    except Exception:
        pass

    resource_items = list(resources.items())
    resource_items.reverse()

    for logical_id, res_rec in resource_items:
        resource_type = res_rec.get("ResourceType", "")
        physical_id = res_rec.get("PhysicalResourceId", "")
        properties = res_rec.get("Properties", {})

        _add_event(stack_name, stack_rec["StackId"], resource_type, logical_id,
                   physical_id, "DELETE_IN_PROGRESS", "Resource deletion initiated")

        await _delete_resource(resource_type, logical_id, physical_id,
                               properties, stack_name, ctx)

        _add_event(stack_name, stack_rec["StackId"], resource_type, logical_id,
                   physical_id, "DELETE_COMPLETE", "")

    # Remove exports associated with this stack
    to_remove = [k for k, v in _exports.items()
                 if v.get("ExportingStackId") == stack_rec.get("StackId")]
    for k in to_remove:
        del _exports[k]


def _resolve_outputs(template, stack_rec, ctx):
    """Resolve the Outputs section and store on the stack record."""
    outputs_section = template.get("Outputs", {})
    resolved_outputs = []
    for out_key, out_def in outputs_section.items():
        if not isinstance(out_def, dict):
            continue
        condition = out_def.get("Condition")
        if condition and not ctx.get("conditions", {}).get(condition, True):
            continue
        value = _resolve_value(out_def.get("Value", ""), ctx)
        out_rec = {
            "OutputKey": out_key,
            "OutputValue": str(value) if value is not None else "",
        }
        if "Description" in out_def:
            out_rec["Description"] = out_def["Description"]
        export_def = out_def.get("Export")
        if export_def and isinstance(export_def, dict):
            export_name = str(_resolve_value(export_def.get("Name", ""), ctx))
            if export_name:
                out_rec["ExportName"] = export_name
                _exports[export_name] = {
                    "Value": out_rec["OutputValue"],
                    "ExportingStackId": stack_rec.get("StackId", ""),
                    "ExportingStackName": stack_rec.get("StackName", ""),
                }
        resolved_outputs.append(out_rec)
    stack_rec["Outputs"] = resolved_outputs


# ---------------------------------------------------------------------------
# XML serialization helpers for responses
# ---------------------------------------------------------------------------

def _xml_stack_member(rec):
    """Serialize a stack record as a <member> XML element."""
    parts = [
        f"<StackId>{_esc(rec.get('StackId', ''))}</StackId>",
        f"<StackName>{_esc(rec.get('StackName', ''))}</StackName>",
        f"<Description>{_esc(rec.get('Description', ''))}</Description>",
        f"<StackStatus>{_esc(rec.get('StackStatus', ''))}</StackStatus>",
        f"<StackStatusReason>{_esc(rec.get('StackStatusReason', ''))}</StackStatusReason>",
        f"<CreationTime>{_esc(rec.get('CreationTime', ''))}</CreationTime>",
    ]
    if rec.get("LastUpdatedTime"):
        parts.append(f"<LastUpdatedTime>{_esc(rec['LastUpdatedTime'])}</LastUpdatedTime>")
    if rec.get("DeletionTime"):
        parts.append(f"<DeletionTime>{_esc(rec['DeletionTime'])}</DeletionTime>")
    if rec.get("RoleARN"):
        parts.append(f"<RoleARN>{_esc(rec['RoleARN'])}</RoleARN>")

    # Parameters
    params = rec.get("Parameters", [])
    if params:
        members = "".join(
            f"<member><ParameterKey>{_esc(p['ParameterKey'])}</ParameterKey>"
            f"<ParameterValue>{_esc(p['ParameterValue'])}</ParameterValue></member>"
            for p in params
        )
        parts.append(f"<Parameters>{members}</Parameters>")
    else:
        parts.append("<Parameters/>")

    # Outputs
    outputs = rec.get("Outputs", [])
    if outputs:
        members = ""
        for o in outputs:
            m = (f"<member><OutputKey>{_esc(o['OutputKey'])}</OutputKey>"
                 f"<OutputValue>{_esc(o.get('OutputValue', ''))}</OutputValue>")
            if o.get("Description"):
                m += f"<Description>{_esc(o['Description'])}</Description>"
            if o.get("ExportName"):
                m += f"<ExportName>{_esc(o['ExportName'])}</ExportName>"
            m += "</member>"
            members += m
        parts.append(f"<Outputs>{members}</Outputs>")
    else:
        parts.append("<Outputs/>")

    # Tags
    tags = rec.get("Tags", [])
    if tags:
        members = "".join(
            f"<member><Key>{_esc(t['Key'])}</Key><Value>{_esc(t['Value'])}</Value></member>"
            for t in tags
        )
        parts.append(f"<Tags>{members}</Tags>")
    else:
        parts.append("<Tags/>")

    # Capabilities
    caps = rec.get("Capabilities", [])
    if caps:
        members = "".join(f"<member>{_esc(c)}</member>" for c in caps)
        parts.append(f"<Capabilities>{members}</Capabilities>")
    else:
        parts.append("<Capabilities/>")

    # NotificationARNs
    narns = rec.get("NotificationARNs", [])
    if narns:
        members = "".join(f"<member>{_esc(a)}</member>" for a in narns)
        parts.append(f"<NotificationARNs>{members}</NotificationARNs>")
    else:
        parts.append("<NotificationARNs/>")

    parts.append(
        f"<EnableTerminationProtection>"
        f"{_bool_str(rec.get('EnableTerminationProtection', False))}"
        f"</EnableTerminationProtection>"
    )
    parts.append(
        f"<DisableRollback>"
        f"{_bool_str(rec.get('DisableRollback', False))}"
        f"</DisableRollback>"
    )

    return f"<member>{''.join(parts)}</member>"


def _xml_stack_summary(rec):
    """Serialize a stack summary as a <member> for ListStacks."""
    parts = [
        f"<StackId>{_esc(rec.get('StackId', ''))}</StackId>",
        f"<StackName>{_esc(rec.get('StackName', ''))}</StackName>",
        f"<StackStatus>{_esc(rec.get('StackStatus', ''))}</StackStatus>",
        f"<CreationTime>{_esc(rec.get('CreationTime', ''))}</CreationTime>",
    ]
    if rec.get("StackStatusReason"):
        parts.append(f"<StackStatusReason>{_esc(rec.get('StackStatusReason', ''))}</StackStatusReason>")
    if rec.get("LastUpdatedTime"):
        parts.append(f"<LastUpdatedTime>{_esc(rec['LastUpdatedTime'])}</LastUpdatedTime>")
    if rec.get("DeletionTime"):
        parts.append(f"<DeletionTime>{_esc(rec['DeletionTime'])}</DeletionTime>")
    if rec.get("TemplateDescription"):
        parts.append(f"<TemplateDescription>{_esc(rec['TemplateDescription'])}</TemplateDescription>")
    return f"<member>{''.join(parts)}</member>"


def _xml_resource_summary(res):
    """Serialize a resource as a <member> for resource listings."""
    parts = [
        f"<LogicalResourceId>{_esc(res.get('LogicalResourceId', ''))}</LogicalResourceId>",
        f"<PhysicalResourceId>{_esc(res.get('PhysicalResourceId', ''))}</PhysicalResourceId>",
        f"<ResourceType>{_esc(res.get('ResourceType', ''))}</ResourceType>",
        f"<ResourceStatus>{_esc(res.get('ResourceStatus', ''))}</ResourceStatus>",
        f"<ResourceStatusReason>{_esc(res.get('ResourceStatusReason', ''))}</ResourceStatusReason>",
        f"<LastUpdatedTimestamp>{_esc(res.get('Timestamp', ''))}</LastUpdatedTimestamp>",
    ]
    if res.get("Description"):
        parts.append(f"<Description>{_esc(res['Description'])}</Description>")
    return f"<member>{''.join(parts)}</member>"


def _xml_resource_detail(res, stack_name, stack_id):
    """Serialize a full resource detail."""
    parts = [
        f"<StackId>{_esc(stack_id)}</StackId>",
        f"<StackName>{_esc(stack_name)}</StackName>",
        f"<LogicalResourceId>{_esc(res.get('LogicalResourceId', ''))}</LogicalResourceId>",
        f"<PhysicalResourceId>{_esc(res.get('PhysicalResourceId', ''))}</PhysicalResourceId>",
        f"<ResourceType>{_esc(res.get('ResourceType', ''))}</ResourceType>",
        f"<ResourceStatus>{_esc(res.get('ResourceStatus', ''))}</ResourceStatus>",
        f"<ResourceStatusReason>{_esc(res.get('ResourceStatusReason', ''))}</ResourceStatusReason>",
        f"<Timestamp>{_esc(res.get('Timestamp', ''))}</Timestamp>",
    ]
    if res.get("Description"):
        parts.append(f"<Description>{_esc(res['Description'])}</Description>")
    return "".join(parts)


def _xml_event_member(evt):
    """Serialize a stack event as a <member>."""
    parts = [
        f"<EventId>{_esc(evt.get('EventId', ''))}</EventId>",
        f"<StackId>{_esc(evt.get('StackId', ''))}</StackId>",
        f"<StackName>{_esc(evt.get('StackName', ''))}</StackName>",
        f"<LogicalResourceId>{_esc(evt.get('LogicalResourceId', ''))}</LogicalResourceId>",
        f"<PhysicalResourceId>{_esc(evt.get('PhysicalResourceId', ''))}</PhysicalResourceId>",
        f"<ResourceType>{_esc(evt.get('ResourceType', ''))}</ResourceType>",
        f"<ResourceStatus>{_esc(evt.get('ResourceStatus', ''))}</ResourceStatus>",
        f"<ResourceStatusReason>{_esc(evt.get('ResourceStatusReason', ''))}</ResourceStatusReason>",
        f"<Timestamp>{_esc(evt.get('Timestamp', ''))}</Timestamp>",
    ]
    return f"<member>{''.join(parts)}</member>"


def _xml_change_set_summary(cs):
    """Serialize a change set summary as a <member>."""
    parts = [
        f"<ChangeSetId>{_esc(cs.get('ChangeSetId', ''))}</ChangeSetId>",
        f"<ChangeSetName>{_esc(cs.get('ChangeSetName', ''))}</ChangeSetName>",
        f"<StackId>{_esc(cs.get('StackId', ''))}</StackId>",
        f"<StackName>{_esc(cs.get('StackName', ''))}</StackName>",
        f"<Status>{_esc(cs.get('Status', ''))}</Status>",
        f"<StatusReason>{_esc(cs.get('StatusReason', ''))}</StatusReason>",
        f"<ExecutionStatus>{_esc(cs.get('ExecutionStatus', ''))}</ExecutionStatus>",
        f"<CreationTime>{_esc(cs.get('CreationTime', ''))}</CreationTime>",
    ]
    if cs.get("Description"):
        parts.append(f"<Description>{_esc(cs['Description'])}</Description>")
    return f"<member>{''.join(parts)}</member>"


# ---------------------------------------------------------------------------
# Action Handlers — Stack Operations
# ---------------------------------------------------------------------------

async def _create_stack(params):
    """CreateStack action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    if len(stack_name) > _MAX_STACK_NAME_LEN:
        return _error("ValidationError",
                       f"Stack name must be 1-{_MAX_STACK_NAME_LEN} characters")

    if not _STACK_NAME_RE.match(stack_name):
        return _error("ValidationError",
                       "Stack name must match [a-zA-Z][-a-zA-Z0-9]*")

    # Check for existing non-deleted stack
    existing_name, existing_rec = _find_active_stack(stack_name)
    if existing_rec:
        return _error("AlreadyExistsException",
                       f"Stack [{stack_name}] already exists")

    template_body = _p(params, "TemplateBody")
    template_url = _p(params, "TemplateURL")
    if not template_body and not template_url:
        return _error("ValidationError",
                       "Either TemplateBody or TemplateURL must be specified")

    if not template_body and template_url:
        template_body = "{}"

    try:
        template = _parse_template(template_body)
    except ValueError as exc:
        return _error("ValidationError", str(exc))

    errors = _validate_template_structure(template)
    if errors:
        return _error("ValidationError", "; ".join(errors))

    stack_id = _make_stack_arn(stack_name)
    now = now_iso()

    stack_parameters = _collect_parameters(params)
    tags = _collect_indexed(params, "Tags")
    capabilities = _collect_list(params, "Capabilities")
    notification_arns = _collect_list(params, "NotificationARNs")
    role_arn = _p(params, "RoleARN")
    disable_rollback = _parse_bool(_p(params, "DisableRollback"))
    enable_termination = _parse_bool(_p(params, "EnableTerminationProtection"))

    # Apply template default parameter values
    template_params = template.get("Parameters", {})
    param_map = {p["ParameterKey"]: p["ParameterValue"] for p in stack_parameters}
    for pk, pdef in template_params.items():
        if pk not in param_map and "Default" in pdef:
            stack_parameters.append({
                "ParameterKey": pk,
                "ParameterValue": str(pdef["Default"]),
            })

    description = template.get("Description", "")

    stack_rec = {
        "StackId": stack_id,
        "StackName": stack_name,
        "Description": description,
        "StackStatus": "CREATE_IN_PROGRESS",
        "StackStatusReason": "User initiated",
        "CreationTime": now,
        "LastUpdatedTime": "",
        "DeletionTime": "",
        "Parameters": stack_parameters,
        "Outputs": [],
        "Tags": tags,
        "TemplateBody": template_body,
        "Resources": {},
        "EnableTerminationProtection": enable_termination,
        "RoleARN": role_arn,
        "NotificationARNs": notification_arns,
        "Capabilities": capabilities,
        "DisableRollback": disable_rollback,
    }

    _stacks[stack_name] = stack_rec
    _events[stack_name] = []

    _add_event(stack_name, stack_id, "AWS::CloudFormation::Stack",
               stack_name, stack_id, "CREATE_IN_PROGRESS", "User initiated")

    # Provision resources
    try:
        await _provision_all_resources(stack_name, template, stack_rec)
        stack_rec["StackStatus"] = "CREATE_COMPLETE"
        stack_rec["StackStatusReason"] = ""
        _add_event(stack_name, stack_id, "AWS::CloudFormation::Stack",
                   stack_name, stack_id, "CREATE_COMPLETE", "")
    except Exception as exc:
        logger.error("CreateStack %s failed: %s", stack_name, exc)
        stack_rec["StackStatus"] = "CREATE_FAILED"
        stack_rec["StackStatusReason"] = str(exc)
        _add_event(stack_name, stack_id, "AWS::CloudFormation::Stack",
                   stack_name, stack_id, "CREATE_FAILED", str(exc))

    logger.info("CreateStack: %s -> %s", stack_name, stack_rec["StackStatus"])

    inner = f"<CreateStackResult><StackId>{_esc(stack_id)}</StackId></CreateStackResult>"
    return _xml(200, "CreateStackResponse", inner)


async def _update_stack(params):
    """UpdateStack action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, stack_rec = _find_active_stack(stack_name)
    if not stack_rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    template_body = _p(params, "TemplateBody")
    use_previous = _parse_bool(_p(params, "UsePreviousTemplate"))

    if not template_body and not use_previous:
        template_url = _p(params, "TemplateURL")
        if not template_url:
            return _error("ValidationError",
                           "Either TemplateBody, TemplateURL, or UsePreviousTemplate must be specified")
        template_body = stack_rec.get("TemplateBody", "{}")

    if use_previous and not template_body:
        template_body = stack_rec.get("TemplateBody", "{}")

    try:
        template = _parse_template(template_body)
    except ValueError as exc:
        return _error("ValidationError", str(exc))

    stack_id = stack_rec["StackId"]
    now = now_iso()

    new_parameters = _collect_parameters(params)
    if new_parameters:
        stack_rec["Parameters"] = new_parameters
    else:
        # Apply defaults for new parameters in updated template
        template_params = template.get("Parameters", {})
        existing_map = {p["ParameterKey"]: p["ParameterValue"]
                        for p in stack_rec.get("Parameters", [])}
        for pk, pdef in template_params.items():
            if pk not in existing_map and "Default" in pdef:
                stack_rec["Parameters"].append({
                    "ParameterKey": pk,
                    "ParameterValue": str(pdef["Default"]),
                })

    new_tags = _collect_indexed(params, "Tags")
    if new_tags:
        stack_rec["Tags"] = new_tags

    new_caps = _collect_list(params, "Capabilities")
    if new_caps:
        stack_rec["Capabilities"] = new_caps

    new_narns = _collect_list(params, "NotificationARNs")
    if new_narns:
        stack_rec["NotificationARNs"] = new_narns

    role_arn = _p(params, "RoleARN")
    if role_arn:
        stack_rec["RoleARN"] = role_arn

    stack_rec["StackStatus"] = "UPDATE_IN_PROGRESS"
    stack_rec["StackStatusReason"] = "User initiated"
    stack_rec["LastUpdatedTime"] = now
    stack_rec["TemplateBody"] = template_body
    stack_rec["Description"] = template.get("Description", stack_rec.get("Description", ""))

    _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
               sname, stack_id, "UPDATE_IN_PROGRESS", "User initiated")

    # Delete old resources and re-provision
    try:
        await _delete_all_resources(sname, stack_rec)
        stack_rec["Resources"] = {}
        await _provision_all_resources(sname, template, stack_rec)
        stack_rec["StackStatus"] = "UPDATE_COMPLETE"
        stack_rec["StackStatusReason"] = ""
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, "UPDATE_COMPLETE", "")
    except Exception as exc:
        logger.error("UpdateStack %s failed: %s", sname, exc)
        stack_rec["StackStatus"] = "UPDATE_FAILED"
        stack_rec["StackStatusReason"] = str(exc)
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, "UPDATE_FAILED", str(exc))

    logger.info("UpdateStack: %s -> %s", sname, stack_rec["StackStatus"])

    inner = f"<UpdateStackResult><StackId>{_esc(stack_id)}</StackId></UpdateStackResult>"
    return _xml(200, "UpdateStackResponse", inner)


async def _delete_stack(params):
    """DeleteStack action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, stack_rec = _find_active_stack(stack_name)
    if not stack_rec:
        # Deleting a non-existent stack is idempotent in AWS
        return _xml(200, "DeleteStackResponse", "<DeleteStackResult/>")

    if stack_rec.get("EnableTerminationProtection"):
        return _error("ValidationError",
                       f"Stack [{sname}] cannot be deleted while TerminationProtection is enabled")

    stack_id = stack_rec["StackId"]
    stack_rec["StackStatus"] = "DELETE_IN_PROGRESS"
    stack_rec["StackStatusReason"] = "User initiated"

    _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
               sname, stack_id, "DELETE_IN_PROGRESS", "User initiated")

    try:
        await _delete_all_resources(sname, stack_rec)
        stack_rec["StackStatus"] = "DELETE_COMPLETE"
        stack_rec["StackStatusReason"] = ""
        stack_rec["DeletionTime"] = now_iso()
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, "DELETE_COMPLETE", "")
    except Exception as exc:
        logger.error("DeleteStack %s failed: %s", sname, exc)
        stack_rec["StackStatus"] = "DELETE_FAILED"
        stack_rec["StackStatusReason"] = str(exc)
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, "DELETE_FAILED", str(exc))

    logger.info("DeleteStack: %s -> %s", sname, stack_rec["StackStatus"])
    return _xml(200, "DeleteStackResponse", "<DeleteStackResult/>")


def _describe_stacks(params):
    """DescribeStacks action handler."""
    stack_name = _p(params, "StackName", None)

    if stack_name:
        sname, rec = _find_stack(stack_name)
        if not rec:
            return _error("ValidationError",
                           f"Stack with id {stack_name} does not exist")
        # If looked up by name and it's deleted, return error
        if rec.get("StackStatus") == "DELETE_COMPLETE" and stack_name == sname:
            return _error("ValidationError",
                           f"Stack with id {stack_name} does not exist")
        members = _xml_stack_member(rec)
    else:
        # Return all non-deleted stacks
        members = ""
        for sn, rec in _stacks.items():
            if rec.get("StackStatus") != "DELETE_COMPLETE":
                members += _xml_stack_member(rec)

    inner = f"<DescribeStacksResult><Stacks>{members}</Stacks></DescribeStacksResult>"
    return _xml(200, "DescribeStacksResponse", inner)


def _list_stacks(params):
    """ListStacks action handler."""
    # Collect status filters
    status_filters = _collect_list(params, "StackStatusFilter")
    if not status_filters:
        # Default: exclude DELETE_COMPLETE
        status_filters = None

    members = ""
    for sn, rec in _stacks.items():
        status = rec.get("StackStatus", "")
        if status_filters:
            if status not in status_filters:
                continue
        else:
            if status == "DELETE_COMPLETE":
                continue

        # Add TemplateDescription from template
        summary = dict(rec)
        try:
            tmpl = _parse_template(rec.get("TemplateBody", "{}"))
            summary["TemplateDescription"] = tmpl.get("Description", "")
        except Exception:
            summary["TemplateDescription"] = ""
        members += _xml_stack_summary(summary)

    inner = f"<ListStacksResult><StackSummaries>{members}</StackSummaries></ListStacksResult>"
    return _xml(200, "ListStacksResponse", inner)


def _get_template(params):
    """GetTemplate action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, rec = _find_stack(stack_name)
    if not rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    template_body = rec.get("TemplateBody", "")
    # Determine stage
    stage = _p(params, "TemplateStage", "Original")

    inner = (
        f"<GetTemplateResult>"
        f"<TemplateBody>{_esc(template_body)}</TemplateBody>"
        f"<StagesAvailable><member>Original</member></StagesAvailable>"
        f"</GetTemplateResult>"
    )
    return _xml(200, "GetTemplateResponse", inner)


def _validate_template(params):
    """ValidateTemplate action handler."""
    template_body = _p(params, "TemplateBody")
    template_url = _p(params, "TemplateURL")

    if not template_body and not template_url:
        return _error("ValidationError",
                       "Either TemplateBody or TemplateURL must be specified")

    if not template_body and template_url:
        template_body = "{}"

    try:
        template = _parse_template(template_body)
    except ValueError as exc:
        return _error("ValidationError", str(exc))

    errors = _validate_template_structure(template)
    if errors:
        return _error("ValidationError", "; ".join(errors))

    description = template.get("Description", "")

    # Parameters
    param_xml = ""
    template_params = template.get("Parameters", {})
    for pk, pdef in template_params.items():
        if not isinstance(pdef, dict):
            continue
        p_parts = [f"<ParameterKey>{_esc(pk)}</ParameterKey>"]
        if "Default" in pdef:
            p_parts.append(f"<DefaultValue>{_esc(str(pdef['Default']))}</DefaultValue>")
        p_parts.append(f"<NoEcho>{_bool_str(pdef.get('NoEcho', False))}</NoEcho>")
        if "Description" in pdef:
            p_parts.append(f"<Description>{_esc(pdef['Description'])}</Description>")
        if "Type" in pdef:
            p_parts.append(f"<ParameterType>{_esc(pdef['Type'])}</ParameterType>")
        param_xml += f"<member>{''.join(p_parts)}</member>"

    # Capabilities
    cap_xml = ""
    resources = template.get("Resources", {})
    needs_cap = False
    for rid, rdef in resources.items():
        if isinstance(rdef, dict):
            rtype = rdef.get("Type", "")
            if "AWS::IAM::" in rtype or "AWS::CloudFormation::Macro" in rtype:
                needs_cap = True
                break
    if needs_cap:
        cap_xml = "<member>CAPABILITY_IAM</member><member>CAPABILITY_NAMED_IAM</member>"

    inner = (
        f"<ValidateTemplateResult>"
        f"<Description>{_esc(description)}</Description>"
        f"<Parameters>{param_xml}</Parameters>"
        f"<Capabilities>{cap_xml}</Capabilities>"
        f"<CapabilitiesReason></CapabilitiesReason>"
        f"</ValidateTemplateResult>"
    )
    return _xml(200, "ValidateTemplateResponse", inner)


def _get_template_summary(params):
    """GetTemplateSummary action handler."""
    template_body = _p(params, "TemplateBody")
    stack_name = _p(params, "StackName")

    if not template_body and stack_name:
        sname, rec = _find_active_stack(stack_name)
        if not rec:
            return _error("ValidationError",
                           f"Stack [{stack_name}] does not exist")
        template_body = rec.get("TemplateBody", "{}")
    elif not template_body:
        return _error("ValidationError",
                       "Either TemplateBody or StackName must be specified")

    try:
        template = _parse_template(template_body)
    except ValueError as exc:
        return _error("ValidationError", str(exc))

    description = template.get("Description", "")
    version = template.get("AWSTemplateFormatVersion", "")

    # Parameters
    param_xml = ""
    template_params = template.get("Parameters", {})
    for pk, pdef in template_params.items():
        if not isinstance(pdef, dict):
            continue
        p_parts = [f"<ParameterKey>{_esc(pk)}</ParameterKey>"]
        if "Default" in pdef:
            p_parts.append(f"<DefaultValue>{_esc(str(pdef['Default']))}</DefaultValue>")
        p_parts.append(f"<NoEcho>{_bool_str(pdef.get('NoEcho', False))}</NoEcho>")
        if "Description" in pdef:
            p_parts.append(f"<Description>{_esc(pdef['Description'])}</Description>")
        if "Type" in pdef:
            p_parts.append(f"<ParameterType>{_esc(pdef['Type'])}</ParameterType>")
        param_xml += f"<member>{''.join(p_parts)}</member>"

    # Resource types
    resource_types_xml = ""
    resources = template.get("Resources", {})
    seen = set()
    for rid, rdef in resources.items():
        if isinstance(rdef, dict):
            rt = rdef.get("Type", "")
            if rt and rt not in seen:
                resource_types_xml += f"<member>{_esc(rt)}</member>"
                seen.add(rt)

    inner = (
        f"<GetTemplateSummaryResult>"
        f"<Description>{_esc(description)}</Description>"
        f"<Parameters>{param_xml}</Parameters>"
        f"<ResourceTypes>{resource_types_xml}</ResourceTypes>"
        f"<Version>{_esc(version)}</Version>"
        f"<Metadata></Metadata>"
        f"</GetTemplateSummaryResult>"
    )
    return _xml(200, "GetTemplateSummaryResponse", inner)


# ---------------------------------------------------------------------------
# Action Handlers — Resource Operations
# ---------------------------------------------------------------------------

def _list_stack_resources(params):
    """ListStackResources action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, rec = _find_stack(stack_name)
    if not rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    resources = rec.get("Resources", {})
    members = ""
    for lid, res in resources.items():
        members += _xml_resource_summary(res)

    inner = (
        f"<ListStackResourcesResult>"
        f"<StackResourceSummaries>{members}</StackResourceSummaries>"
        f"</ListStackResourcesResult>"
    )
    return _xml(200, "ListStackResourcesResponse", inner)


def _describe_stack_resources(params):
    """DescribeStackResources action handler."""
    stack_name = _p(params, "StackName")
    physical_resource_id = _p(params, "PhysicalResourceId")
    logical_resource_id = _p(params, "LogicalResourceId")

    if not stack_name and not physical_resource_id:
        return _error("ValidationError",
                       "Either StackName or PhysicalResourceId must be specified")

    results = []

    if stack_name:
        sname, rec = _find_stack(stack_name)
        if not rec:
            return _error("ValidationError",
                           f"Stack [{stack_name}] does not exist")
        resources = rec.get("Resources", {})
        for lid, res in resources.items():
            if logical_resource_id and lid != logical_resource_id:
                continue
            detail = dict(res)
            detail["StackId"] = rec["StackId"]
            detail["StackName"] = rec["StackName"]
            results.append(detail)
    else:
        # Search all stacks for the physical resource ID
        for sn, rec in _stacks.items():
            if rec.get("StackStatus") == "DELETE_COMPLETE":
                continue
            resources = rec.get("Resources", {})
            for lid, res in resources.items():
                if res.get("PhysicalResourceId") == physical_resource_id:
                    detail = dict(res)
                    detail["StackId"] = rec["StackId"]
                    detail["StackName"] = rec["StackName"]
                    results.append(detail)

    members = ""
    for res in results:
        parts = [
            f"<member>",
            f"<StackId>{_esc(res.get('StackId', ''))}</StackId>",
            f"<StackName>{_esc(res.get('StackName', ''))}</StackName>",
            f"<LogicalResourceId>{_esc(res.get('LogicalResourceId', ''))}</LogicalResourceId>",
            f"<PhysicalResourceId>{_esc(res.get('PhysicalResourceId', ''))}</PhysicalResourceId>",
            f"<ResourceType>{_esc(res.get('ResourceType', ''))}</ResourceType>",
            f"<ResourceStatus>{_esc(res.get('ResourceStatus', ''))}</ResourceStatus>",
            f"<ResourceStatusReason>{_esc(res.get('ResourceStatusReason', ''))}</ResourceStatusReason>",
            f"<Timestamp>{_esc(res.get('Timestamp', ''))}</Timestamp>",
            f"</member>",
        ]
        members += "".join(parts)

    inner = (
        f"<DescribeStackResourcesResult>"
        f"<StackResources>{members}</StackResources>"
        f"</DescribeStackResourcesResult>"
    )
    return _xml(200, "DescribeStackResourcesResponse", inner)


def _describe_stack_resource(params):
    """DescribeStackResource action handler."""
    stack_name = _p(params, "StackName")
    logical_resource_id = _p(params, "LogicalResourceId")

    if not stack_name:
        return _error("ValidationError", "StackName is required")
    if not logical_resource_id:
        return _error("ValidationError", "LogicalResourceId is required")

    sname, rec = _find_stack(stack_name)
    if not rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    resources = rec.get("Resources", {})
    res = resources.get(logical_resource_id)
    if not res:
        return _error("ValidationError",
                       f"Resource [{logical_resource_id}] does not exist in stack [{stack_name}]")

    detail = _xml_resource_detail(res, rec["StackName"], rec["StackId"])
    inner = (
        f"<DescribeStackResourceResult>"
        f"<StackResourceDetail>{detail}</StackResourceDetail>"
        f"</DescribeStackResourceResult>"
    )
    return _xml(200, "DescribeStackResourceResponse", inner)


# ---------------------------------------------------------------------------
# Action Handlers — Event Operations
# ---------------------------------------------------------------------------

def _describe_stack_events(params):
    """DescribeStackEvents action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, rec = _find_stack(stack_name)
    if not rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    events = _events.get(sname, [])
    members = "".join(_xml_event_member(evt) for evt in events)

    inner = (
        f"<DescribeStackEventsResult>"
        f"<StackEvents>{members}</StackEvents>"
        f"</DescribeStackEventsResult>"
    )
    return _xml(200, "DescribeStackEventsResponse", inner)


# ---------------------------------------------------------------------------
# Action Handlers — Change Set Operations
# ---------------------------------------------------------------------------

async def _create_change_set(params):
    """CreateChangeSet action handler."""
    stack_name = _p(params, "StackName")
    change_set_name = _p(params, "ChangeSetName")
    change_set_type = _p(params, "ChangeSetType", "UPDATE")

    if not stack_name:
        return _error("ValidationError", "StackName is required")
    if not change_set_name:
        return _error("ValidationError", "ChangeSetName is required")

    template_body = _p(params, "TemplateBody")
    use_previous = _parse_bool(_p(params, "UsePreviousTemplate"))

    sname, stack_rec = _find_active_stack(stack_name)

    if change_set_type == "CREATE":
        # Stack should not exist
        if stack_rec:
            return _error("ValidationError",
                           f"Stack [{stack_name}] already exists")
        if not template_body:
            template_url = _p(params, "TemplateURL")
            if not template_url:
                return _error("ValidationError",
                               "TemplateBody or TemplateURL must be specified for CREATE type change set")
            template_body = "{}"

        try:
            template = _parse_template(template_body)
        except ValueError as exc:
            return _error("ValidationError", str(exc))

        stack_id = _make_stack_arn(stack_name)
        now = now_iso()
        stack_parameters = _collect_parameters(params)
        tags = _collect_indexed(params, "Tags")
        capabilities = _collect_list(params, "Capabilities")
        notification_arns = _collect_list(params, "NotificationARNs")

        # Apply template defaults
        template_params = template.get("Parameters", {})
        param_map = {p["ParameterKey"]: p["ParameterValue"] for p in stack_parameters}
        for pk, pdef in template_params.items():
            if pk not in param_map and "Default" in pdef:
                stack_parameters.append({
                    "ParameterKey": pk,
                    "ParameterValue": str(pdef["Default"]),
                })

        stack_rec = {
            "StackId": stack_id,
            "StackName": stack_name,
            "Description": template.get("Description", ""),
            "StackStatus": "REVIEW_IN_PROGRESS",
            "StackStatusReason": "",
            "CreationTime": now,
            "LastUpdatedTime": "",
            "DeletionTime": "",
            "Parameters": stack_parameters,
            "Outputs": [],
            "Tags": tags,
            "TemplateBody": template_body,
            "Resources": {},
            "EnableTerminationProtection": False,
            "RoleARN": _p(params, "RoleARN"),
            "NotificationARNs": notification_arns,
            "Capabilities": capabilities,
            "DisableRollback": False,
        }
        _stacks[stack_name] = stack_rec
        _events[stack_name] = []
        sname = stack_name
    else:
        # UPDATE type — stack must exist
        if not stack_rec:
            return _error("ValidationError",
                           f"Stack [{stack_name}] does not exist")

        if not template_body and use_previous:
            template_body = stack_rec.get("TemplateBody", "{}")
        elif not template_body:
            template_url = _p(params, "TemplateURL")
            if not template_url:
                return _error("ValidationError",
                               "TemplateBody, TemplateURL, or UsePreviousTemplate must be specified")
            template_body = stack_rec.get("TemplateBody", "{}")

        try:
            template = _parse_template(template_body)
        except ValueError as exc:
            return _error("ValidationError", str(exc))

        stack_id = stack_rec["StackId"]
        stack_parameters = _collect_parameters(params)
        if not stack_parameters:
            stack_parameters = stack_rec.get("Parameters", [])

    # Compute changes
    changes = _compute_changes(template, stack_rec)

    change_set_id = (
        f"arn:aws:cloudformation:{REGION}:{ACCOUNT_ID}:"
        f"changeSet/{change_set_name}/{new_uuid()}"
    )
    now = now_iso()
    description = _p(params, "Description")

    cs_rec = {
        "ChangeSetId": change_set_id,
        "ChangeSetName": change_set_name,
        "StackId": stack_rec["StackId"],
        "StackName": sname,
        "Status": "CREATE_COMPLETE",
        "StatusReason": "Change set created",
        "ExecutionStatus": "AVAILABLE",
        "CreationTime": now,
        "Description": description,
        "ChangeSetType": change_set_type,
        "Changes": changes,
        "Parameters": stack_parameters,
        "Tags": _collect_indexed(params, "Tags") or stack_rec.get("Tags", []),
        "Capabilities": _collect_list(params, "Capabilities") or stack_rec.get("Capabilities", []),
        "TemplateBody": template_body,
        "NotificationARNs": (_collect_list(params, "NotificationARNs")
                              or stack_rec.get("NotificationARNs", [])),
        "RoleARN": _p(params, "RoleARN") or stack_rec.get("RoleARN", ""),
    }

    if not changes:
        cs_rec["Status"] = "FAILED"
        cs_rec["StatusReason"] = ("The submitted information didn't contain changes. "
                                  "Submit different information to create a change set.")
        cs_rec["ExecutionStatus"] = "UNAVAILABLE"

    _change_sets[change_set_id] = cs_rec

    inner = (
        f"<CreateChangeSetResult>"
        f"<Id>{_esc(change_set_id)}</Id>"
        f"<StackId>{_esc(stack_rec['StackId'])}</StackId>"
        f"</CreateChangeSetResult>"
    )
    return _xml(200, "CreateChangeSetResponse", inner)


def _compute_changes(template, stack_rec):
    """Compute a list of changes between the template and the current stack state."""
    changes = []
    new_resources = template.get("Resources", {})
    old_resources = stack_rec.get("Resources", {})

    for lid, rdef in new_resources.items():
        if not isinstance(rdef, dict):
            continue
        rtype = rdef.get("Type", "")
        if lid in old_resources:
            changes.append({
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Modify",
                    "LogicalResourceId": lid,
                    "PhysicalResourceId": old_resources[lid].get("PhysicalResourceId", ""),
                    "ResourceType": rtype,
                    "Replacement": "Conditional",
                },
            })
        else:
            changes.append({
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Add",
                    "LogicalResourceId": lid,
                    "ResourceType": rtype,
                },
            })

    for lid in old_resources:
        if lid not in new_resources:
            old_type = old_resources[lid].get("ResourceType", "")
            changes.append({
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Remove",
                    "LogicalResourceId": lid,
                    "PhysicalResourceId": old_resources[lid].get("PhysicalResourceId", ""),
                    "ResourceType": old_type,
                },
            })

    return changes


def _describe_change_set(params):
    """DescribeChangeSet action handler."""
    change_set_name = _p(params, "ChangeSetName")
    stack_name = _p(params, "StackName")

    if not change_set_name:
        return _error("ValidationError", "ChangeSetName is required")

    cs_rec = _find_change_set(change_set_name, stack_name)
    if not cs_rec:
        return _error("ChangeSetNotFound",
                       f"ChangeSet [{change_set_name}] does not exist")

    # Build changes XML
    changes_xml = ""
    for change in cs_rec.get("Changes", []):
        rc = change.get("ResourceChange", {})
        change_parts = [
            f"<member><Type>{_esc(change.get('Type', 'Resource'))}</Type>",
            f"<ResourceChange>",
            f"<Action>{_esc(rc.get('Action', ''))}</Action>",
            f"<LogicalResourceId>{_esc(rc.get('LogicalResourceId', ''))}</LogicalResourceId>",
        ]
        if rc.get("PhysicalResourceId"):
            change_parts.append(
                f"<PhysicalResourceId>{_esc(rc['PhysicalResourceId'])}</PhysicalResourceId>"
            )
        change_parts.append(f"<ResourceType>{_esc(rc.get('ResourceType', ''))}</ResourceType>")
        if rc.get("Replacement"):
            change_parts.append(f"<Replacement>{_esc(rc['Replacement'])}</Replacement>")
        change_parts.append("</ResourceChange></member>")
        changes_xml += "".join(change_parts)

    # Parameters XML
    params_xml = ""
    for p in cs_rec.get("Parameters", []):
        params_xml += (
            f"<member>"
            f"<ParameterKey>{_esc(p['ParameterKey'])}</ParameterKey>"
            f"<ParameterValue>{_esc(p['ParameterValue'])}</ParameterValue>"
            f"</member>"
        )

    # Tags XML
    tags_xml = ""
    for t in cs_rec.get("Tags", []):
        tags_xml += (
            f"<member><Key>{_esc(t['Key'])}</Key>"
            f"<Value>{_esc(t['Value'])}</Value></member>"
        )

    # Capabilities XML
    caps_xml = ""
    for c in cs_rec.get("Capabilities", []):
        caps_xml += f"<member>{_esc(c)}</member>"

    # NotificationARNs XML
    narns_xml = ""
    for a in cs_rec.get("NotificationARNs", []):
        narns_xml += f"<member>{_esc(a)}</member>"

    inner = (
        f"<DescribeChangeSetResult>"
        f"<ChangeSetId>{_esc(cs_rec.get('ChangeSetId', ''))}</ChangeSetId>"
        f"<ChangeSetName>{_esc(cs_rec.get('ChangeSetName', ''))}</ChangeSetName>"
        f"<StackId>{_esc(cs_rec.get('StackId', ''))}</StackId>"
        f"<StackName>{_esc(cs_rec.get('StackName', ''))}</StackName>"
        f"<Description>{_esc(cs_rec.get('Description', ''))}</Description>"
        f"<Status>{_esc(cs_rec.get('Status', ''))}</Status>"
        f"<StatusReason>{_esc(cs_rec.get('StatusReason', ''))}</StatusReason>"
        f"<ExecutionStatus>{_esc(cs_rec.get('ExecutionStatus', ''))}</ExecutionStatus>"
        f"<CreationTime>{_esc(cs_rec.get('CreationTime', ''))}</CreationTime>"
        f"<ChangeSetType>{_esc(cs_rec.get('ChangeSetType', ''))}</ChangeSetType>"
        f"<Changes>{changes_xml}</Changes>"
        f"<Parameters>{params_xml}</Parameters>"
        f"<Tags>{tags_xml}</Tags>"
        f"<Capabilities>{caps_xml}</Capabilities>"
        f"<NotificationARNs>{narns_xml}</NotificationARNs>"
        f"<RoleARN>{_esc(cs_rec.get('RoleARN', ''))}</RoleARN>"
        f"</DescribeChangeSetResult>"
    )
    return _xml(200, "DescribeChangeSetResponse", inner)


async def _execute_change_set(params):
    """ExecuteChangeSet action handler."""
    change_set_name = _p(params, "ChangeSetName")
    stack_name = _p(params, "StackName")

    if not change_set_name:
        return _error("ValidationError", "ChangeSetName is required")

    cs_rec = _find_change_set(change_set_name, stack_name)
    if not cs_rec:
        return _error("ChangeSetNotFound",
                       f"ChangeSet [{change_set_name}] does not exist")

    if cs_rec.get("ExecutionStatus") != "AVAILABLE":
        return _error("InvalidChangeSetStatus",
                       f"ChangeSet [{change_set_name}] cannot be executed in its current status "
                       f"[{cs_rec.get('Status')}]")

    cs_rec["ExecutionStatus"] = "EXECUTE_IN_PROGRESS"

    sname = cs_rec["StackName"]
    stack_rec = _stacks.get(sname)
    if not stack_rec:
        return _error("ValidationError",
                       f"Stack [{sname}] does not exist")

    template_body = cs_rec.get("TemplateBody", stack_rec.get("TemplateBody", "{}"))

    try:
        template = _parse_template(template_body)
    except ValueError as exc:
        return _error("ValidationError", str(exc))

    change_set_type = cs_rec.get("ChangeSetType", "UPDATE")
    stack_id = stack_rec["StackId"]
    now = now_iso()

    # Update stack parameters from change set
    if cs_rec.get("Parameters"):
        stack_rec["Parameters"] = cs_rec["Parameters"]
    if cs_rec.get("Tags"):
        stack_rec["Tags"] = cs_rec["Tags"]
    if cs_rec.get("Capabilities"):
        stack_rec["Capabilities"] = cs_rec["Capabilities"]
    if cs_rec.get("NotificationARNs"):
        stack_rec["NotificationARNs"] = cs_rec["NotificationARNs"]
    if cs_rec.get("RoleARN"):
        stack_rec["RoleARN"] = cs_rec["RoleARN"]

    stack_rec["TemplateBody"] = template_body
    stack_rec["Description"] = template.get("Description", stack_rec.get("Description", ""))
    stack_rec["LastUpdatedTime"] = now

    if change_set_type == "CREATE":
        stack_rec["StackStatus"] = "CREATE_IN_PROGRESS"
        status_word = "CREATE"
    else:
        stack_rec["StackStatus"] = "UPDATE_IN_PROGRESS"
        status_word = "UPDATE"

    _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
               sname, stack_id, f"{status_word}_IN_PROGRESS",
               f"Change set {cs_rec['ChangeSetName']} execution initiated")

    try:
        if change_set_type == "UPDATE":
            await _delete_all_resources(sname, stack_rec)
            stack_rec["Resources"] = {}
        await _provision_all_resources(sname, template, stack_rec)
        stack_rec["StackStatus"] = f"{status_word}_COMPLETE"
        stack_rec["StackStatusReason"] = ""
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, f"{status_word}_COMPLETE", "")
    except Exception as exc:
        logger.error("ExecuteChangeSet %s failed: %s", sname, exc)
        stack_rec["StackStatus"] = f"{status_word}_FAILED"
        stack_rec["StackStatusReason"] = str(exc)
        _add_event(sname, stack_id, "AWS::CloudFormation::Stack",
                   sname, stack_id, f"{status_word}_FAILED", str(exc))

    cs_rec["ExecutionStatus"] = "EXECUTE_COMPLETE"

    return _xml(200, "ExecuteChangeSetResponse", "<ExecuteChangeSetResult/>")


def _delete_change_set(params):
    """DeleteChangeSet action handler."""
    change_set_name = _p(params, "ChangeSetName")
    stack_name = _p(params, "StackName")

    if not change_set_name:
        return _error("ValidationError", "ChangeSetName is required")

    cs_rec = _find_change_set(change_set_name, stack_name)
    if not cs_rec:
        return _error("ChangeSetNotFound",
                       f"ChangeSet [{change_set_name}] does not exist")

    if cs_rec.get("ExecutionStatus") == "EXECUTE_IN_PROGRESS":
        return _error("InvalidChangeSetStatus",
                       f"ChangeSet [{change_set_name}] cannot be deleted while in EXECUTE_IN_PROGRESS")

    _change_sets.pop(cs_rec["ChangeSetId"], None)
    return _xml(200, "DeleteChangeSetResponse", "<DeleteChangeSetResult/>")


def _list_change_sets(params):
    """ListChangeSets action handler."""
    stack_name = _p(params, "StackName")
    if not stack_name:
        return _error("ValidationError", "StackName is required")

    sname, rec = _find_stack(stack_name)
    if not rec:
        return _error("ValidationError",
                       f"Stack [{stack_name}] does not exist")

    stack_id = rec["StackId"]
    members = ""
    for cs_id, cs_rec in _change_sets.items():
        if cs_rec.get("StackId") == stack_id or cs_rec.get("StackName") == sname:
            members += _xml_change_set_summary(cs_rec)

    inner = (
        f"<ListChangeSetsResult>"
        f"<Summaries>{members}</Summaries>"
        f"</ListChangeSetsResult>"
    )
    return _xml(200, "ListChangeSetsResponse", inner)


def _find_change_set(name_or_id, stack_name=None):
    """Look up a change set by name/ARN, optionally scoped to a stack."""
    # Try direct ID match
    if name_or_id in _change_sets:
        return _change_sets[name_or_id]
    # Search by name
    for cs_id, cs_rec in _change_sets.items():
        if cs_rec.get("ChangeSetName") == name_or_id:
            if stack_name:
                cs_stack = cs_rec.get("StackName", "")
                cs_stack_id = cs_rec.get("StackId", "")
                if stack_name not in (cs_stack, cs_stack_id):
                    continue
            return cs_rec
        if cs_rec.get("ChangeSetId") == name_or_id:
            return cs_rec
    return None


# ---------------------------------------------------------------------------
# Action Handlers — Export Operations
# ---------------------------------------------------------------------------

def _list_exports(params):
    """ListExports action handler."""
    members = ""
    for export_name, export_rec in _exports.items():
        members += (
            f"<member>"
            f"<ExportingStackId>{_esc(export_rec.get('ExportingStackId', ''))}</ExportingStackId>"
            f"<Name>{_esc(export_name)}</Name>"
            f"<Value>{_esc(export_rec.get('Value', ''))}</Value>"
            f"</member>"
        )

    inner = (
        f"<ListExportsResult>"
        f"<Exports>{members}</Exports>"
        f"</ListExportsResult>"
    )
    return _xml(200, "ListExportsResponse", inner)


def _list_imports(params):
    """ListImports action handler."""
    export_name = _p(params, "ExportName")
    if not export_name:
        return _error("ValidationError", "ExportName is required")

    if export_name not in _exports:
        return _error("ValidationError",
                       f"Export [{export_name}] does not exist")

    export_rec = _exports[export_name]
    exporting_stack_id = export_rec.get("ExportingStackId", "")

    # Find all stacks that import this export by scanning templates
    importing_stacks = []
    for sname, rec in _stacks.items():
        if rec.get("StackStatus") == "DELETE_COMPLETE":
            continue
        if rec.get("StackId") == exporting_stack_id:
            continue
        template_body = rec.get("TemplateBody", "")
        if export_name in template_body:
            importing_stacks.append(sname)

    members = "".join(f"<member>{_esc(s)}</member>" for s in importing_stacks)

    inner = (
        f"<ListImportsResult>"
        f"<Imports>{members}</Imports>"
        f"</ListImportsResult>"
    )
    return _xml(200, "ListImportsResponse", inner)


# ---------------------------------------------------------------------------
# Action dispatch map
# ---------------------------------------------------------------------------

_ACTION_MAP = {
    # Stack operations
    "CreateStack": _create_stack,
    "UpdateStack": _update_stack,
    "DeleteStack": _delete_stack,
    "DescribeStacks": _describe_stacks,
    "ListStacks": _list_stacks,
    "GetTemplate": _get_template,
    "ValidateTemplate": _validate_template,
    "GetTemplateSummary": _get_template_summary,
    # Resource operations
    "ListStackResources": _list_stack_resources,
    "DescribeStackResources": _describe_stack_resources,
    "DescribeStackResource": _describe_stack_resource,
    # Event operations
    "DescribeStackEvents": _describe_stack_events,
    # Change set operations
    "CreateChangeSet": _create_change_set,
    "DescribeChangeSet": _describe_change_set,
    "ExecuteChangeSet": _execute_change_set,
    "DeleteChangeSet": _delete_change_set,
    "ListChangeSets": _list_change_sets,
    # Export operations
    "ListExports": _list_exports,
    "ListImports": _list_imports,
}

# Handlers that are coroutines (async)
_ASYNC_ACTIONS = {
    "CreateStack", "UpdateStack", "DeleteStack",
    "CreateChangeSet", "ExecuteChangeSet",
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def handle_request(method, path, headers, body, query_params):
    """Main entry point for CloudFormation requests."""
    params = dict(query_params)
    if method in ("POST", "PUT") and body:
        raw = body if isinstance(body, str) else body.decode("utf-8", errors="replace")
        for k, v in parse_qs(raw).items():
            params[k] = v

    action = _p(params, "Action")
    if not action:
        return _error("MissingAction", "Missing Action parameter", 400)

    handler = _ACTION_MAP.get(action)
    if not handler:
        return _error("InvalidAction", f"Unknown CloudFormation action: {action}", 400)

    if action in _ASYNC_ACTIONS:
        return await handler(params)
    return handler(params)
