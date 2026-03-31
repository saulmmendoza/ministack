"""
CodeBuild Service Emulator.
JSON-based API via X-Amz-Target (CodeBuild_20161006).

Supports: CreateProject, DeleteProject, BatchGetProjects, UpdateProject, ListProjects,
          StartBuild, StopBuild, BatchGetBuilds, ListBuilds, ListBuildsForProject,
          BatchDeleteBuilds,
          CreateWebhook, DeleteWebhook, UpdateWebhook,
          ListCuratedEnvironmentImages,
          TagResource, UntagResource, ListTagsForResource.

Builds run in background threads and transition:
  QUEUED -> IN_PROGRESS -> SUCCEEDED / FAILED / STOPPED.
"""

import json
import logging
import threading
import time

from ministack.core.responses import json_response, error_response_json, new_uuid, now_iso

logger = logging.getLogger("codebuild")

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"
BUILD_RUN_SECONDS = 1  # simulated build duration

_projects: dict = {}   # name -> project dict
_builds: dict = {}     # build_id -> build dict
_tags: dict = {}       # arn -> {key: value}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _project_arn(name: str) -> str:
    return f"arn:aws:codebuild:{REGION}:{ACCOUNT_ID}:project/{name}"


def _build_arn(build_id: str) -> str:
    return f"arn:aws:codebuild:{REGION}:{ACCOUNT_ID}:build/{build_id}"


def _sanitize_tags(raw) -> list:
    """Normalise tags: accept list of {key,value} dicts."""
    if not raw:
        return []
    out = []
    for t in raw:
        if isinstance(t, dict):
            out.append({"key": t.get("key", ""), "value": t.get("value", "")})
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def handle_request(method, path, headers, body, query_params):
    target = headers.get("x-amz-target", "")
    action = target.split(".")[-1] if "." in target else ""

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        return error_response_json("SerializationException", "Invalid JSON", 400)

    handlers = {
        "CreateProject": _create_project,
        "DeleteProject": _delete_project,
        "BatchGetProjects": _batch_get_projects,
        "UpdateProject": _update_project,
        "ListProjects": _list_projects,
        "StartBuild": _start_build,
        "StopBuild": _stop_build,
        "BatchGetBuilds": _batch_get_builds,
        "ListBuilds": _list_builds,
        "ListBuildsForProject": _list_builds_for_project,
        "BatchDeleteBuilds": _batch_delete_builds,
        "CreateWebhook": _create_webhook,
        "DeleteWebhook": _delete_webhook,
        "UpdateWebhook": _update_webhook,
        "ListCuratedEnvironmentImages": _list_curated_environment_images,
        "TagResource": _tag_resource,
        "UntagResource": _untag_resource,
        "ListTagsForResource": _list_tags_for_resource,
    }

    handler = handlers.get(action)
    if not handler:
        return error_response_json("InvalidAction", f"Unknown action: {action}", 400)
    return handler(data)


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------

def _create_project(data):
    name = data.get("name")
    if not name:
        return error_response_json("InvalidInputException", "name is required", 400)
    if name in _projects:
        return error_response_json("ResourceAlreadyExistsException",
                                   f"Project already exists: {name}", 400)

    tags = _sanitize_tags(data.get("tags", []))
    project = {
        "name": name,
        "arn": _project_arn(name),
        "description": data.get("description", ""),
        "source": data.get("source", {"type": "NO_SOURCE"}),
        "secondarySources": data.get("secondarySources", []),
        "artifacts": data.get("artifacts", {"type": "NO_ARTIFACTS"}),
        "secondaryArtifacts": data.get("secondaryArtifacts", []),
        "cache": data.get("cache", {"type": "NO_CACHE"}),
        "environment": data.get("environment", {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        }),
        "serviceRole": data.get("serviceRole", f"arn:aws:iam::{ACCOUNT_ID}:role/codebuild-role"),
        "timeoutInMinutes": data.get("timeoutInMinutes", 60),
        "queuedTimeoutInMinutes": data.get("queuedTimeoutInMinutes", 480),
        "encryptionKey": data.get("encryptionKey", f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:alias/aws/s3"),
        "tags": tags,
        "created": now_iso(),
        "lastModified": now_iso(),
        "webhook": None,
        "badge": {"badgeEnabled": False},
        "logsConfig": data.get("logsConfig", {}),
        "buildBatchConfig": data.get("buildBatchConfig", {}),
        "concurrentBuildLimit": data.get("concurrentBuildLimit", None),
    }
    _projects[name] = project
    arn = project["arn"]
    if tags:
        _tags[arn] = {t["key"]: t["value"] for t in tags}
    return json_response({"project": project})


def _delete_project(data):
    name = data.get("name")
    if not name:
        return error_response_json("InvalidInputException", "name is required", 400)
    project = _projects.pop(name, None)
    if project:
        _tags.pop(project["arn"], None)
    return json_response({})


def _batch_get_projects(data):
    names = data.get("names", [])
    found = []
    not_found = []
    for name in names:
        if name in _projects:
            found.append(_projects[name])
        else:
            not_found.append(name)
    return json_response({"projects": found, "projectsNotFound": not_found})


def _update_project(data):
    name = data.get("name")
    if not name:
        return error_response_json("InvalidInputException", "name is required", 400)
    if name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {name}", 400)
    project = _projects[name]
    for field in ("description", "source", "secondarySources", "artifacts",
                  "secondaryArtifacts", "cache", "environment", "serviceRole",
                  "timeoutInMinutes", "queuedTimeoutInMinutes", "encryptionKey",
                  "logsConfig", "buildBatchConfig", "concurrentBuildLimit"):
        if field in data:
            project[field] = data[field]
    if "tags" in data:
        project["tags"] = _sanitize_tags(data["tags"])
        _tags[project["arn"]] = {t["key"]: t["value"] for t in project["tags"]}
    project["lastModified"] = now_iso()
    return json_response({"project": project})


def _list_projects(data):
    sort_by = data.get("sortBy", "NAME")
    sort_order = data.get("sortOrder", "ASCENDING")
    names = sorted(_projects.keys(), reverse=(sort_order == "DESCENDING"))
    return json_response({"projects": names})


# ---------------------------------------------------------------------------
# Build operations
# ---------------------------------------------------------------------------

def _make_build(project_name, overrides: dict) -> dict:
    build_id = f"{project_name}:{new_uuid()}"
    project = _projects.get(project_name, {})
    build = {
        "id": build_id,
        "arn": _build_arn(build_id),
        "buildNumber": len([b for b in _builds.values() if b["projectName"] == project_name]) + 1,
        "startTime": now_iso(),
        "endTime": None,
        "currentPhase": "QUEUED",
        "buildStatus": "IN_PROGRESS",
        "sourceVersion": overrides.get("sourceVersion", project.get("source", {}).get("location", "")),
        "resolvedSourceVersion": None,
        "projectName": project_name,
        "phases": [],
        "source": overrides.get("sourceOverride", project.get("source", {})),
        "artifacts": overrides.get("artifactsOverride", project.get("artifacts", {})),
        "cache": project.get("cache", {}),
        "environment": overrides.get("environmentOverride", project.get("environment", {})),
        "serviceRole": project.get("serviceRole", ""),
        "logs": {"deepLink": "", "s3DeepLink": "", "cloudWatchLogs": {}, "s3Logs": {}},
        "timeoutInMinutes": overrides.get("timeoutInMinutesOverride", project.get("timeoutInMinutes", 60)),
        "queuedTimeoutInMinutes": project.get("queuedTimeoutInMinutes", 480),
        "buildComplete": False,
        "initiator": "test",
        "encryptionKey": project.get("encryptionKey", ""),
        "exportedEnvironmentVariables": [],
        "networkInterface": {},
        "secondaryArtifacts": [],
        "secondarySources": [],
        "secondarySourceVersions": [],
        "reportArns": [],
    }
    return build


def _run_build_async(build_id: str):
    """Simulate build execution in a background thread."""
    time.sleep(BUILD_RUN_SECONDS)
    build = _builds.get(build_id)
    if not build:
        return
    if build["buildStatus"] == "STOPPED":
        return
    build["buildStatus"] = "SUCCEEDED"
    build["currentPhase"] = "COMPLETED"
    build["buildComplete"] = True
    build["endTime"] = now_iso()
    build["resolvedSourceVersion"] = new_uuid()[:8]


def _start_build(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    build = _make_build(project_name, data)
    _builds[build["id"]] = build
    threading.Thread(target=_run_build_async, args=(build["id"],), daemon=True).start()
    return json_response({"build": build})


def _stop_build(data):
    build_id = data.get("id")
    if not build_id:
        return error_response_json("InvalidInputException", "id is required", 400)
    build = _builds.get(build_id)
    if not build:
        return error_response_json("ResourceNotFoundException",
                                   f"Build not found: {build_id}", 400)
    if not build["buildComplete"]:
        build["buildStatus"] = "STOPPED"
        build["buildComplete"] = True
        build["endTime"] = now_iso()
        build["currentPhase"] = "COMPLETED"
    return json_response({"build": build})


def _batch_get_builds(data):
    ids = data.get("ids", [])
    found = [_builds[bid] for bid in ids if bid in _builds]
    not_found = [bid for bid in ids if bid not in _builds]
    return json_response({"builds": found, "buildsNotFound": not_found})


def _list_builds(data):
    sort_order = data.get("sortOrder", "DESCENDING")
    ids = list(_builds.keys())
    if sort_order == "DESCENDING":
        ids = list(reversed(ids))
    return json_response({"ids": ids})


def _list_builds_for_project(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    sort_order = data.get("sortOrder", "DESCENDING")
    ids = [bid for bid, b in _builds.items() if b["projectName"] == project_name]
    if sort_order == "DESCENDING":
        ids = list(reversed(ids))
    return json_response({"ids": ids})


def _batch_delete_builds(data):
    ids = data.get("ids", [])
    deleted = []
    not_deleted = []
    for bid in ids:
        build = _builds.pop(bid, None)
        if build:
            deleted.append({"id": bid, "arn": _build_arn(bid)})
        else:
            not_deleted.append({"id": bid, "statusCode": "BUILD_NOT_FOUND",
                                 "message": f"Build not found: {bid}"})
    return json_response({"buildsDeleted": deleted, "buildsNotDeleted": not_deleted})


# ---------------------------------------------------------------------------
# Webhook operations
# ---------------------------------------------------------------------------

def _create_webhook(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    project = _projects[project_name]
    if project.get("webhook"):
        return error_response_json("InvalidInputException",
                                   "Webhook already exists for project", 400)
    webhook = {
        "url": f"https://codebuild.{REGION}.amazonaws.com/webhooks/{project_name}",
        "payloadUrl": f"https://codebuild.{REGION}.amazonaws.com/webhooks/{project_name}/payload",
        "secret": new_uuid(),
        "branchFilter": data.get("branchFilter", ""),
        "filterGroups": data.get("filterGroups", []),
        "buildType": data.get("buildType", "BUILD"),
        "lastModifiedSecret": now_iso(),
    }
    project["webhook"] = webhook
    return json_response({"webhook": webhook})


def _delete_webhook(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    _projects[project_name]["webhook"] = None
    return json_response({})


def _update_webhook(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    project = _projects[project_name]
    webhook = project.get("webhook")
    if not webhook:
        return error_response_json("ResourceNotFoundException",
                                   "No webhook found for project", 400)
    if "branchFilter" in data:
        webhook["branchFilter"] = data["branchFilter"]
    if "filterGroups" in data:
        webhook["filterGroups"] = data["filterGroups"]
    if "buildType" in data:
        webhook["buildType"] = data["buildType"]
    webhook["lastModifiedSecret"] = now_iso()
    return json_response({"webhook": webhook})


# ---------------------------------------------------------------------------
# Curated environment images
# ---------------------------------------------------------------------------

_CURATED_IMAGES = [
    {
        "platform": "AMAZON_LINUX_2",
        "languages": [
            {
                "language": "PYTHON",
                "images": [
                    {"name": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                     "description": "Amazon Linux 2 x86_64 standard image 5.0",
                     "versions": ["5.0"]},
                ],
            },
            {
                "language": "NODEJS",
                "images": [
                    {"name": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                     "description": "Amazon Linux 2 x86_64 standard image 5.0",
                     "versions": ["5.0"]},
                ],
            },
        ],
    },
    {
        "platform": "UBUNTU",
        "languages": [
            {
                "language": "PYTHON",
                "images": [
                    {"name": "aws/codebuild/standard:7.0",
                     "description": "Ubuntu standard image 7.0",
                     "versions": ["7.0"]},
                ],
            },
        ],
    },
]


def _list_curated_environment_images(_data):
    return json_response({"platforms": _CURATED_IMAGES})


# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------

def _tag_resource(data):
    arn = data.get("resourceArn")
    raw_tags = data.get("tags", [])
    if not arn:
        return error_response_json("InvalidInputException", "resourceArn is required", 400)
    existing = _tags.get(arn, {})
    for t in raw_tags:
        existing[t.get("key", "")] = t.get("value", "")
    _tags[arn] = existing
    return json_response({})


def _untag_resource(data):
    arn = data.get("resourceArn")
    tag_keys = data.get("tagKeys", [])
    if not arn:
        return error_response_json("InvalidInputException", "resourceArn is required", 400)
    existing = _tags.get(arn, {})
    for k in tag_keys:
        existing.pop(k, None)
    _tags[arn] = existing
    return json_response({})


def _list_tags_for_resource(data):
    arn = data.get("resourceArn")
    if not arn:
        return error_response_json("InvalidInputException", "resourceArn is required", 400)
    raw = _tags.get(arn, {})
    tags = [{"key": k, "value": v} for k, v in raw.items()]
    return json_response({"tags": tags})


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def reset():
    global _projects, _builds, _tags
    _projects.clear()
    _builds.clear()
    _tags.clear()
