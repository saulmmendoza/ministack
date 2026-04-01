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

Buildspec execution:
  - Parses buildspec.yml (YAML) or buildspec.json (JSON) supplied inline via
    ``buildspecOverride`` or embedded in the project source as ``buildspec``.
  - Phases executed: install → pre_build → build → post_build.
  - Two execution backends:
      CODEBUILD_EXECUTOR=local  (default) — runs commands in a subprocess shell
      CODEBUILD_EXECUTOR=docker            — runs commands inside the Docker image
        specified on the project environment (falls back to local if Docker is
        unavailable or the image cannot be pulled).
"""

import importlib
import json
import logging
import os
import shlex
import subprocess
import tempfile
import threading
import time
from typing import Any

try:
    import yaml as _yaml
    _yaml_available = True
except ImportError:  # pragma: no cover
    _yaml = None  # type: ignore[assignment]
    _yaml_available = False

try:
    docker_lib: Any = importlib.import_module("docker")
    _docker_available = True
except ImportError:
    docker_lib = None
    _docker_available = False

from ministack.core.responses import json_response, error_response_json, new_uuid, now_iso

logger = logging.getLogger("codebuild")

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"
BUILD_RUN_SECONDS = 1  # simulated build duration when no buildspec present

# Execution backend: "local" (subprocess) or "docker"
CODEBUILD_EXECUTOR = os.environ.get("CODEBUILD_EXECUTOR", "local").lower()

# Optional: map CodeBuild image identifiers to actual Docker image names.
# Can be overridden by the user in the project environment config.
_CODEBUILD_IMAGE_MAP: dict[str, str] = {
    "aws/codebuild/standard:7.0": "ubuntu:22.04",
    "aws/codebuild/standard:6.0": "ubuntu:22.04",
    "aws/codebuild/standard:5.0": "ubuntu:20.04",
    "aws/codebuild/amazonlinux2-x86_64-standard:5.0": "amazonlinux:2",
    "aws/codebuild/amazonlinux2-x86_64-standard:4.0": "amazonlinux:2",
}

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
        "buildStatus": "QUEUED",
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
        # Internal: raw log lines accumulated during execution
        "_log_lines": [],
    }
    return build


# ---------------------------------------------------------------------------
# Buildspec parsing
# ---------------------------------------------------------------------------

def _parse_buildspec(raw: str) -> dict | None:
    """Parse a buildspec string (YAML or JSON).

    Buildspec format follows the AWS CodeBuild specification:
      version: "0.2"
      env:
        variables:
          KEY: value
      phases:
        install:
          commands: [...]
        pre_build:
          commands: [...]
        build:
          commands: [...]
        post_build:
          commands: [...]

    Returns the parsed dict, or None if the input is empty or cannot be parsed.
    """
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    # Try JSON first (starts with '{')
    if raw.startswith("{"):
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse buildspec as JSON: %s", exc)
            return None
    # Try YAML
    if _yaml_available:
        try:
            return _yaml.safe_load(raw)
        except Exception as exc:
            logger.warning("Failed to parse buildspec as YAML: %s", exc)
            return None
    logger.warning("PyYAML is not installed — cannot parse YAML buildspec; install pyyaml to enable YAML support")
    return None


def _resolve_buildspec(build: dict, project: dict, overrides: dict) -> dict | None:
    """Return a parsed buildspec dict for this build, or None if unavailable."""
    # 1. buildspecOverride from StartBuild call
    raw = overrides.get("buildspecOverride")
    if raw:
        return _parse_buildspec(raw)
    # 2. Inline buildspec embedded in the project source config
    raw = project.get("source", {}).get("buildspec")
    if raw:
        return _parse_buildspec(raw)
    return None


def _make_phase_entry(phase_name: str, status: str, duration_ms: int = 0,
                      log: str = "") -> dict:
    return {
        "phaseType": phase_name,
        "phaseStatus": status,
        "startTime": now_iso(),
        "endTime": now_iso(),
        "durationInSeconds": max(0, duration_ms // 1000),
        "contexts": [{"statusCode": "0", "message": log}] if log else [],
    }


# ---------------------------------------------------------------------------
# Local (subprocess) build executor
# ---------------------------------------------------------------------------

def _run_phase_local(phase_name: str, commands: list[str],
                     env: dict[str, str], workdir: str) -> tuple[bool, str]:
    """Run a single buildspec phase locally.

    Returns (success, combined_log).
    """
    if not commands:
        return True, ""
    log_lines: list[str] = []
    for cmd in commands:
        log_lines.append(f"[{phase_name}] $ {cmd}")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                cwd=workdir,
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            if result.stdout:
                log_lines.append(result.stdout.rstrip())
            if result.stderr:
                log_lines.append(result.stderr.rstrip())
            if result.returncode != 0:
                log_lines.append(f"[{phase_name}] command failed (exit {result.returncode})")
                return False, "\n".join(log_lines)
        except subprocess.TimeoutExpired:
            log_lines.append(f"[{phase_name}] command timed out: {cmd}")
            return False, "\n".join(log_lines)
        except Exception as exc:
            log_lines.append(f"[{phase_name}] error: {exc}")
            return False, "\n".join(log_lines)
    return True, "\n".join(log_lines)


def _execute_buildspec_local(build: dict, spec: dict) -> str:
    """Execute all buildspec phases locally using subprocesses.

    Returns final build status: SUCCEEDED or FAILED.
    """
    phases_order = ["install", "pre_build", "build", "post_build"]
    spec_phases = spec.get("phases", {})

    # Merge environment variables: project env → buildspec env
    env = dict(os.environ)
    env.update({
        "CODEBUILD_BUILD_ID": build["id"],
        "CODEBUILD_BUILD_ARN": build["arn"],
        "CODEBUILD_PROJECT_NAME": build["projectName"],
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    })
    # Buildspec env.variables block
    for k, v in spec.get("env", {}).get("variables", {}).items():
        env[k] = str(v)
    # Project environment variables
    for ev in build.get("environment", {}).get("environmentVariables", []):
        env[ev["name"]] = ev.get("value", "")

    with tempfile.TemporaryDirectory(prefix="ministack-codebuild-") as workdir:
        for phase_name in phases_order:
            phase_cfg = spec_phases.get(phase_name, {})
            commands = phase_cfg.get("commands", [])
            if not commands:
                continue
            t0 = time.time()
            ok, log = _run_phase_local(phase_name, commands, env, workdir)
            elapsed_ms = int((time.time() - t0) * 1000)
            status = "SUCCEEDED" if ok else "FAILED"
            build["phases"].append(_make_phase_entry(
                phase_name.upper(), status, elapsed_ms, log
            ))
            build["_log_lines"].append(log)
            if not ok:
                return "FAILED"
    return "SUCCEEDED"


# ---------------------------------------------------------------------------
# Docker build executor
# ---------------------------------------------------------------------------

def _resolve_docker_image(build: dict) -> str:
    """Return the Docker image name to use for the build."""
    image = build.get("environment", {}).get("image", "")
    return _CODEBUILD_IMAGE_MAP.get(image, image) or "ubuntu:22.04"


def _execute_buildspec_docker(build: dict, spec: dict) -> str:
    """Execute buildspec phases inside a Docker container.

    Falls back to local subprocess execution if Docker is unavailable or errors.
    """
    if not _docker_available:
        logger.warning("Docker SDK unavailable — falling back to local executor for build %s", build["id"])
        return _execute_buildspec_local(build, spec)

    try:
        client = docker_lib.from_env()
    except Exception as exc:
        logger.warning("Cannot connect to Docker daemon (%s) — falling back to local executor", exc)
        return _execute_buildspec_local(build, spec)

    phases_order = ["install", "pre_build", "build", "post_build"]
    spec_phases = spec.get("phases", {})

    # Collect all commands as a single shell script so the container stays up.
    # Each phase is wrapped in a block that prints a START/END marker and captures
    # its own exit code so we can tell which phase failed without relying solely
    # on the overall container exit code.
    script_lines: list[str] = ["#!/bin/sh"]
    has_commands = False
    active_phases: list[str] = []

    for phase_name in phases_order:
        commands = spec_phases.get(phase_name, {}).get("commands", [])
        if not commands:
            continue
        has_commands = True
        active_phases.append(phase_name)
        script_lines.append(f"echo '__phase_start:{phase_name}__'")
        script_lines.append("(")
        for cmd in commands:
            script_lines.append(f"  {cmd} || exit $?")
        script_lines.append(")")
        script_lines.append(f"echo \"__phase_end:{phase_name}:$?__\"")
        # Stop the whole script on first phase failure
        script_lines.append(f'[ $? -eq 0 ] || exit 1')

    if not has_commands:
        return "SUCCEEDED"

    # Build environment variables
    container_env: dict[str, str] = {
        "CODEBUILD_BUILD_ID": build["id"],
        "CODEBUILD_BUILD_ARN": build["arn"],
        "CODEBUILD_PROJECT_NAME": build["projectName"],
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    }
    for k, v in spec.get("env", {}).get("variables", {}).items():
        container_env[k] = str(v)
    for ev in build.get("environment", {}).get("environmentVariables", []):
        container_env[ev["name"]] = ev.get("value", "")

    endpoint = os.environ.get("AWS_ENDPOINT_URL", "")
    if endpoint:
        container_env["AWS_ENDPOINT_URL"] = endpoint

    image = _resolve_docker_image(build)
    container = None

    try:
        with tempfile.TemporaryDirectory(prefix="ministack-codebuild-docker-") as tmpdir:
            script_path = os.path.join(tmpdir, "buildspec_run.sh")
            with open(script_path, "w") as sf:
                sf.write("\n".join(script_lines) + "\n")

            container = client.containers.run(
                image,
                command=["sh", "/workspace/buildspec_run.sh"],
                environment=container_env,
                volumes={tmpdir: {"bind": "/workspace", "mode": "rw"}},
                network_mode="host",
                detach=True,
                working_dir="/workspace",
            )
            timeout_sec = build.get("timeoutInMinutes", 60) * 60
            result = container.wait(timeout=min(timeout_sec, 3600))
            exit_code = result.get("StatusCode", -1)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

        # Parse per-phase logs from start/end markers
        current_phase: str | None = None
        phase_logs: dict[str, list[str]] = {}
        phase_exit: dict[str, int] = {}
        for line in logs.splitlines():
            if line.startswith("__phase_start:") and line.endswith("__"):
                current_phase = line[14:-2]
                phase_logs.setdefault(current_phase, [])
            elif line.startswith("__phase_end:") and line.endswith("__"):
                parts = line[12:-2].rsplit(":", 1)
                if len(parts) == 2:
                    p_name, p_rc = parts
                    try:
                        phase_exit[p_name] = int(p_rc)
                    except ValueError:
                        phase_exit[p_name] = 1
                current_phase = None
            elif current_phase is not None:
                phase_logs[current_phase].append(line)

        # Only record phases that actually started (markers seen in output)
        overall_status = "SUCCEEDED"
        for phase_name in active_phases:
            if phase_name not in phase_logs:
                # Phase never started (earlier phase failed and stopped the script)
                break
            p_rc = phase_exit.get(phase_name, exit_code)
            p_status = "SUCCEEDED" if p_rc == 0 else "FAILED"
            p_log = "\n".join(phase_logs[phase_name])
            build["phases"].append(_make_phase_entry(phase_name.upper(), p_status, 0, p_log))
            build["_log_lines"].append(p_log)
            if p_status == "FAILED":
                overall_status = "FAILED"
                break

        return overall_status

    except Exception as exc:
        logger.warning("Docker build execution failed (%s) — falling back to local executor", exc)
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        return _execute_buildspec_local(build, spec)
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Build runner (background thread)
# ---------------------------------------------------------------------------

def _run_build_async(build_id: str):
    """Execute a build in a background thread."""
    build = _builds.get(build_id)
    if not build:
        return
    project = _projects.get(build["projectName"], {})

    build["buildStatus"] = "IN_PROGRESS"
    build["currentPhase"] = "BUILD"

    # Resolve buildspec (may be None if project has no buildspec)
    spec = _resolve_buildspec(build, project, build.get("_overrides", {}))

    if spec:
        executor = CODEBUILD_EXECUTOR
        if executor == "docker":
            final_status = _execute_buildspec_docker(build, spec)
        else:
            final_status = _execute_buildspec_local(build, spec)
    else:
        # No buildspec — simulate a successful build
        time.sleep(BUILD_RUN_SECONDS)
        final_status = "SUCCEEDED"

    build = _builds.get(build_id)
    if not build:
        return
    if build["buildStatus"] == "STOPPED":
        return

    build["buildStatus"] = final_status
    build["currentPhase"] = "COMPLETED"
    build["buildComplete"] = True
    build["endTime"] = now_iso()
    build["resolvedSourceVersion"] = new_uuid()[:8]
    # Remove internal key before it leaks to API responses
    build.pop("_overrides", None)


def _start_build(data):
    project_name = data.get("projectName")
    if not project_name:
        return error_response_json("InvalidInputException", "projectName is required", 400)
    if project_name not in _projects:
        return error_response_json("ResourceNotFoundException",
                                   f"Project not found: {project_name}", 400)
    build = _make_build(project_name, data)
    # Stash overrides for the async executor (not exposed in API responses)
    build["_overrides"] = {
        "buildspecOverride": data.get("buildspecOverride", ""),
    }
    _builds[build["id"]] = build
    threading.Thread(target=_run_build_async, args=(build["id"],), daemon=True).start()
    return json_response({"build": _public_build(build)})


def _public_build(build: dict) -> dict:
    """Return a copy of the build dict without internal-only keys."""
    return {k: v for k, v in build.items() if not k.startswith("_")}


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
    return json_response({"build": _public_build(build)})


def _batch_get_builds(data):
    ids = data.get("ids", [])
    found = [_public_build(_builds[bid]) for bid in ids if bid in _builds]
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
