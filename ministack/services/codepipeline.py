"""
CodePipeline Service Emulator.
JSON-based API via X-Amz-Target (CodePipeline_20150709).

Supports: CreatePipeline, GetPipeline, UpdatePipeline, DeletePipeline, ListPipelines,
          StartPipelineExecution, StopPipelineExecution,
          GetPipelineExecution, ListPipelineExecutions,
          GetPipelineState,
          ListActionTypes,
          PutApprovalResult,
          AcknowledgeJob, PollForJobs,
          PutJobSuccessResult, PutJobFailureResult,
          EnableStageTransition, DisableStageTransition,
          RetryStageExecution,
          TagResource, UntagResource, ListTagsForResource.

Pipeline executions advance through stages asynchronously:
  InProgress -> Succeeded / Failed / Stopped.
"""

import json
import logging
import threading
import time

from ministack.core.responses import json_response, error_response_json, new_uuid, now_iso

logger = logging.getLogger("codepipeline")

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"
EXECUTION_RUN_SECONDS = 1  # simulated execution duration

_pipelines: dict = {}    # name -> pipeline definition dict
_executions: dict = {}   # execution_id -> execution dict
_stage_states: dict = {}  # pipeline_name -> list of stage-state dicts
_disabled_transitions: dict = {}  # pipeline_name -> set of stage names
_jobs: dict = {}         # job_id -> job dict (for custom action jobs)
_tags: dict = {}         # arn -> {key: value}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pipeline_arn(name: str) -> str:
    return f"arn:aws:codepipeline:{REGION}:{ACCOUNT_ID}:{name}"


def _execution_arn(name: str, exec_id: str) -> str:
    return f"arn:aws:codepipeline:{REGION}:{ACCOUNT_ID}:{name}/{exec_id}"


def _init_stage_states(pipeline_name: str, stages: list):
    """Initialise stage-state structures for a pipeline."""
    _stage_states[pipeline_name] = [
        {
            "stageName": s.get("name", ""),
            "inboundTransitionState": {
                "enabled": True,
                "lastChangedBy": "",
                "lastChangedAt": now_iso(),
            },
            "actionStates": [
                {
                    "actionName": a.get("name", ""),
                    "currentRevision": None,
                    "latestExecution": None,
                    "entityUrl": "",
                    "revisionUrl": "",
                }
                for a in s.get("actions", [])
            ],
            "latestExecution": None,
        }
        for s in stages
    ]
    _disabled_transitions.setdefault(pipeline_name, set())


def _run_execution_async(pipeline_name: str, execution_id: str):
    """Simulate pipeline execution in a background thread."""
    time.sleep(EXECUTION_RUN_SECONDS)
    execution = _executions.get(execution_id)
    if not execution:
        return
    if execution["status"] in ("Stopped", "Stopping"):
        execution["status"] = "Stopped"
        return
    execution["status"] = "Succeeded"

    # Update stage states
    for ss in _stage_states.get(pipeline_name, []):
        ss["latestExecution"] = {
            "pipelineExecutionId": execution_id,
            "status": "Succeeded",
        }
        for action_state in ss.get("actionStates", []):
            action_state["latestExecution"] = {
                "actionExecutionId": new_uuid(),
                "status": "Succeeded",
                "summary": "",
                "lastUpdatedBy": "",
                "lastStatusChange": now_iso(),
                "token": "",
                "lastStatusChangeEpochMillis": int(time.time() * 1000),
                "errorDetails": None,
                "externalExecutionId": None,
                "externalExecutionUrl": None,
                "percentComplete": 100,
            }


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
        "CreatePipeline": _create_pipeline,
        "GetPipeline": _get_pipeline,
        "UpdatePipeline": _update_pipeline,
        "DeletePipeline": _delete_pipeline,
        "ListPipelines": _list_pipelines,
        "StartPipelineExecution": _start_pipeline_execution,
        "StopPipelineExecution": _stop_pipeline_execution,
        "GetPipelineExecution": _get_pipeline_execution,
        "ListPipelineExecutions": _list_pipeline_executions,
        "GetPipelineState": _get_pipeline_state,
        "ListActionTypes": _list_action_types,
        "PutApprovalResult": _put_approval_result,
        "AcknowledgeJob": _acknowledge_job,
        "PollForJobs": _poll_for_jobs,
        "PutJobSuccessResult": _put_job_success_result,
        "PutJobFailureResult": _put_job_failure_result,
        "EnableStageTransition": _enable_stage_transition,
        "DisableStageTransition": _disable_stage_transition,
        "RetryStageExecution": _retry_stage_execution,
        "TagResource": _tag_resource,
        "UntagResource": _untag_resource,
        "ListTagsForResource": _list_tags_for_resource,
    }

    handler = handlers.get(action)
    if not handler:
        return error_response_json("InvalidAction", f"Unknown action: {action}", 400)
    return handler(data)


# ---------------------------------------------------------------------------
# Pipeline CRUD
# ---------------------------------------------------------------------------

def _create_pipeline(data):
    pipeline = data.get("pipeline")
    if not pipeline:
        return error_response_json("InvalidStructureException", "pipeline is required", 400)
    name = pipeline.get("name")
    if not name:
        return error_response_json("InvalidStructureException", "pipeline.name is required", 400)
    if name in _pipelines:
        return error_response_json("PipelineNameInUseException",
                                   f"Pipeline already exists: {name}", 400)

    pipeline.setdefault("roleArn", f"arn:aws:iam::{ACCOUNT_ID}:role/codepipeline-role")
    pipeline.setdefault("artifactStore", {
        "type": "S3",
        "location": f"codepipeline-{REGION}-{ACCOUNT_ID}",
    })
    pipeline.setdefault("stages", [])
    pipeline.setdefault("version", 1)

    metadata = {
        "pipelineArn": _pipeline_arn(name),
        "created": now_iso(),
        "updated": now_iso(),
        "pollingDisabledAt": None,
    }
    _pipelines[name] = {"pipeline": pipeline, "metadata": metadata}
    _init_stage_states(name, pipeline.get("stages", []))

    tags = data.get("tags", [])
    if tags:
        _tags[metadata["pipelineArn"]] = {t.get("key", ""): t.get("value", "") for t in tags}

    return json_response({"pipeline": pipeline, "tags": tags})


def _get_pipeline(data):
    name = data.get("name")
    if not name:
        return error_response_json("ValidationException", "name is required", 400)
    entry = _pipelines.get(name)
    if not entry:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    return json_response({"pipeline": entry["pipeline"], "metadata": entry["metadata"]})


def _update_pipeline(data):
    pipeline = data.get("pipeline")
    if not pipeline:
        return error_response_json("InvalidStructureException", "pipeline is required", 400)
    name = pipeline.get("name")
    if not name:
        return error_response_json("InvalidStructureException", "pipeline.name is required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    entry = _pipelines[name]
    old_version = entry["pipeline"].get("version", 1)
    pipeline["version"] = old_version + 1
    entry["pipeline"] = pipeline
    entry["metadata"]["updated"] = now_iso()
    _init_stage_states(name, pipeline.get("stages", []))
    return json_response({"pipeline": pipeline})


def _delete_pipeline(data):
    name = data.get("name")
    if not name:
        return error_response_json("ValidationException", "name is required", 400)
    entry = _pipelines.pop(name, None)
    _stage_states.pop(name, None)
    _disabled_transitions.pop(name, None)
    if entry:
        _tags.pop(entry["metadata"]["pipelineArn"], None)
    return json_response({})


def _list_pipelines(data):
    pipelines = [
        {
            "name": name,
            "version": e["pipeline"].get("version", 1),
            "pipelineType": e["pipeline"].get("pipelineType", "V1"),
            "created": e["metadata"]["created"],
            "updated": e["metadata"]["updated"],
        }
        for name, e in _pipelines.items()
    ]
    return json_response({"pipelines": pipelines})


# ---------------------------------------------------------------------------
# Execution operations
# ---------------------------------------------------------------------------

def _start_pipeline_execution(data):
    name = data.get("name")
    if not name:
        return error_response_json("ValidationException", "name is required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    exec_id = new_uuid()
    execution = {
        "pipelineExecutionId": exec_id,
        "pipelineName": name,
        "pipelineVersion": _pipelines[name]["pipeline"].get("version", 1),
        "status": "InProgress",
        "statusSummary": "",
        "artifactRevisions": [],
        "trigger": {
            "triggerType": "StartPipelineExecution",
            "triggerDetail": data.get("clientRequestToken", ""),
        },
        "startTime": now_iso(),
        "lastUpdateTime": now_iso(),
        "executionMode": data.get("executionMode", "QUEUED"),
    }
    _executions[exec_id] = execution
    threading.Thread(target=_run_execution_async, args=(name, exec_id), daemon=True).start()
    return json_response({"pipelineExecutionId": exec_id})


def _stop_pipeline_execution(data):
    name = data.get("pipelineName")
    exec_id = data.get("pipelineExecutionId")
    if not name or not exec_id:
        return error_response_json("ValidationException",
                                   "pipelineName and pipelineExecutionId are required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    execution = _executions.get(exec_id)
    if not execution:
        return error_response_json("PipelineExecutionNotFoundException",
                                   f"Execution not found: {exec_id}", 400)
    if execution["status"] not in ("InProgress",):
        return error_response_json("PipelineExecutionNotStoppableException",
                                   "Execution is not in a stoppable state", 400)
    abandon = data.get("abandon", False)
    execution["status"] = "Stopped" if abandon else "Stopping"
    execution["statusSummary"] = data.get("reason", "")
    execution["lastUpdateTime"] = now_iso()
    return json_response({"pipelineExecutionId": exec_id})


def _get_pipeline_execution(data):
    name = data.get("pipelineName")
    exec_id = data.get("pipelineExecutionId")
    if not name or not exec_id:
        return error_response_json("ValidationException",
                                   "pipelineName and pipelineExecutionId are required", 400)
    execution = _executions.get(exec_id)
    if not execution or execution.get("pipelineName") != name:
        return error_response_json("PipelineExecutionNotFoundException",
                                   f"Execution not found: {exec_id}", 400)
    return json_response({"pipelineExecution": execution})


def _list_pipeline_executions(data):
    name = data.get("pipelineName")
    if not name:
        return error_response_json("ValidationException", "pipelineName is required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    max_results = data.get("maxResults", 100)
    execs = [
        {
            "pipelineExecutionId": e["pipelineExecutionId"],
            "status": e["status"],
            "statusSummary": e.get("statusSummary", ""),
            "startTime": e["startTime"],
            "lastUpdateTime": e["lastUpdateTime"],
            "trigger": {"triggerType": "StartPipelineExecution", "triggerDetail": ""},
            "executionMode": e.get("executionMode", "QUEUED"),
        }
        for e in _executions.values()
        if e.get("pipelineName") == name
    ]
    execs.sort(key=lambda x: x["startTime"], reverse=True)
    return json_response({"pipelineExecutionSummaries": execs[:max_results]})


def _get_pipeline_state(data):
    name = data.get("name")
    if not name:
        return error_response_json("ValidationException", "name is required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    entry = _pipelines[name]
    stage_states = _stage_states.get(name, [])
    return json_response({
        "pipelineName": name,
        "pipelineVersion": entry["pipeline"].get("version", 1),
        "stageStates": stage_states,
        "created": entry["metadata"]["created"],
        "updated": entry["metadata"]["updated"],
    })


# ---------------------------------------------------------------------------
# Action types
# ---------------------------------------------------------------------------

_BUILT_IN_ACTION_TYPES = [
    {
        "id": {"category": "Source", "owner": "AWS", "provider": "CodeCommit", "version": "1"},
        "settings": {"executionUrlTemplate": "", "revisionUrlTemplate": ""},
        "actionConfigurationProperties": [],
        "inputArtifactDetails": {"minimumCount": 0, "maximumCount": 0},
        "outputArtifactDetails": {"minimumCount": 1, "maximumCount": 1},
    },
    {
        "id": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "settings": {"executionUrlTemplate": "", "revisionUrlTemplate": ""},
        "actionConfigurationProperties": [],
        "inputArtifactDetails": {"minimumCount": 0, "maximumCount": 0},
        "outputArtifactDetails": {"minimumCount": 1, "maximumCount": 1},
    },
    {
        "id": {"category": "Build", "owner": "AWS", "provider": "CodeBuild", "version": "1"},
        "settings": {"executionUrlTemplate": "", "revisionUrlTemplate": ""},
        "actionConfigurationProperties": [],
        "inputArtifactDetails": {"minimumCount": 1, "maximumCount": 5},
        "outputArtifactDetails": {"minimumCount": 0, "maximumCount": 5},
    },
    {
        "id": {"category": "Deploy", "owner": "AWS", "provider": "CloudFormation", "version": "1"},
        "settings": {"executionUrlTemplate": "", "revisionUrlTemplate": ""},
        "actionConfigurationProperties": [],
        "inputArtifactDetails": {"minimumCount": 1, "maximumCount": 10},
        "outputArtifactDetails": {"minimumCount": 0, "maximumCount": 1},
    },
    {
        "id": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
        "settings": {"executionUrlTemplate": ""},
        "actionConfigurationProperties": [],
        "inputArtifactDetails": {"minimumCount": 0, "maximumCount": 0},
        "outputArtifactDetails": {"minimumCount": 0, "maximumCount": 0},
    },
]


def _list_action_types(data):
    action_owner_filter = data.get("actionOwnerFilter")
    types = _BUILT_IN_ACTION_TYPES
    if action_owner_filter:
        types = [t for t in types if t["id"]["owner"] == action_owner_filter]
    return json_response({"actionTypes": types})


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

def _put_approval_result(data):
    name = data.get("pipelineName")
    stage_name = data.get("stageName")
    action_name = data.get("actionName")
    result = data.get("result", {})
    if not name or not stage_name or not action_name:
        return error_response_json("ValidationException",
                                   "pipelineName, stageName, and actionName are required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    approved_at = now_iso()
    return json_response({"approvedAt": approved_at})


# ---------------------------------------------------------------------------
# Job polling (custom actions)
# ---------------------------------------------------------------------------

def _poll_for_jobs(data):
    action_type_id = data.get("actionTypeId", {})
    max_batch_size = data.get("maxBatchSize", 1)
    jobs_to_return = []
    for job_id, job in list(_jobs.items()):
        if job.get("status") == "Created":
            if (job.get("actionTypeId", {}).get("category") == action_type_id.get("category") and
                    job.get("actionTypeId", {}).get("provider") == action_type_id.get("provider")):
                jobs_to_return.append(job)
                if len(jobs_to_return) >= max_batch_size:
                    break
    return json_response({"jobs": jobs_to_return})


def _acknowledge_job(data):
    job_id = data.get("jobId")
    nonce = data.get("nonce")
    if not job_id:
        return error_response_json("ValidationException", "jobId is required", 400)
    job = _jobs.get(job_id)
    if not job:
        return error_response_json("JobNotFoundException", f"Job not found: {job_id}", 400)
    return json_response({"status": "InProgress"})


def _put_job_success_result(data):
    job_id = data.get("jobId")
    if not job_id:
        return error_response_json("ValidationException", "jobId is required", 400)
    job = _jobs.get(job_id)
    if job:
        job["status"] = "Succeeded"
    return json_response({})


def _put_job_failure_result(data):
    job_id = data.get("jobId")
    if not job_id:
        return error_response_json("ValidationException", "jobId is required", 400)
    job = _jobs.get(job_id)
    if job:
        job["status"] = "Failed"
        job["failureDetails"] = data.get("failureDetails", {})
    return json_response({})


# ---------------------------------------------------------------------------
# Stage transitions
# ---------------------------------------------------------------------------

def _enable_stage_transition(data):
    name = data.get("pipelineName")
    stage_name = data.get("stageName")
    transition_type = data.get("transitionType", "Inbound")
    if not name or not stage_name:
        return error_response_json("ValidationException",
                                   "pipelineName and stageName are required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    _disabled_transitions.setdefault(name, set()).discard(stage_name)
    for ss in _stage_states.get(name, []):
        if ss["stageName"] == stage_name:
            ss["inboundTransitionState"]["enabled"] = True
            ss["inboundTransitionState"]["lastChangedAt"] = now_iso()
    return json_response({})


def _disable_stage_transition(data):
    name = data.get("pipelineName")
    stage_name = data.get("stageName")
    transition_type = data.get("transitionType", "Inbound")
    reason = data.get("reason", "")
    if not name or not stage_name:
        return error_response_json("ValidationException",
                                   "pipelineName and stageName are required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    _disabled_transitions.setdefault(name, set()).add(stage_name)
    for ss in _stage_states.get(name, []):
        if ss["stageName"] == stage_name:
            ss["inboundTransitionState"]["enabled"] = False
            ss["inboundTransitionState"]["disabledReason"] = reason
            ss["inboundTransitionState"]["lastChangedAt"] = now_iso()
    return json_response({})


# ---------------------------------------------------------------------------
# Retry stage execution
# ---------------------------------------------------------------------------

def _retry_stage_execution(data):
    name = data.get("pipelineName")
    stage_name = data.get("stageName")
    exec_id = data.get("pipelineExecutionId")
    retry_mode = data.get("retryMode", "FAILED_ACTIONS")
    if not name or not stage_name or not exec_id:
        return error_response_json("ValidationException",
                                   "pipelineName, stageName, and pipelineExecutionId are required", 400)
    if name not in _pipelines:
        return error_response_json("PipelineNotFoundException",
                                   f"Pipeline not found: {name}", 400)
    return json_response({"pipelineExecutionId": exec_id})


# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------

def _tag_resource(data):
    arn = data.get("resourceArn")
    raw_tags = data.get("tags", [])
    if not arn:
        return error_response_json("ValidationException", "resourceArn is required", 400)
    existing = _tags.get(arn, {})
    for t in raw_tags:
        existing[t.get("key", "")] = t.get("value", "")
    _tags[arn] = existing
    return json_response({})


def _untag_resource(data):
    arn = data.get("resourceArn")
    tag_keys = data.get("tagKeys", [])
    if not arn:
        return error_response_json("ValidationException", "resourceArn is required", 400)
    existing = _tags.get(arn, {})
    for k in tag_keys:
        existing.pop(k, None)
    _tags[arn] = existing
    return json_response({})


def _list_tags_for_resource(data):
    arn = data.get("resourceArn")
    if not arn:
        return error_response_json("ValidationException", "resourceArn is required", 400)
    raw = _tags.get(arn, {})
    tags = [{"key": k, "value": v} for k, v in raw.items()]
    return json_response({"tags": tags})


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def reset():
    global _pipelines, _executions, _stage_states, _disabled_transitions, _jobs, _tags
    _pipelines.clear()
    _executions.clear()
    _stage_states.clear()
    _disabled_transitions.clear()
    _jobs.clear()
    _tags.clear()
