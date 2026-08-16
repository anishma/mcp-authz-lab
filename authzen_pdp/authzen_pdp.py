"""authzen-pdp: an OpenID AuthZEN Authorization API PDP backed by Cedar.

This is the Policy Decision Point (PDP). It exposes the standard AuthZEN
evaluation endpoint

    POST /access/v1/evaluation
    { "subject": {...}, "action": {...}, "resource": {...}, "context": {...} }
    -> { "decision": true | false }

and answers each request by evaluating Cedar policy directly in the official
Cedar engine (the Rust `cedar-policy` crate, via its Python binding). No
external policy service is involved: the PDP owns the engine.

AuthZEN's (subject, action, resource, context) tuple maps one-to-one onto
Cedar's (principal, action, resource, context), which is what lets the open API
and the open policy language compose cleanly:

    subject  {type,id}  -> principal  User::"<id>"
    action   {name}     -> action     Action::"<name>"
    resource {type,id}  -> resource   Tool::"<id>"
    context             -> context    (passed through)

Policies and entities are read from the mounted files on every request, so a
student editing the Cedar policy sees the effect on the next tool call with no
restart and no separate loader step.
"""

import json
import os
import pathlib

import cedarpy
from fastapi import FastAPI
from pydantic import BaseModel

POLICY_FILE = pathlib.Path(os.environ.get("POLICY_FILE", "/policies/policies.starter.cedar"))
ENTITIES_FILE = pathlib.Path(os.environ.get("ENTITIES_FILE", "/policies/entities.json"))

app = FastAPI(title="AuthZEN PDP (Cedar-backed)")


class Subject(BaseModel):
    type: str
    id: str


class Action(BaseModel):
    name: str


class Resource(BaseModel):
    type: str
    id: str


class EvaluationRequest(BaseModel):
    subject: Subject
    action: Action
    resource: Resource
    context: dict = {}


def _entity_type(kind: str) -> str:
    # Map AuthZEN entity types onto the Cedar entity types the lab's schema uses.
    return {"user": "User", "tool": "Tool"}.get(kind.lower(), kind.capitalize())


@app.post("/access/v1/evaluation")
def evaluate(req: EvaluationRequest) -> dict:
    cedar_request = {
        "principal": f'{_entity_type(req.subject.type)}::"{req.subject.id}"',
        "action": f'Action::"{req.action.name}"',
        "resource": f'{_entity_type(req.resource.type)}::"{req.resource.id}"',
        "context": req.context,
    }
    try:
        policies = POLICY_FILE.read_text()
        entities = json.loads(ENTITIES_FILE.read_text())
        result = cedarpy.is_authorized(cedar_request, policies, entities)
        allowed = result.decision == cedarpy.Decision.Allow
    except Exception as exc:
        # Fail closed: a policy error or missing file denies.
        return {"decision": False, "context": {"reason": f"evaluation error: {exc}"}}
    return {"decision": allowed}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
