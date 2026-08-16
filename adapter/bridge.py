"""gateway-bridge: connects the MCP gateway's policy hook to an AuthZEN PDP.

agentgateway is the Policy Enforcement Point (PEP). It calls this bridge over
its ExtMcp gRPC hook for every MCP `tools/call`. The bridge is the PEP-side
adapter: it turns the tool invocation into an **OpenID AuthZEN Authorization
API** evaluation request and sends it to the PDP over the standard wire format

    POST /access/v1/evaluation
    {
      "subject":  {"type": "user", "id": "<sub from the caller's JWT>"},
      "action":   {"name": "invoke"},
      "resource": {"type": "tool", "id": "<MCP tool name>"},
      "context":  {"args": <tool-call arguments>}
    }

and expects the AuthZEN response `{"decision": true|false}`. A deny becomes a
JSON-RPC permission error the agent receives. Using AuthZEN here means the
PEP->PDP contract is a vendor-neutral open standard, not a product-specific API.
"""

import json
import logging
import os
from concurrent import futures

import grpc
import httpx

import ext_mcp_pb2
import ext_mcp_pb2_grpc

PDP_URL = os.environ.get("PDP_URL", "http://authzen-pdp:8080")
LISTEN = os.environ.get("LISTEN", "0.0.0.0:50051")

logging.basicConfig(level=logging.INFO, format="%(asctime)s gateway-bridge %(message)s")
log = logging.getLogger(__name__)

# `pass` is a Python keyword, so the oneof arm is set via dict expansion.
PASS_REQUEST = ext_mcp_pb2.McpRequestResult(**{"pass": ext_mcp_pb2.Pass()})
PASS_RESPONSE = ext_mcp_pb2.McpResponseResult(**{"pass": ext_mcp_pb2.Pass()})


def deny(reason: str) -> ext_mcp_pb2.McpRequestResult:
    return ext_mcp_pb2.McpRequestResult(
        error=ext_mcp_pb2.AuthorizationError(
            code=ext_mcp_pb2.AuthorizationError.PERMISSION_DENIED,
            reason=reason,
        )
    )


class ExtMcpServicer(ext_mcp_pb2_grpc.ExtMcpServicer):
    def CheckRequest(self, request, grpc_context):
        if request.method != "tools/call":
            return PASS_REQUEST

        sub = (
            request.metadata_context.fields["sub"].string_value
            if "sub" in request.metadata_context.fields
            else ""
        )
        if not sub:
            return deny("no authenticated principal forwarded to the PDP")

        params = json.loads(request.mcp_request) if request.mcp_request else {}
        tool = params.get("name", "")
        args = params.get("arguments") or {}

        # AuthZEN Authorization API 1.0 evaluation request.
        authzen_request = {
            "subject": {"type": "user", "id": sub},
            "action": {"name": "invoke"},
            "resource": {"type": "tool", "id": tool},
            "context": {"args": args},
        }
        try:
            resp = httpx.post(
                f"{PDP_URL}/access/v1/evaluation", json=authzen_request, timeout=5.0
            )
            resp.raise_for_status()
            decision = bool(resp.json().get("decision", False))
        except Exception as exc:
            log.error("PDP unreachable: %s", exc)
            return deny("policy decision point unavailable (failing closed)")

        log.info(
            "subject=%s tool=%s args=%s -> decision=%s",
            sub, tool, json.dumps(args), decision,
        )
        if decision:
            return PASS_REQUEST
        return deny(
            f'AuthZEN PDP denied: user "{sub}" may not invoke {tool} with these arguments'
        )

    def CheckResponse(self, request, grpc_context):
        return PASS_RESPONSE


def main() -> None:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    ext_mcp_pb2_grpc.add_ExtMcpServicer_to_server(ExtMcpServicer(), server)
    server.add_insecure_port(LISTEN)
    server.start()
    log.info("listening on %s, AuthZEN PDP at %s", LISTEN, PDP_URL)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
