# Fine-Grained Authorization for MCP Tool Invocations — a hands-on lab

An open-source teaching lab about authorizing what an AI agent is allowed to
*do*. You secure a deliberately over-capable finance assistant exposed over the
[Model Context Protocol (MCP)](https://modelcontextprotocol.io), moving from no
authorization, to coarse per-tool rules, to fine-grained rules that inspect the
delegating user's identity **and the arguments of each tool call**.

Everything is open source and runs from one `docker compose` command. No cloud
accounts, no API keys, no LLM required — the "agent" is a scripted MCP client
whose actions you can read.

## What you build

```
   agent.py  ──JWT──▶  agentgateway  ──▶  PayFlow MCP server
 (the agent)          (gateway / PEP)      (the tools)
                            │
                            ▼  (Exercise 3 only)  ExtMcp
                      gateway-bridge
                            │  AuthZEN  POST /access/v1/evaluation
                            ▼
                       authzen-pdp
                    (AuthZEN PDP; evaluates Cedar policy in-process)
```

- **agentgateway** — an open-source MCP gateway; here the Policy Enforcement Point (PEP).
- **gateway-bridge** — a small adapter (`adapter/`) that turns the gateway's ExtMcp hook into a standard [OpenID AuthZEN](https://openid.net/specs/authorization-api-1_0-01.html) evaluation request.
- **authzen-pdp** — the Policy Decision Point (`authzen_pdp/`): exposes the vendor-neutral AuthZEN `POST /access/v1/evaluation` API and answers each call by evaluating [Cedar](https://www.cedarpolicy.com/) policy in-process, using the official Cedar engine (the Rust `cedar-policy` crate via its Python binding). No separate policy server is involved.
- **PayFlow** — a small MCP server (in `server/`) exposing four tools of a fictional finance assistant. All data is fictional and resets on restart.

The lab teaches two open standards at once: **AuthZEN** for the PEP→PDP *API* and **Cedar** for the *policy language* behind it.

## Prerequisites

- Docker + Docker Compose
- **Python 3.10+** for the host-side agent and validator (tested on 3.12). Create the
  virtual environment once — use a 3.10+ interpreter explicitly, since a machine's
  default `python3` is often older (macOS ships 3.9, and there is no bare `python`):
  ```bash
  python3.12 -m venv .venv        # or any python3.10+; e.g. python3.11
  ./.venv/bin/pip install -r client/requirements.txt
  ```
  Every `./.venv/bin/python …` command below then runs inside this environment.
  (Prefer `source .venv/bin/activate` once, and you can drop the `./.venv/bin/`
  prefix and just type `python …`.)
- Identity fixtures (JWKS + persona JWTs) are committed, so you normally do nothing.
  To regenerate them: `./.venv/bin/python identity/make_tokens.py`.

## The scenario

Two people delegate tasks to the assistant:

| Persona | Role | Payment limit |
|---------|------|---------------|
| **alice** | finance | \$500 |
| **bob** | engineering intern | none |

The threat is **indirect prompt injection**: a document the agent reads tells it
to pay a fraudulent \$250,000 invoice (`I-1002`, vendor "QuickCash LLC") and to
email an employee's HR record to `drop@attacker.example`. The `demo
prompt-injection` command replays exactly those tool calls.

---

## Exercise 1 — the ungoverned agent

Bring up the stack with no authorization:

```bash
GATEWAY_CONFIG=e1-ungoverned.yaml docker compose up -d
```

Run the poisoned task as the intern:

```bash
./.venv/bin/python client/agent.py --as bob demo prompt-injection
```

Every call succeeds: the intern's agent pays \$250,000 and mails out an HR
record. The gateway authenticated *who* delegated the agent (the JWT is valid)
but authorized *nothing*. **Authentication is not authorization.**

> Question: the toy server's port is also published on `localhost:8000`. What
> happens if the agent talks to it directly? What does that tell you about
> where enforcement has to live?

## Exercise 2 — coarse, per-tool control (and its bypass)

```bash
GATEWAY_CONFIG=e2-coarse.yaml docker compose up -d gateway
docker compose restart payflow      # reset the fictional ledger
```

The gateway now applies per-tool rules keyed on the caller's role
(`gateway/e2-coarse.yaml`): only finance may `pay_invoice`; only
finance/HR may `get_employee`. List bob's tools — the ones he may not call have
**disappeared from his catalog**:

```bash
./.venv/bin/python client/agent.py --as bob list-tools
./.venv/bin/python client/agent.py --as bob demo prompt-injection   # pay/get_employee now DENIED
```

Now run the **same attack as alice**, who legitimately belongs to finance:

```bash
docker compose restart payflow
./.venv/bin/python client/agent.py --as alice demo prompt-injection
```

The \$250,000 payment and the exfiltration email both succeed. Tool-name rules
cannot see the *amount* or the *recipient*. **You just defeated your own
configuration.** Per-tool allow/deny is not enough.

## Exercise 3 — fine-grained authorization with AuthZEN + Cedar

```bash
GATEWAY_CONFIG=e3-finegrained.yaml docker compose up -d gateway gateway-bridge authzen-pdp payflow
```

Now every `tools/call` is forwarded — with its full arguments — as an AuthZEN
evaluation request to the PDP, which decides it against Cedar policy.

**This is the exercise: you write the policies.** By default the PDP loads
`pdp/policies.starter.cedar`, which permits **only** `list_invoices` — every
other tool is a `// TODO` and Cedar denies anything not explicitly permitted.
So right now, `pay_invoice`, `get_employee`, and `send_email` are **all denied,
for everyone** — that is the correct starting point, not a bug. Your job is to
edit `pdp/policies.starter.cedar` to add least-privilege rules: cap payments at
the caller's `payment_limit`, restrict HR reads to self-or-HR, and allow email
only to company addresses. The PDP re-reads the file on every request, so each
edit takes effect on the next tool call — no restart, no reload step.

You can test a single rule against the PDP directly with a standard AuthZEN
request (this is exactly what the gateway sends per call):

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation -H 'Content-Type: application/json' -d '{
  "subject":{"type":"user","id":"alice"},
  "action":{"name":"invoke"},
  "resource":{"type":"tool","id":"pay_invoice"},
  "context":{"args":{"amount":250000}}}'
# -> {"decision":false}   (once you've written the pay_invoice rule)
```

### Seeing the finished state

When your policies are complete, the poisoned task is blocked at exactly the
offending calls while alice's legitimate work still succeeds. If you'd rather
**skip ahead and load the instructor answer key** (`pdp/policies.solution.cedar`)
instead of writing the rules yourself, recreate just the PDP with it:

```bash
CEDAR_POLICIES=policies.solution.cedar docker compose up -d authzen-pdp
```

Either way — your completed starter, or the solution — verify the behavior:

```bash
docker compose restart payflow
./.venv/bin/python client/agent.py --as alice demo prompt-injection    # all DENIED
docker compose restart payflow
./.venv/bin/python client/agent.py --as alice demo legitimate-work     # all ALLOW
```

To go back to the starter (your own work), recreate the PDP without the override:
`docker compose up -d authzen-pdp`.

---

## Validating the whole matrix

`tests/validate.py` asserts the expected allow/deny outcome for every case in an
exercise and reports median call latency. The harness talks to the same gateway,
so each exercise must be brought up with its own config first:

```bash
# E1
GATEWAY_CONFIG=e1-ungoverned.yaml docker compose up -d gateway && docker compose restart payflow
EXERCISE=e1 ./.venv/bin/python tests/validate.py

# E2
GATEWAY_CONFIG=e2-coarse.yaml docker compose up -d gateway && docker compose restart payflow
EXERCISE=e2 ./.venv/bin/python tests/validate.py

# E3 — load the solution policies so legitimate work is permitted
GATEWAY_CONFIG=e3-finegrained.yaml docker compose up -d gateway
CEDAR_POLICIES=policies.solution.cedar docker compose up -d authzen-pdp
docker compose restart payflow
EXERCISE=e3 ./.venv/bin/python tests/validate.py
```

## Layout

```
server/       PayFlow MCP server + Dockerfile
gateway/      one agentgateway config per exercise (e1/e2/e3)
adapter/      gateway-bridge: the ExtMcp gRPC -> AuthZEN bridge (PEP side)
authzen_pdp/  authzen-pdp: the AuthZEN /access/v1/evaluation PDP (embeds Cedar)
pdp/          Cedar policies (starter + solution) and entities
client/       agent.py: the scripted delegated agent
identity/     local issuer keypair, JWKS, persona JWTs (test fixtures)
tests/        validate.py: the outcome-matrix harness
```

## Credits & licensing

This lab composes independent open-source projects and open standards, each
under its own license/terms:
[agentgateway](https://github.com/agentgateway/agentgateway) (Apache-2.0),
the [Cedar](https://www.cedarpolicy.com/) policy language and engine (Apache-2.0,
via the `cedarpy` Python binding),
the [OpenID AuthZEN Authorization API](https://openid.net/specs/authorization-api-1_0-01.html),
and the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk). The
`adapter/ext_mcp.proto` file is vendored from agentgateway (Apache-2.0). Lab
code in this repository is released under the MIT License (`LICENSE`).
