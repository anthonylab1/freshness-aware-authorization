# Freshness-aware authorization with Policy as Code

A reference implementation of an access control policy written in Rego (Open
Policy Agent), with an explicit data contract, a dependency-free Python
integration, 144 tests and reproducible CI.

**This is not any client's or organisation's system.** It is a personal
exercise, written to explore how to design an authorization policy that does not
fail silently. The identifier `RCI-EXP-001` is fictional.

---

## The problem

A caseworker asks to open a record. Do we let them?

The naive answer is to check whether their unit matches the unit assigned to the
record. But that check hides several traps that only surface in production:

**The data you decide with may be stale.** The record assignment is served by
another system. If that source has not been updated for hours, "the unit
matches" is a statement about the past, not the present. Deciding on stale data
is as dangerous as deciding with no data at all.

**Malformed input must not take the engine down.** If an impossible date
(`2026-02-31`) arrives, or a field with the wrong type, or a JSON payload that
is not even an object, the policy must not abort: it must *deny in a structured
way* and explain why. An engine that crashes is an engine that does not deny.

**Exceptions are the back door of any permission system.** If an exception
mechanism exists — and one always ends up existing — you have to define
precisely what counts as a valid exception, and what it cannot grant no matter
what it says.

This policy answers all three.

---

## Design decisions

### 1. Data freshness is part of the decision

The policy does not trust that the assignment is up to date: it requires the
adapter to state whether the data is `FRESH`, `STALE` or `UNAVAILABLE`, and
**rejects any contradiction as invalid input**. If the declared status says
`FRESH` but the actual age of the timestamp exceeds the threshold, that is not a
business decision: it is a broken adapter, and it is treated as one.

With stale data the policy neither denies nor allows: it **escalates**. Denying
would punish the user for an infrastructure failure; allowing would mean
deciding blind. The operation is held and sent to human review.

### 2. Invalid input always produces a response, never an exception

The result is **always defined**, for any conceivable input: `null`, an array, a
number, an empty object. Dates are validated by shape, by calendar and by
representability *before* being parsed, so `time.parse_rfc3339_ns` never
receives anything that could make it abort — not even under
`--strict-builtin-errors`.

When the input does not meet the contract, the output is `DENY /
RCI_DENY_INVALID_INPUT` with an ordered list of specific errors. The caller
always knows what happened.

### 3. The decision and its justification are emitted together or not at all

`decision`, `reason_code` and `execution_allowed` live in a single `outcome`
object, built from mutually exclusive branches. They cannot fall out of sync
across rules: it is impossible for the policy to return `DENY` with
`execution_allowed: true`, because no path in the code allows it.

### 4. An exception never widens base permissions

The requested action must be in `actor.acciones_permitidas` (a list already
resolved by the corporate system) **before** units or exceptions are considered.
An exception can bypass a unit mismatch; it cannot grant an action the actor did
not have. And an exception resting on a stale source is not valid: exceptions
expire too.

### 5. The policy does not compute permissions, it checks them

The trust boundary is explicit. Rego does not query directories or recompute
roles: it receives facts already resolved by the calling system and decides on
them. What it does do is **refuse to assume** those facts are consistent with
each other.

---

## The six possible decisions

| Decision | Reason code | Executes? | When |
|---|---|---|---|
| `ALLOW` | `RCI_ALLOW_UNIT_MATCH` | Yes | Fresh data and the actor's unit matches the assigned one |
| `ALLOW_WITH_EXCEPTION` | `RCI_ALLOW_EXCEPTION_APPLIED` | Yes (and it is logged) | Unit does not match, but a valid exception with a fresh source applies |
| `DENY` | `RCI_DENY_UNIT_MISMATCH` | No | Fresh data, different unit, no valid exception |
| `DENY` | `RCI_DENY_ACTION_NOT_ALLOWED` | No | The action is not among those permitted to the actor |
| `DENY` | `RCI_DENY_SOURCE_UNAVAILABLE` | No | The assignment source is unavailable |
| `DENY` | `RCI_DENY_INVALID_INPUT` | No | Input does not meet the contract (with detailed `validation_errors`) |
| `ESCALATE` | `RCI_ESCALATE_STALE_ASSIGNMENT` | No (held) | Stale data with no exception to compensate |

---

## Layout

```
.
├── .github/workflows/ci.yml     # CI with OPA pinned by version and checksum
├── contrato.md                  # Input/output schema and trust guarantees
├── integracion_rci.py           # Python adapter (no external dependencies)
├── policy.rego                  # The policy
├── policy_test.rego             # 80 policy tests
└── test_integracion_rci.py      # 64 adapter tests
```

---

## How it is tested

Requirements: Python 3.10+ (uses `match`) and OPA on `PATH`.

```bash
python3 -m unittest -v
opa fmt --fail policy.rego policy_test.rego
opa check --strict policy.rego policy_test.rego
opa test policy.rego policy_test.rego --coverage
```

144 tests in total, with ~99% coverage over the policy. The tests cover the happy
paths, but mostly the ones that are not: impossible dates, exceptions with an
inverted window, `max_age` set to zero, contradictions between status and
timestamp, input roots that are not objects, leap seconds.

CI additionally verifies a property no unit test can: that the integration test
**against real OPA** actually ran, and was not silently skipped because the
binary could not be found.

---

## Usage

```python
from integracion_rci import Decision, evaluar, obtener_decision

resultado = evaluar(trusted_backend_input)

match obtener_decision(resultado):
    case Decision.ALLOW:
        pass  # execute
    case Decision.ALLOW_WITH_EXCEPTION:
        pass  # execute and log the applied exception
    case Decision.DENY:
        pass  # deny
    case Decision.ESCALATE:
        pass  # hold and send to human review
```

The full schema, the trust guarantees and the exact semantics of each decision
are in [`contrato.md`](contrato.md).

---

## Scope and limitations

- The policy decides on facts supplied by the caller. It does not verify that
  those facts are true, only that they are internally consistent.
- Freshness is evaluated against the timestamp and threshold provided by the
  adapter. A wrong clock produces a wrong decision.
- This is a reference implementation, not a production-hardened component.

---

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
