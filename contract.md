# Policy contract — RCI-EXP-001

> **Policy version: 4.0.0.** Changes from previous versions are at the end, under **Changelog**.
>
> **Specialised PDP.** This project decides record access based on an **already resolved** action authorization, unit match, assignment freshness and approved exceptions. It runs **behind a trusted PEP/backend** that builds the entire input (identity from IAM, already resolved permissions, assignment from the records system, exception from an authorised store, and server time). **The end client never builds the input.** The policy does not authenticate, does not manage identities or roles, does not compute permissions, does not query databases and does not administer exceptions: it only checks consistency and applicability over trusted data.

## INPUT (what the enforcement point sends to OPA)

The **input root must be a JSON object**; `null`, a string, an array or a number is rejected as `RCI_DENY_INVALID_INPUT`.

```json
{
  "actor": {
    "id": "u-001",
    "unit": "UNIDAD_A",
    "allowed_actions": ["leer", "modificar"]
  },
  "action": "leer",
  "resource": {
    "record_id": "exp-123",
    "assigned_unit": "UNIDAD_A",
    "assignment_status": "FRESH",
    "assignment_timestamp": "2026-06-28T10:00:00Z",
    "assignment_max_age_seconds": 3600
  },
  "exception": {
    "id": "exc-777",
    "actor_id": "u-001",
    "record_id": "exp-123",
    "authorised_actions": ["leer"],
    "valid_from": "2026-06-28T00:00:00Z",
    "valid_until": "2026-06-29T00:00:00Z",
    "source_status": "FRESH",
    "source_timestamp": "2026-06-28T10:00:00Z",
    "source_max_age_seconds": 3600,
    "approved_by": "responsable-x"
  },
  "now": "2026-06-28T10:15:00Z"
}
```

(`exception` is `null` when there is no active exception; the example shows it populated in order to document its fields.)

Fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `actor.id` | non-empty string | yes | unique identifier of the actor |
| `actor.unit` | non-empty string | yes | organisational unit of the actor, per IAM |
| `actor.allowed_actions` | non-empty array of strings | yes | actions already authorised by the corporate system (trusted data from the PEP). The policy does **not** compute roles or permissions: it only checks membership |
| `action` | non-empty string | yes | requested action; it **must be in `actor.allowed_actions`** to be grantable. If an exception is used, it must also be in `exception.authorised_actions` |
| `resource.record_id` | non-empty string | yes | record identifier |
| `resource.assigned_unit` | non-empty string | yes (if `assignment_status` is `FRESH`/`STALE`) | unit the record is assigned to |
| `resource.assignment_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | yes | freshness state of the data, computed by the adapter before reaching here |
| `resource.assignment_timestamp` | RFC 3339 string | yes (if `FRESH`/`STALE`) | when the assignment data was produced; parsed with `time.parse_rfc3339_ns` |
| `resource.assignment_max_age_seconds` | number ≥ 0 | yes | threshold used by the adapter to decide FRESH vs STALE. **Rego uses it to detect contradictions** (see *Design note*), not to recompute the state |
| `exception` | object or `null` | yes | **the key must always be present**; use `null` when there is no active exception (a missing key makes the input invalid) |
| `exception.id` | non-empty string | if `exception != null` | unique identifier of the exception; echoed in the output as `applied_exception_id` when applied |
| `exception.actor_id` | non-empty string | if `exception != null` | who the exception benefits |
| `exception.record_id` | non-empty string | if `exception != null` | which record it covers |
| `exception.authorised_actions` | array of strings | if `exception != null` | which actions it covers; **non-empty strings only**. `action` must be included |
| `exception.valid_from` | RFC 3339 string | if `exception != null` | start of the validity window; parsed with `time.parse_rfc3339_ns` |
| `exception.valid_until` | RFC 3339 string | if `exception != null` | end of the validity window; `valid_from <= valid_until` is enforced |
| `exception.source_status` | enum: `FRESH`, `STALE`, `UNAVAILABLE` | if `exception != null` | freshness of the exception record itself, independent of the assignment. **An exception only grants access if its `source_status == "FRESH"`** |
| `exception.source_timestamp` | RFC 3339 string | if `source_status` is `FRESH`/`STALE` | when the exception record was read; Rego checks `source_status` against this age |
| `exception.source_max_age_seconds` | number ≥ 0 | if `source_status` is `FRESH`/`STALE` | freshness threshold of the exception source |
| `exception.approved_by` | non-empty string | if `exception != null` | traceability of who approved it |
| `now` | RFC 3339 string (year 1678–2261 inclusive) | yes | evaluation instant, injected by the enforcement point; parsed with `time.parse_rfc3339_ns` |

**Design note (responsibilities and consistency):**

- **Computing the state (`FRESH`/`STALE`/`UNAVAILABLE`) lives in the adapter, outside Rego.** The policy decides *what to do* given a state, not *how to compute* the state. The assignment and the exception are evaluated **independently**: they are two distinct sources that can fall out of sync.
- **Exception freshness: modelled, not assumed.** In 2.0.0, `exception.source_status` was accepted without cross-checking. Since 2.1.0 the exception carries its own `source_timestamp` and `source_max_age_seconds`, and Rego validates that `source_status` does not contradict that age (same criterion as the assignment). Modelling the freshness of the exception source was preferred over declaring it inside the trust base, so that an exception declared `FRESH` over an expired record is rejected as invalid input instead of granting access.
- **Rego does NOT recompute freshness, but it DOES detect contradictions.** For this prototype it was an explicit choice that Rego cross-check the declared `assignment_status` against the computed age `now − assignment_timestamp` versus `assignment_max_age_seconds`. Convention: `age ≤ max_age ⇒ FRESH`; `age > max_age ⇒ STALE`. If the declared state contradicts that relation (for example `status = FRESH` but `age > max_age`), the input is considered **invalid** and `RCI_DENY_INVALID_INPUT` is returned. Rego does not overwrite the adapter's state: it rejects it when incoherent.
- **Temporal comparison by instant, not by string.** All instants are converted to nanoseconds with `time.parse_rfc3339_ns` before being compared. This makes the comparison correct even when `now` and the exception window arrive with **different time offsets** (for example `Z` vs `+02:00`), which a lexical string comparison would get wrong.

**Temporal rules (normative summary):**

- Comparison uses the **actual instant with nanosecond precision**; never lexical comparison.
- `now` **comes from the backend/server**; the client does not supply it.
- A **future** `timestamp` (`> now`) is **invalid** (`RCI_DENY_INVALID_INPUT`).
- There is **no implicit or configurable clock tolerance** in this version.
- Convention: `age ≤ max_age ⇒ FRESH`; `age > max_age ⇒ STALE`.
- With **`max_age_seconds = 0`**, only an age **exactly equal to zero** (`now == timestamp`) counts as `FRESH`; any positive age declared `FRESH` is incoherent → invalid.
- **Leap seconds `:60`** are **not** accepted by this contract, even though other readings of RFC 3339 may accept them.
- **Year range actually accepted by the implementation: `1678..2261` inclusive** (limit of `time.parse_rfc3339_ns` as `int64` nanoseconds). Outside it → invalid.
- **Dates validated by calendar before parsing.** The RFC 3339 shape is checked with a regex and, in addition, the real calendar is validated (month range, day according to month and leap year, hour, minute, second and offset). Only an instant that passes all of this reaches `time.parse_rfc3339_ns`. This way a date with a valid shape but an impossible value (for example `2026-02-31`) is rejected as invalid input and the policy **does not abort, not even under `--strict-builtin-errors`**.
- **Representability, not just validity.** A date can have a correct shape and calendar and still not be representable by OPA as `int64` nanoseconds (the useful range of `time.parse_rfc3339_ns` covers roughly that span). That is why the year is limited to **`1678..2261` inclusive** **before** parsing, and the parse is additionally required to **actually return a number** before it is used. Out-of-range dates (for example years `0000` or `9999`) → `RCI_DENY_INVALID_INPUT`, with `resultado` always defined.

## OUTPUT (what OPA returns)

The policy **always** returns a structured, complete `resultado` object, even for invalid or incomplete input. `decision`, `reason_code` and `execution_allowed` are emitted **together, from a single `outcome` object**, so they cannot fall out of sync with each other.

```json
{
  "decision": "ALLOW",
  "reason_code": "RCI_ALLOW_UNIT_MATCH",
  "execution_allowed": true,
  "rule": "RCI-EXP-001",
  "actor_id": "u-001",
  "record_id": "exp-123",
  "assignment_status": "FRESH",
  "applied_exception_id": null,
  "unused_exception_present": false,
  "validation_errors": [],
  "evaluated_at": "2026-06-28T10:15:00Z",
  "policy_version": "4.0.0"
}
```

| Field | Type | Notes |
|---|---|---|
| `decision` | enum: `ALLOW`, `ALLOW_WITH_EXCEPTION`, `ESCALATE`, `DENY` | the final decision |
| `reason_code` | string (closed, stable enum) | fixed code: `RCI_DENY_INVALID_INPUT`, `RCI_DENY_ACTION_NOT_ALLOWED`, `RCI_DENY_SOURCE_UNAVAILABLE`, `RCI_ALLOW_UNIT_MATCH`, `RCI_ALLOW_EXCEPTION_APPLIED`, `RCI_DENY_UNIT_MISMATCH`, `RCI_ESCALATE_STALE_ASSIGNMENT` |
| `execution_allowed` | boolean | `true` only for `ALLOW` and `ALLOW_WITH_EXCEPTION`; `false` for `DENY`, `ESCALATE` and invalid input |
| `rule` | string | fixed identifier of the evaluated rule |
| `actor_id` / `record_id` | string \| null | audit echo **sanitised by type**: string if the input carries it as a string, `null` otherwise |
| `assignment_status` | string \| null | the freshness state used; one of `FRESH`/`STALE`/`UNAVAILABLE`, or `null` if absent or mistyped |
| `applied_exception_id` | string \| null | `exception.id` of the exception actually applied; only in `ALLOW_WITH_EXCEPTION`, `null` otherwise |
| `unused_exception_present` | boolean | `true` only when the decision was `ALLOW` by direct match **and** a basic applicable exception also existed for that same actor/record/action. An audit signal |
| `validation_errors` | array of strings | **ordered** list of input problems; empty (`[]`) when the input is valid. Non-empty ⇔ `reason_code == "RCI_DENY_INVALID_INPUT"` |
| `evaluated_at` | string \| null | echo of `input.now` **sanitised by type**: string or `null` |
| `policy_version` | string (semver) | policy version |

### Input validation → `RCI_DENY_INVALID_INPUT`

Before the business logic, the policy validates the input. If `validation_errors` is not empty, `outcome` is:

```json
{ "decision": "DENY", "reason_code": "RCI_DENY_INVALID_INPUT", "execution_allowed": false }
```

It is marked invalid when, among others:

- Any of `actor.id`, `actor.unit`, `action`, `resource.record_id` is missing or not a string.
- `assignment_status` is absent or outside the enum.
- `assignment_max_age_seconds` is not a number **or is negative** (`< 0`).
- `now` is not valid RFC 3339.
- With `FRESH`/`STALE`: `assigned_unit` is missing, or `assignment_timestamp` is missing/not RFC 3339, **or `assignment_timestamp` is in the future (`> now`)** — future data cannot be FRESH.
- The `exception` key **does not exist** (it is required even when its value is `null`); or it is present and is neither an object nor `null`; or, being an object, some field is missing or broken (`id`, `actor_id`, `record_id`, `authorised_actions`, `valid_from`, `valid_until`, `source_status`, `approved_by`).
- With `exception.source_status` `FRESH`/`STALE`: `source_timestamp` is missing (or is not RFC 3339, or is in the future), or `source_max_age_seconds` is missing (or is negative), **or `source_status` contradicts its real age** (same criterion as the assignment).
- The input **root** is not a JSON object (it is `null`, a string, an array or a number).
- Some required string field is **empty**: `actor.id`, `actor.unit`, `action`, `resource.record_id`, `resource.assigned_unit`, or the exception's ids / `approved_by`.
- A date with valid shape and calendar **is not representable** by OPA (year outside 1678–2261, for example `0000` or `9999`), or the parse does not produce a number.
- Some date has RFC 3339 shape but is **impossible in the calendar** (month/day/hour/offset out of range, for example `2026-02-31`).
- The exception has `valid_from` **later than** `valid_until`, or `authorised_actions` contains an element that is not a string or is an empty string.
- The assignment state **contradicts** its timestamp/`max_age` (see *Design note*).

### Decision logic (declarative: mutually exclusive rules)

Rego evaluates a set of rules; for any **valid** `input`, exactly one `outcome` branch is satisfied. The conditions are mutually exclusive by construction.

Helper rules (pure functions of `input`):

- `input_valido` ⇔ `validation_errors` is empty.
- `accion_permitida` ⇔ `action ∈ actor.allowed_actions` (trusted list already resolved by the corporate system; the policy only checks membership).
- `fuente_disponible` ⇔ `resource.assignment_status != "UNAVAILABLE"`.
- `unidad_coincide` ⇔ `resource.assignment_status == "FRESH"` and `actor.unit == resource.assigned_unit`.
- `excepcion_basica_aplicable` ⇔ an `exception` exists, matches on `actor_id`, `record_id`, `action ∈ authorised_actions`, and `now` falls within the window `[valid_from, valid_until]` (nanosecond comparison, both bounds **inclusive**).
- `excepcion_valida` ⇔ `excepcion_basica_aplicable` **and** `exception.source_status == "FRESH"`. An exception is only valid if it is itself `FRESH`, whether the assignment is `FRESH` or `STALE`.
- `excepcion_aplicable_y_valida` ⇔ `resource.assignment_status ∈ {FRESH, STALE}` and `excepcion_valida`.

**The action check is evaluated BEFORE units and exceptions.** An exception can **never** grant an action absent from `actor.allowed_actions`.

`outcome` branches (mutually exclusive):

| condition | `decision` | `reason_code` | `execution_allowed` |
|---|---|---|---|
| `not input_valido` | `DENY` | `RCI_DENY_INVALID_INPUT` | `false` |
| `input_valido`, `not accion_permitida` | `DENY` | `RCI_DENY_ACTION_NOT_ALLOWED` | `false` |
| `input_valido`, `accion_permitida`, `not fuente_disponible` | `DENY` | `RCI_DENY_SOURCE_UNAVAILABLE` | `false` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `unidad_coincide` | `ALLOW` | `RCI_ALLOW_UNIT_MATCH` | `true` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `excepcion_aplicable_y_valida` | `ALLOW_WITH_EXCEPTION` | `RCI_ALLOW_EXCEPTION_APPLIED` | `true` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `not excepcion_aplicable_y_valida`, `status == FRESH` | `DENY` | `RCI_DENY_UNIT_MISMATCH` | `false` |
| `input_valido`, `accion_permitida`, `fuente_disponible`, `not unidad_coincide`, `not excepcion_aplicable_y_valida`, `status == STALE` | `ESCALATE` | `RCI_ESCALATE_STALE_ASSIGNMENT` | `false` |

### Summary table

| action allowed | `assignment_status` | unit matches | valid `FRESH` exception | → `decision` |
|---|---|---|---|---|
| (invalid/incoherent input) | — | — | — | `DENY` (`RCI_DENY_INVALID_INPUT`) |
| no | — | — | — | `DENY` (`RCI_DENY_ACTION_NOT_ALLOWED`) |
| yes | UNAVAILABLE | — | — | `DENY` (`RCI_DENY_SOURCE_UNAVAILABLE`) |
| yes | FRESH | yes | (does not change the decision) | `ALLOW` |
| yes | FRESH | no | yes | `ALLOW_WITH_EXCEPTION` |
| yes | FRESH | no | no | `DENY` (`RCI_DENY_UNIT_MISMATCH`) |
| yes | STALE | not applicable\* | yes | `ALLOW_WITH_EXCEPTION` |
| yes | STALE | not applicable\* | no | `ESCALATE` (held) |

\* With `STALE` the unit is not compared, because the assignment data itself is not trustworthy — hence a `FRESH` exception is always looked for, or the request is escalated.

### How the consumer must handle decisions

The PEP must handle the four decisions **explicitly** (not collapse them into a boolean):

- **`ALLOW`** → execute.
- **`ALLOW_WITH_EXCEPTION`** → execute, but at minimum **log the applied exception**, preserving `reason_code` and `applied_exception_id`.
- **`DENY`** (any `reason_code`) → deny.
- **`ESCALATE`** → **hold** the operation and trigger review/retention; do **not** silently turn it into an ordinary denial.

In the Python integration, `acceso_permitido()` returns `True` only for `ALLOW` and `False` for any `DENY`; `ALLOW_WITH_EXCEPTION` and `ESCALATE` raise `DecisionRequiereTratamientoExplicito` to prevent the API from hiding these cases. The audit system and the review workflow are the consumer's responsibility; this project only avoids concealing them.

---

## Python integration (client boundary)

The `integracion_rci.py` module wraps `opa eval` via subprocess and adds guarantees at the **Python boundary**:

- **Response ↔ request binding.** The result is additionally validated against the original input: `actor_id`, `record_id`, `assignment_status` and `evaluated_at` must correspond to the request; in `ALLOW_WITH_EXCEPTION`, `applied_exception_id` must be the `exception.id` that was sent; otherwise it is `null`. A response reflecting a different actor, record, state, exception or instant is not trusted. For `RCI_DENY_INVALID_INPUT`, the **sanitised** echoes are compared (valid string → echoed; wrong type/absent → `null`; state outside the enum → `null`).
- **Output normalisation.** **Unknown fields** returned by OPA **take no part in the decision and are stripped at the Python boundary**: the consumer only receives the contractual keys. They are not rejected automatically, so that compatible policy changes remain possible.
- **Strict serialisation.** The input root must be an object; it is serialised with `allow_nan=False`. `NaN`, infinities, non-serialisable objects and non-object roots are rejected in a controlled way (`ErrorDeEvaluacion`), without raw exceptions.
- **Safe OPA execution.** The binary is resolved once to a verified **absolute path** (exists, is a file, is executable) and run without a shell. `opa_path=` can be injected **for testing/development only**.
- **Bundled policy.** Normal use runs the policy shipped alongside the module. A **custom policy** (`policy_path=`) is **for testing or development only** and requires `permitir_politica_personalizada=True`; it must never come from client data. `sha256_politica()` is exposed for audit/diagnostics (it is not a complete integrity system).
- **Minimal audit.** `crear_registro_auditoria()` first revalidates the response against the contract and the original request, and then builds (without persisting) a dictionary with actor, unit, record, action, state, decision, `reason_code`, `execution_allowed`, `applied_exception_id`, `approved_by`, `evaluated_at`, version and SHA-256 of the policy. The consumer decides where to store it.
- **Performance limitation.** Each evaluation spawns an `opa eval` **subprocess**; suitable for moderate volumes, not for very high-throughput paths. An OPA Server/sidecar or bundles are **out of scope** for this version (see future recommendations).

## Migration 3.0.0 → 4.0.0

A **major** change: every schema key is renamed from Spanish to English. The
decision semantics, the freshness rules and the `RCI_*` reason codes are
**unchanged** — only the field names change.

| 3.0.0 | 4.0.0 |
|---|---|
| `actor.unidad` | `actor.unit` |
| `actor.acciones_permitidas` | `actor.allowed_actions` |
| `resource.expediente_id` | `resource.record_id` |
| `resource.unidad_asignada` | `resource.assigned_unit` |
| `resource.asignacion_status` | `resource.assignment_status` |
| `resource.asignacion_timestamp` | `resource.assignment_timestamp` |
| `resource.asignacion_max_age_seconds` | `resource.assignment_max_age_seconds` |
| `excepcion` | `exception` |
| `excepcion.expediente_id` | `exception.record_id` |
| `excepcion.acciones_autorizadas` | `exception.authorised_actions` |
| `excepcion.vigente_desde` | `exception.valid_from` |
| `excepcion.vigente_hasta` | `exception.valid_until` |
| `excepcion.fuente_status` | `exception.source_status` |
| `excepcion.fuente_timestamp` | `exception.source_timestamp` |
| `excepcion.fuente_max_age_seconds` | `exception.source_max_age_seconds` |
| `excepcion.aprobada_por` | `exception.approved_by` |
| `regla` (output) | `rule` |
| `expediente_id` (output) | `record_id` |
| `asignacion_status` (output) | `assignment_status` |
| `excepcion_id_aplicada` (output) | `applied_exception_id` |
| `excepcion_existente_no_utilizada` (output) | `unused_exception_present` |

`actor.id`, `action`, `now`, `exception.id`, `exception.actor_id`, `decision`,
`reason_code`, `execution_allowed`, `actor_id`, `validation_errors`,
`evaluated_at` and `policy_version` are unchanged. The `RCI_*` reason codes are
a closed, stable enum and are **not** renamed.

The Python module is now `rci_integration.py` (was `integracion_rci.py`) and its
public API is in English: `evaluate()`, `get_decision()`, `access_allowed()`,
`build_audit_record()`, `policy_sha256()`, `EvaluationError`, `OPAUnavailable`,
`DecisionRequiresExplicitHandling`.

## Migration 2.3.1 → 3.0.0

A **major** change (input and decisions change). To migrate:

1. **Input:** add `actor.allowed_actions` (array of non-empty strings, **required**) to every request. If it is missing or not an array → `RCI_DENY_INVALID_INPUT`.
2. **New decision:** handle `RCI_DENY_ACTION_NOT_ALLOWED` (valid input but `action ∉ allowed_actions`). Not to be confused with `RCI_DENY_INVALID_INPUT`. It is evaluated **before** units and exceptions; an exception cannot grant a disallowed action.
3. **Version:** `policy_version` becomes `"4.0.0"` in the policy, contract, integration and tests.
4. **Python consumer:** `evaluar(...)` takes **keyword-only** arguments (`policy_path=`, `permitir_politica_personalizada=`, `timeout=`, `opa_path=`) and returns the **normalised** result. `acceso_permitido()` now **raises** `DecisionRequiereTratamientoExplicito` for `ALLOW_WITH_EXCEPTION` and `ESCALATE`; use `obtener_decision()` + `match` for exhaustive handling.
5. No changes to the freshness rules, the exceptions or the adapter's responsibility.

## Changelog 4.0.0 (English schema)

1. **All schema keys renamed from Spanish to English** (see the migration table
   above). Breaking change for any consumer sending the previous format.
2. **Public Python API renamed to English**; the module is now
   `rci_integration.py`.
3. **`RCI_*` reason codes unchanged**: they remain a closed, stable enum.
4. **No change to decision semantics**, freshness rules, exception handling or
   the trust boundary.

## Changelog 3.0.0 (per-action authorization + trust boundary)

1. **`actor.allowed_actions`** (array of non-empty strings, required): list of actions **already resolved** by the corporate system (trusted data from the PEP). The policy only checks membership; it does not compute roles or permissions.
2. **New decision `RCI_DENY_ACTION_NOT_ALLOWED`**: valid input but disallowed action. Checked **before** units and exceptions; an exception cannot grant an action absent from the list.
3. **Documented trust boundary**: specialised PDP behind a trusted PEP; the end client does not build the input.
4. **Hardened Python integration**: response↔request binding, output normalisation, strict serialisation, timeout validation, safe binary execution, bundled policy + SHA-256, minimal audit, and explicit handling of `ALLOW_WITH_EXCEPTION`/`ESCALATE`.
5. **Documentation fix** of the year range to `1678..2261` inclusive (the mention of `2262` is removed).

## Changelog 2.3.1 (audit echo sanitisation)

17. **Audit echoes sanitised by type.** `actor_id`, `record_id`, `assignment_status` and `evaluated_at` reflect the input value only if it has the contractual type (string; enum for `assignment_status`); otherwise they return `null`. This avoids dragging mistyped values (for example a numeric `actor_id`) into the metadata when rejecting an invalid input. It does **not** change the decision, `reason_code` or `validation_errors`.

## Changelog 2.3.0 (hardening)

15. **Date representability.** Shape and calendar are not enough: the year is limited to the range representable as `int64` nanoseconds (~1678–2261), and `time.parse_rfc3339_ns` is required to return a number before it is used. Years such as `0000`/`9999` → `RCI_DENY_INVALID_INPUT` without aborting.
16. **Empty strings rejected** in `actor.id`, `actor.unit`, `action`, `resource.record_id`, `resource.assigned_unit`, and in `exception.id`, `exception.actor_id`, `exception.record_id`, `exception.approved_by`.

## Changelog 2.2.0 (hardening)

11. **Input root validated.** If `input` is not an object (null, string, array, number) → `RCI_DENY_INVALID_INPUT`, with `resultado` still defined.
12. **Coherent exception window.** `valid_from > valid_until` is rejected.
13. **`authorised_actions` sanitised.** It must be an array of non-empty strings.
14. **Impossible-date-proof parsing.** Calendar validation (month, day with leap years, hour, offset) before parsing; `time.parse_rfc3339_ns` only receives real dates, so the policy does not fail even under `--strict-builtin-errors`.

## Changelog 2.1.0

7. **`exception` genuinely required.** The **key** is validated to exist even when its value is `null`; if it is missing, `RCI_DENY_INVALID_INPUT` (previously a missing key was treated as `null`).
8. **New assignment validations:** `assignment_timestamp <= now` (a future timestamp cannot be FRESH) and `assignment_max_age_seconds >= 0`.
9. **Exception freshness modelled.** New `exception.source_timestamp` and `exception.source_max_age_seconds` (required if `source_status` is FRESH/STALE); Rego validates that `source_status` does not contradict the real age of the source, as it does for the assignment.
10. **Contract wording:** "the exception is not evaluated" → "the exception does not change the authorization decision".

## Changelog 2.0.0

1. **An exception must always be `FRESH` to grant access.** `excepcion_valida` requires `exception.source_status == "FRESH"` with both `FRESH` and `STALE` assignments. A `STALE`/`UNAVAILABLE` exception no longer compensates for a unit mismatch or a stale assignment.
2. **Temporal comparison by instant.** `now`, `valid_from`, `valid_until` (and `assignment_timestamp`) are parsed with `time.parse_rfc3339_ns`; string comparisons are gone. Correct in the presence of time offsets.
3. **Always-structured result + input validation.** New `reason_code` `RCI_DENY_INVALID_INPUT` and new field `validation_errors`. For absent/incomplete/mistyped input, the policy returns a complete `resultado` instead of being undefined.
4. **Unified `outcome`.** `decision`, `reason_code` and `execution_allowed` are emitted from a single object, preventing separate rules from contradicting each other.
5. **`exception.id` (input) and `applied_exception_id` (output).** Traceability of which specific exception was applied.
6. **Detection of state/timestamp/max_age contradictions.** Rego trusts the adapter for the state, but rejects as `RCI_DENY_INVALID_INPUT` those inputs where the declared state contradicts the computed age.
