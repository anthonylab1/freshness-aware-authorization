"""
Minimal Python integration for the RCI-EXP-001 policy (v3.0.0).

Trust boundary
--------------
This module is only the client of a specialised PDP. It runs behind a trusted
PEP/backend that builds the input IN FULL (identity from IAM, actions already
resolved by the corporate authorization system, assignment from the records
system, exception from an authorised store, and server time). The end client
NEVER builds the input. This module does not authenticate, does not manage
identities or roles, does not query databases and does not administer exceptions.

What it does
------------
It wraps the `opa` binary (Open Policy Agent) via subprocess: serialises the
input, runs the bundled policy, validates the `result` against the contract and
against the original request, normalises the output (stripping unknown keys) and
returns it. No external dependencies.

Requirements
------------
- **Python 3.10+**.
- The `opa` binary on PATH (or injected with `opa_path=`, testing/dev only).
  Secondary verification without OPA: `regorus` is compatible.

Recommended use (exhaustive decision handling)
---------------------------------------------
    from rci_integration import evaluate, get_decision, Decision

    result = evaluate(request)
    match get_decision(result):
        case Decision.ALLOW:                 ...  # execute
        case Decision.ALLOW_WITH_EXCEPTION:  ...  # execute + log applied exception
        case Decision.DENY:                  ...  # deny
        case Decision.ESCALATE:              ...  # hold and send to review

`access_allowed()` is a boolean shortcut that CANNOT hide special decisions:
`ALLOW_WITH_EXCEPTION` and `ESCALATE` raise `DecisionRequiresExplicitHandling`.

Time range and freshness: see the contract. age<=max_age => FRESH;
age>max_age => STALE; `now` comes from the backend; a future timestamp is
invalid; no clock tolerance; `:60` seconds not accepted; accepted years
1678..2261 inclusive.
"""

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any

# Path to the policy bundled alongside the module (normal use).
_DEFAULT_POLICY = Path(__file__).with_name("policy.rego")

_QUERY = "data.rci.exp001.result"
_DEFAULT_TIMEOUT = 5.0

_EXPECTED_POLICY_VERSION = "4.0.0"
_EXPECTED_RULE = "RCI-EXP-001"

_ASSIGNMENT_STATUSES: set[str] = {"FRESH", "STALE", "UNAVAILABLE"}

# (decision, reason_code, execution_allowed) combinations accepted by the contract.
_VALID_COMBINATIONS: set[tuple[str, str, bool]] = {
    ("ALLOW", "RCI_ALLOW_UNIT_MATCH", True),
    ("ALLOW_WITH_EXCEPTION", "RCI_ALLOW_EXCEPTION_APPLIED", True),
    ("DENY", "RCI_DENY_ACTION_NOT_ALLOWED", False),
    ("DENY", "RCI_DENY_UNIT_MISMATCH", False),
    ("DENY", "RCI_DENY_SOURCE_UNAVAILABLE", False),
    ("ESCALATE", "RCI_ESCALATE_STALE_ASSIGNMENT", False),
    ("DENY", "RCI_DENY_INVALID_INPUT", False),
}

# Per-reason_code constraints (accepted status + non-empty audit echoes).
_CONSTRAINTS: dict[str, dict[str, Any]] = {
    "RCI_ALLOW_UNIT_MATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_ALLOW_EXCEPTION_APPLIED": {"estados": {"FRESH", "STALE"}, "audit_no_vacio": True},
    "RCI_DENY_ACTION_NOT_ALLOWED": {"estados": {"FRESH", "STALE", "UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_DENY_UNIT_MISMATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_DENY_SOURCE_UNAVAILABLE": {"estados": {"UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_ESCALATE_STALE_ASSIGNMENT": {"estados": {"STALE"}, "audit_no_vacio": True},
    "RCI_DENY_INVALID_INPUT": {"estados": {"FRESH", "STALE", "UNAVAILABLE", None}, "audit_no_vacio": False},
}

# Contractual keys of the result. Their presence is required and they are the
# only ones propagated to the consumer (unknown fields are stripped here).
_CONTRACT_FIELDS: tuple[str, ...] = (
    "decision",
    "reason_code",
    "execution_allowed",
    "rule",
    "actor_id",
    "record_id",
    "assignment_status",
    "applied_exception_id",
    "unused_exception_present",
    "validation_errors",
    "evaluated_at",
    "policy_version",
)


class Decision(str, Enum):
    """Contract decisions (inherits from str for 3.10 compatibility)."""

    ALLOW = "ALLOW"
    ALLOW_WITH_EXCEPTION = "ALLOW_WITH_EXCEPTION"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class OPAUnavailable(RuntimeError):
    """The `opa` binary is missing, is not a file, or is not executable."""


class EvaluationError(RuntimeError):
    """OPA returned an error, timed out, or produced an incoherent output."""


class DecisionRequiresExplicitHandling(RuntimeError):
    """The decision (ALLOW_WITH_EXCEPTION/ESCALATE) cannot be reduced to a bool."""

    def __init__(self, decision: str, reason_code: str, applied_exception_id: str | None = None):
        self.decision = decision
        self.reason_code = reason_code
        self.applied_exception_id = applied_exception_id
        super().__init__(
            f"Decision {decision} ({reason_code}) requires explicit handling; "
            "use get_decision() and handle every case."
        )


# ---------------------------------------------------------------------------
# RFC 3339 helpers (contract subset) — mirrors the policy.
# ---------------------------------------------------------------------------

_RFC3339_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})")


def _is_leap_year(anio: int) -> bool:
    return anio % 4 == 0 and (anio % 100 != 0 or anio % 400 == 0)


def _days_in_month(anio: int, mes: int) -> int:
    if mes in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if mes in (4, 6, 9, 11):
        return 30
    return 29 if _is_leap_year(anio) else 28


def _contractual_rfc3339(s: Any) -> bool:
    """True if `s` belongs to the contract RFC 3339 subset (year 1678..2261, no :60)."""
    if not isinstance(s, str) or _RFC3339_RE.fullmatch(s) is None:
        return False
    anio, mes, dia = int(s[0:4]), int(s[5:7]), int(s[8:10])
    hora, minuto, segundo = int(s[11:13]), int(s[14:16]), int(s[17:19])
    if not (1678 <= anio <= 2261):
        return False
    if not (1 <= mes <= 12) or not (1 <= dia <= _days_in_month(anio, mes)):
        return False
    if hora > 23 or minuto > 59 or segundo > 59:
        return False
    if not s.endswith("Z"):
        if int(s[-5:-3]) > 23 or int(s[-2:]) > 59:
            return False
    return True


def _is_str_or_none(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and v != ""


# ---------------------------------------------------------------------------
# Strict input serialisation and timeout validation
# ---------------------------------------------------------------------------

def _serialise_input(request: Any) -> str:
    """Serialises the input. The root must be a dict; no NaN/inf; no odd objects."""
    if not isinstance(request, dict):
        raise EvaluationError(
            f"the input root must be an object (dict), not {type(request).__name__}"
        )
    try:
        return json.dumps(request, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvaluationError(f"request no serializable a JSON: {exc}") from exc


def _validate_timeout(timeout: Any) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise EvaluationError(f"timeout must be int or float (not bool), not {type(timeout).__name__}")
    if not math.isfinite(timeout):
        raise EvaluationError("timeout must be finite (neither NaN nor infinity)")
    if timeout <= 0:
        raise EvaluationError("timeout must be strictly greater than zero")


# ---------------------------------------------------------------------------
# Safe resolution of OPA and of the policy
# ---------------------------------------------------------------------------

def _resolve_opa(opa_path: str | Path | None) -> str:
    """Resuelve OPA una sola vez a una path absoluta comprobada (archivo ejecutable)."""
    if opa_path is not None:
        candidate: str | None = str(opa_path)
    else:
        candidate = shutil.which("opa")
    if candidate is None:
        raise OPAUnavailable(
            "The 'opa' binary was not found on PATH. Install it or pass it with opa_path=."
        )
    path = Path(candidate).resolve()
    if not path.is_file():
        raise OPAUnavailable(f"La path de OPA no es un archivo: {path}")
    if not os.access(path, os.X_OK):
        raise OPAUnavailable(f"The OPA binary is not executable: {path}")
    return str(path)


def _resolve_policy(policy_path: str | Path | None, allow_custom_policy: bool) -> Path:
    if policy_path is None:
        path = _DEFAULT_POLICY
    else:
        if not allow_custom_policy:
            raise EvaluationError(
                "custom policy not allowed: use allow_custom_policy=True "
                "(testing or development only). Normal use runs the bundled policy."
            )
        path = Path(policy_path)
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"The policy is not a regular file: {path}")
    return path


def policy_sha256(policy_path: str | Path | None = None) -> str:
    """Hex SHA-256 of the evaluated policy (audit/diagnostics, not full integrity)."""
    path = Path(policy_path).resolve() if policy_path else _DEFAULT_POLICY
    if not path.is_file():
        raise FileNotFoundError(f"The policy is not a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# OPA execution
# ---------------------------------------------------------------------------

def _run_opa(payload: str, policy_path: Path, timeout: float, opa_bin: str) -> Any:
    """Ejecuta `opa eval` con la path absoluta `opa_bin` (sin shell) y devuelve el value crudo."""
    cmd = [
        opa_bin, "eval",
        "--format", "json",
        "--data", str(policy_path),
        "--stdin-input",
        _QUERY,
    ]
    try:
        proc = subprocess.run(
            cmd, input=payload, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise EvaluationError(f"OPA exceeded the {timeout} s timeout") from exc
    except OSError as exc:  # PermissionError, FileNotFoundError, etc.
        raise EvaluationError(f"Could not run OPA: {exc}") from exc

    if proc.returncode != 0:
        raise EvaluationError(proc.stderr.strip() or proc.stdout.strip() or "OPA failed")
    try:
        data = json.loads(proc.stdout)
        return data["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise EvaluationError(f"Empty or malformed OPA output: {exc}\n{proc.stdout!r}") from exc


# ---------------------------------------------------------------------------
# Result validation (internal consistency + binding to the request)
# ---------------------------------------------------------------------------

def _path_value(d: Any, path: tuple[str, ...]) -> Any:
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _sanitise_str(v: Any) -> Any:
    return v if isinstance(v, str) else None


def _sanitise_status(v: Any) -> Any:
    return v if isinstance(v, str) and v in _ASSIGNMENT_STATUSES else None


def _validate_result(result: Any, request: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validates the `result` against the contract (internal consistency). If
    `request` is supplied, it also checks that the audit echoes match the request.
    Raises EvaluationError for any malformed output (never TypeError/KeyError).
    """
    if not isinstance(result, dict):
        raise EvaluationError(f"result is not a JSON object: {result!r}")

    missing = [c for c in _CONTRACT_FIELDS if c not in result]
    if missing:
        raise EvaluationError(f"missing required fields: {missing}")

    decision = result["decision"]
    reason_code = result["reason_code"]
    execution_allowed = result["execution_allowed"]

    if not isinstance(decision, str):
        raise EvaluationError(f"decision must be str, not {type(decision).__name__}")
    if not isinstance(reason_code, str):
        raise EvaluationError(f"reason_code must be str, not {type(reason_code).__name__}")
    if not isinstance(execution_allowed, bool):
        raise EvaluationError(
            f"execution_allowed must be a real boolean, not {type(execution_allowed).__name__}"
        )

    if (decision, reason_code, execution_allowed) not in _VALID_COMBINATIONS:
        raise EvaluationError(
            f"invalid combination: {(decision, reason_code, execution_allowed)!r}"
        )

    if result["policy_version"] != _EXPECTED_POLICY_VERSION:
        raise EvaluationError(
            f"policy_version must be {_EXPECTED_POLICY_VERSION!r}, not {result['policy_version']!r}"
        )
    if result["rule"] != _EXPECTED_RULE:
        raise EvaluationError(f"rule must be {_EXPECTED_RULE!r}, not {result['rule']!r}")

    if not _is_str_or_none(result["actor_id"]):
        raise EvaluationError(f"actor_id must be str or None, not {result['actor_id']!r}")
    if not _is_str_or_none(result["record_id"]):
        raise EvaluationError(f"record_id must be str or None, not {result['record_id']!r}")
    if not _is_str_or_none(result["evaluated_at"]):
        raise EvaluationError(f"evaluated_at must be str or None, not {result['evaluated_at']!r}")

    assignment_status = result["assignment_status"]
    if not _is_str_or_none(assignment_status):
        raise EvaluationError(f"assignment_status must be str or None, not {type(assignment_status).__name__}")
    if not (assignment_status is None or assignment_status in _ASSIGNMENT_STATUSES):
        raise EvaluationError(f"invalid assignment_status: {assignment_status!r}")

    exc_id = result["applied_exception_id"]
    if not (exc_id is None or _non_empty_str(exc_id)):
        raise EvaluationError(f"applied_exception_id must be a non-empty str or None, not {exc_id!r}")

    if not isinstance(result["unused_exception_present"], bool):
        raise EvaluationError("unused_exception_present must be a real boolean")

    validation_errors = result["validation_errors"]
    if not isinstance(validation_errors, list):
        raise EvaluationError("validation_errors must be a list")
    if not all(isinstance(e, str) for e in validation_errors):
        raise EvaluationError("validation_errors must contain only strings")
    if validation_errors != sorted(validation_errors):
        raise EvaluationError("validation_errors must be lexicographically sorted")

    # reason_code <-> validation_errors consistency.
    if reason_code == "RCI_DENY_INVALID_INPUT":
        if len(validation_errors) == 0:
            raise EvaluationError("RCI_DENY_INVALID_INPUT without validation_errors")
    elif len(validation_errors) != 0:
        raise EvaluationError(f"{reason_code} should not carry validation_errors: {validation_errors!r}")

    # Exception invariants.
    if decision == "ALLOW_WITH_EXCEPTION":
        if not _non_empty_str(exc_id):
            raise EvaluationError("ALLOW_WITH_EXCEPTION requires a non-empty applied_exception_id")
    elif exc_id is not None:
        raise EvaluationError(f"{decision} must not carry applied_exception_id: {exc_id!r}")

    if result["unused_exception_present"] is True and not (
        decision == "ALLOW" and reason_code == "RCI_ALLOW_UNIT_MATCH"
    ):
        raise EvaluationError(
            "unused_exception_present can only be True with ALLOW + RCI_ALLOW_UNIT_MATCH"
        )

    # Per-combination consistency: status and non-empty audit echoes per reason_code.
    constraint = _CONSTRAINTS[reason_code]
    if assignment_status not in constraint["estados"]:
        allowed = sorted(str(e) for e in constraint["estados"])
        raise EvaluationError(f"{reason_code} requires assignment_status in {allowed}, not {assignment_status!r}")
    if constraint["audit_no_vacio"]:
        for field in ("actor_id", "record_id", "evaluated_at"):
            if not _non_empty_str(result[field]):
                raise EvaluationError(f"{reason_code} requires {field} to be a non-empty string, not {result[field]!r}")
        # evaluated_at of a business output must be contract RFC 3339.
        if not _contractual_rfc3339(result["evaluated_at"]):
            raise EvaluationError(f"evaluated_at is not contract RFC 3339: {result['evaluated_at']!r}")

    # result <-> original request binding.
    if request is not None:
        _verify_echoes(result, request, reason_code, decision)

    return result


def _verify_echoes(result: dict[str, Any], request: dict[str, Any], reason_code: str, decision: str) -> None:
    """Checks that the audit echoes match the original input."""
    if reason_code == "RCI_DENY_INVALID_INPUT":
        expected = {
            "actor_id": _sanitise_str(_path_value(request, ("actor", "id"))),
            "record_id": _sanitise_str(_path_value(request, ("resource", "record_id"))),
            "assignment_status": _sanitise_status(_path_value(request, ("resource", "assignment_status"))),
            "evaluated_at": _sanitise_str(_path_value(request, ("now",))),
        }
    else:
        expected = {
            "actor_id": _path_value(request, ("actor", "id")),
            "record_id": _path_value(request, ("resource", "record_id")),
            "assignment_status": _path_value(request, ("resource", "assignment_status")),
            "evaluated_at": _path_value(request, ("now",)),
        }
    for field, value in expected.items():
        if result[field] != value:
            raise EvaluationError(
                f"echo {field}={result[field]!r} does not match the request ({value!r})"
            )

    if decision == "ALLOW_WITH_EXCEPTION":
        expected_id = _path_value(request, ("exception", "id"))
        if result["applied_exception_id"] != expected_id:
            raise EvaluationError(
                f"applied_exception_id={result['applied_exception_id']!r} does not match "
                f"the exception in the request ({expected_id!r})"
            )
    elif result["applied_exception_id"] is not None:
        raise EvaluationError("applied_exception_id must be None except in ALLOW_WITH_EXCEPTION")


def _normalise(result: dict[str, Any]) -> dict[str, Any]:
    """Returns only the contractual keys; unknown fields are stripped."""
    return {k: result[k] for k in _CONTRACT_FIELDS}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    request: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    allow_custom_policy: bool = False,
    timeout: float = _DEFAULT_TIMEOUT,
    opa_path: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluates `request` against the policy and returns the validated, normalised `result`.

    Runs the bundled policy unless `policy_path` is supplied with
    `allow_custom_policy=True` (testing/development only). `opa_path`
    allows injecting the OPA binary in tests. Raises FileNotFoundError,
    OPAUnavailable or EvaluationError as appropriate.
    """
    _validate_timeout(timeout)
    policy = _resolve_policy(policy_path, allow_custom_policy)
    payload = _serialise_input(request)
    opa_bin = _resolve_opa(opa_path)
    result = _run_opa(payload, policy, timeout, opa_bin)
    validated = _validate_result(result, request)
    return _normalise(validated)


def get_decision(result: dict[str, Any]) -> Decision:
    """Validates the result and returns its Decision (type safe)."""
    validated = _validate_result(result)
    return Decision(validated["decision"])


def access_allowed(result: dict[str, Any]) -> bool:
    """True only for ALLOW; False for any DENY.

    ALLOW_WITH_EXCEPTION and ESCALATE CANNOT be reduced to a bool: they raise
    DecisionRequiresExplicitHandling to force explicit handling.
    """
    validated = _validate_result(result)
    decision = Decision(validated["decision"])
    if decision is Decision.ALLOW:
        return True
    if decision is Decision.DENY:
        return False
    raise DecisionRequiresExplicitHandling(
        decision=validated["decision"],
        reason_code=validated["reason_code"],
        applied_exception_id=validated["applied_exception_id"],
    )


def build_audit_record(
    request: dict[str, Any],
    result: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    opa_version: str | None = None,
) -> dict[str, Any]:
    """Builds (without persisting) a normalised audit record. A pure function.

    Revalidates the result against the contract and the request, to avoid building
    audit records from an incomplete or out-of-context response.
    """
    validated = _validate_result(result, request)
    return {
        "actor_id": validated["actor_id"],
        "actor_unit": _path_value(request, ("actor", "unit")),
        "record_id": validated["record_id"],
        "action": _path_value(request, ("action",)),
        "assigned_unit": _path_value(request, ("resource", "assigned_unit")),
        "assignment_status": validated["assignment_status"],
        "decision": validated["decision"],
        "reason_code": validated["reason_code"],
        "execution_allowed": validated["execution_allowed"],
        "applied_exception_id": validated["applied_exception_id"],
        "approved_by": _path_value(request, ("exception", "approved_by")),
        "evaluated_at": validated["evaluated_at"],
        "policy_version": validated["policy_version"],
        "policy_sha256": policy_sha256(policy_path),
        "opa_version": opa_version,
    }


if __name__ == "__main__":
    example = {
        "actor": {"id": "u-001", "unit": "UNIDAD_A", "allowed_actions": ["leer", "modificar"]},
        "action": "leer",
        "resource": {
            "record_id": "exp-123",
            "assigned_unit": "UNIDAD_A",
            "assignment_status": "FRESH",
            "assignment_timestamp": "2026-06-28T10:00:00Z",
            "assignment_max_age_seconds": 3600,
        },
        "exception": None,
        "now": "2026-06-28T10:15:00Z",
    }
    try:
        r = evaluate(example)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        match get_decision(r):
            case Decision.ALLOW:
                print("-> execute")
            case Decision.ALLOW_WITH_EXCEPTION:
                print("-> execute and log the exception")
            case Decision.DENY:
                print("-> deny")
            case Decision.ESCALATE:
                print("-> hold / review")
    except (OPAUnavailable, EvaluationError, FileNotFoundError) as e:
        print("[WARNING]", type(e).__name__, "-", e)
