"""
Integración mínima de la política RCI-EXP-001 (v3.0.0) en Python.

Frontera de confianza
---------------------
Este módulo es solo el cliente de un PDP especializado. Se ejecuta detrás de un
PEP/backend confiable que construye ÍNTEGRAMENTE el input (identidad del IAM,
acciones ya resueltas por el sistema de autorización corporativo, asignación del
sistema de expedientes, excepción de un almacén autorizado y hora del servidor).
El cliente final NUNCA construye el input. Este módulo no autentica, no gestiona
identidades ni roles, no consulta bases de datos y no administra excepciones.

Qué hace
--------
Envuelve el binario `opa` (Open Policy Agent) por subprocess: serializa el input,
ejecuta la política empaquetada, valida el `result` contra el contrato y contra
la petición original, normaliza la salida (elimina claves desconocidas) y la
entrega. Sin dependencias externas.

Requisitos
----------
- **Python 3.10+**.
- El binario `opa` en el PATH (o inyectado con `opa_path=` solo en pruebas/dev).
  Verificación secundaria sin OPA: `regorus` es compatible.

Uso recomendado (tratamiento exhaustivo de la decisión)
-------------------------------------------------------
    from integracion_rci import evaluate, get_decision, Decision

    result = evaluate(entrada)
    match get_decision(result):
        case Decision.ALLOW:                 ...  # ejecutar
        case Decision.ALLOW_WITH_EXCEPTION:  ...  # ejecutar + registrar excepción aplicada
        case Decision.DENY:                  ...  # denegar
        case Decision.ESCALATE:              ...  # retener y enviar a revisión

`access_allowed()` es un atajo booleano que NO puede ocultar decisiones
especiales: `ALLOW_WITH_EXCEPTION` y `ESCALATE` lanzan
`DecisionRequiresExplicitHandling`.

Rango temporal y frescura: ver contrato. edad<=max_age => FRESH; edad>max_age =>
STALE; `now` viene del backend; timestamp futuro es inválido; sin tolerancia de
reloj; segundos `:60` no admitidos; años aceptados 1678..2261 inclusive.
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

# Ruta a la política empaquetada junto al módulo (uso normal).
_DEFAULT_POLICY = Path(__file__).with_name("policy.rego")

_QUERY = "data.rci.exp001.result"
_DEFAULT_TIMEOUT = 5.0

_EXPECTED_POLICY_VERSION = "3.0.0"
_EXPECTED_RULE = "RCI-EXP-001"

_ASSIGNMENT_STATUSES: set[str] = {"FRESH", "STALE", "UNAVAILABLE"}

# Combinaciones (decision, reason_code, execution_allowed) admitidas por el contrato.
_VALID_COMBINATIONS: set[tuple[str, str, bool]] = {
    ("ALLOW", "RCI_ALLOW_UNIT_MATCH", True),
    ("ALLOW_WITH_EXCEPTION", "RCI_ALLOW_EXCEPTION_APPLIED", True),
    ("DENY", "RCI_DENY_ACTION_NOT_ALLOWED", False),
    ("DENY", "RCI_DENY_UNIT_MISMATCH", False),
    ("DENY", "RCI_DENY_SOURCE_UNAVAILABLE", False),
    ("ESCALATE", "RCI_ESCALATE_STALE_ASSIGNMENT", False),
    ("DENY", "RCI_DENY_INVALID_INPUT", False),
}

# Restricciones por reason_code (estado admitido + auditoría no vacía).
_CONSTRAINTS: dict[str, dict[str, Any]] = {
    "RCI_ALLOW_UNIT_MATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_ALLOW_EXCEPTION_APPLIED": {"estados": {"FRESH", "STALE"}, "audit_no_vacio": True},
    "RCI_DENY_ACTION_NOT_ALLOWED": {"estados": {"FRESH", "STALE", "UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_DENY_UNIT_MISMATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_DENY_SOURCE_UNAVAILABLE": {"estados": {"UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_ESCALATE_STALE_ASSIGNMENT": {"estados": {"STALE"}, "audit_no_vacio": True},
    "RCI_DENY_INVALID_INPUT": {"estados": {"FRESH", "STALE", "UNAVAILABLE", None}, "audit_no_vacio": False},
}

# Claves contractuales del result. Se exige su presencia y son las únicas que
# se propagan al consumidor (los campos desconocidos se eliminan en esta frontera).
_CONTRACT_FIELDS: tuple[str, ...] = (
    "decision",
    "reason_code",
    "execution_allowed",
    "regla",
    "actor_id",
    "expediente_id",
    "asignacion_status",
    "excepcion_id_aplicada",
    "excepcion_existente_no_utilizada",
    "validation_errors",
    "evaluated_at",
    "policy_version",
)


class Decision(str, Enum):
    """Decisiones del contrato (hereda de str para compatibilidad con 3.10)."""

    ALLOW = "ALLOW"
    ALLOW_WITH_EXCEPTION = "ALLOW_WITH_EXCEPTION"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class OPAUnavailable(RuntimeError):
    """El binario `opa` no está, no es un archivo o no es ejecutable."""


class EvaluationError(RuntimeError):
    """OPA devolvió un error, agotó el tiempo, o la salida es incoherente."""


class DecisionRequiresExplicitHandling(RuntimeError):
    """La decisión (ALLOW_WITH_EXCEPTION/ESCALATE) no puede reducirse a bool."""

    def __init__(self, decision: str, reason_code: str, excepcion_id_aplicada: str | None = None):
        self.decision = decision
        self.reason_code = reason_code
        self.excepcion_id_aplicada = excepcion_id_aplicada
        super().__init__(
            f"La decisión {decision} ({reason_code}) requiere tratamiento explícito; "
            "usa get_decision() y trata todos los casos."
        )


# ---------------------------------------------------------------------------
# Utilidades RFC3339 (subconjunto del contrato) — espejo de la política.
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
    """True si `s` es del subconjunto RFC3339 del contrato (año 1678..2261, sin :60)."""
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
# Serialización estricta del input y validación del timeout
# ---------------------------------------------------------------------------

def _serialise_input(entrada: Any) -> str:
    """Serializa el input. La raíz debe ser un dict; sin NaN/inf; sin objetos raros."""
    if not isinstance(entrada, dict):
        raise EvaluationError(
            f"la raíz de la entrada debe ser un objeto (dict), no {type(entrada).__name__}"
        )
    try:
        return json.dumps(entrada, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise EvaluationError(f"entrada no serializable a JSON: {exc}") from exc


def _validate_timeout(timeout: Any) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise EvaluationError(f"timeout debe ser int o float (no bool), no {type(timeout).__name__}")
    if not math.isfinite(timeout):
        raise EvaluationError("timeout debe ser finito (no NaN ni infinito)")
    if timeout <= 0:
        raise EvaluationError("timeout debe ser estrictamente mayor que cero")


# ---------------------------------------------------------------------------
# Resolución segura de OPA y de la política
# ---------------------------------------------------------------------------

def _resolve_opa(opa_path: str | Path | None) -> str:
    """Resuelve OPA una sola vez a una ruta absoluta comprobada (archivo ejecutable)."""
    if opa_path is not None:
        candidato: str | None = str(opa_path)
    else:
        candidato = shutil.which("opa")
    if candidato is None:
        raise OPAUnavailable(
            "No se encontró el binario 'opa' en el PATH. Instálalo o pásalo con opa_path=."
        )
    ruta = Path(candidato).resolve()
    if not ruta.is_file():
        raise OPAUnavailable(f"La ruta de OPA no es un archivo: {ruta}")
    if not os.access(ruta, os.X_OK):
        raise OPAUnavailable(f"El binario de OPA no es ejecutable: {ruta}")
    return str(ruta)


def _resolve_policy(policy_path: str | Path | None, allow_custom_policy: bool) -> Path:
    if policy_path is None:
        ruta = _DEFAULT_POLICY
    else:
        if not allow_custom_policy:
            raise EvaluationError(
                "política personalizada no permitida: usa allow_custom_policy=True "
                "(solo para pruebas o desarrollo). El uso normal emplea la política empaquetada."
            )
        ruta = Path(policy_path)
    ruta = ruta.resolve()
    if not ruta.is_file():
        raise FileNotFoundError(f"La política no es un archivo regular: {ruta}")
    return ruta


def policy_sha256(policy_path: str | Path | None = None) -> str:
    """SHA-256 hex de la política evaluada (auditoría/diagnóstico, no integridad completa)."""
    ruta = Path(policy_path).resolve() if policy_path else _DEFAULT_POLICY
    if not ruta.is_file():
        raise FileNotFoundError(f"La política no es un archivo regular: {ruta}")
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Ejecución de OPA
# ---------------------------------------------------------------------------

def _run_opa(payload: str, policy_path: Path, timeout: float, opa_bin: str) -> Any:
    """Ejecuta `opa eval` con la ruta absoluta `opa_bin` (sin shell) y devuelve el valor crudo."""
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
        raise EvaluationError(f"OPA excedió el timeout de {timeout} s") from exc
    except OSError as exc:  # PermissionError, FileNotFoundError, etc.
        raise EvaluationError(f"No se pudo ejecutar OPA: {exc}") from exc

    if proc.returncode != 0:
        raise EvaluationError(proc.stderr.strip() or proc.stdout.strip() or "OPA falló")
    try:
        data = json.loads(proc.stdout)
        return data["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise EvaluationError(f"Salida de OPA vacía o malformada: {exc}\n{proc.stdout!r}") from exc


# ---------------------------------------------------------------------------
# Validación del result (coherencia interna + vínculo con la petición)
# ---------------------------------------------------------------------------

def _path_value(d: Any, ruta: tuple[str, ...]) -> Any:
    cur = d
    for k in ruta:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _sanitise_str(v: Any) -> Any:
    return v if isinstance(v, str) else None


def _sanitise_status(v: Any) -> Any:
    return v if isinstance(v, str) and v in _ASSIGNMENT_STATUSES else None


def _validate_result(result: Any, entrada: dict[str, Any] | None = None) -> dict[str, Any]:
    """Valida el `result` contra el contrato (coherencia interna). Si se pasa
    `entrada`, verifica además que los ecos de auditoría corresponden a la petición.
    Lanza EvaluationError ante cualquier salida malformada (nunca TypeError/KeyError).
    """
    if not isinstance(result, dict):
        raise EvaluationError(f"result no es un objeto JSON: {result!r}")

    faltantes = [c for c in _CONTRACT_FIELDS if c not in result]
    if faltantes:
        raise EvaluationError(f"faltan campos obligatorios: {faltantes}")

    decision = result["decision"]
    reason_code = result["reason_code"]
    execution_allowed = result["execution_allowed"]

    if not isinstance(decision, str):
        raise EvaluationError(f"decision debe ser str, no {type(decision).__name__}")
    if not isinstance(reason_code, str):
        raise EvaluationError(f"reason_code debe ser str, no {type(reason_code).__name__}")
    if not isinstance(execution_allowed, bool):
        raise EvaluationError(
            f"execution_allowed debe ser booleano real, no {type(execution_allowed).__name__}"
        )

    if (decision, reason_code, execution_allowed) not in _VALID_COMBINATIONS:
        raise EvaluationError(
            f"combinación inválida: {(decision, reason_code, execution_allowed)!r}"
        )

    if result["policy_version"] != _EXPECTED_POLICY_VERSION:
        raise EvaluationError(
            f"policy_version debe ser {_EXPECTED_POLICY_VERSION!r}, no {result['policy_version']!r}"
        )
    if result["regla"] != _EXPECTED_RULE:
        raise EvaluationError(f"regla debe ser {_EXPECTED_RULE!r}, no {result['regla']!r}")

    if not _is_str_or_none(result["actor_id"]):
        raise EvaluationError(f"actor_id debe ser str o None, no {result['actor_id']!r}")
    if not _is_str_or_none(result["expediente_id"]):
        raise EvaluationError(f"expediente_id debe ser str o None, no {result['expediente_id']!r}")
    if not _is_str_or_none(result["evaluated_at"]):
        raise EvaluationError(f"evaluated_at debe ser str o None, no {result['evaluated_at']!r}")

    asignacion_status = result["asignacion_status"]
    if not _is_str_or_none(asignacion_status):
        raise EvaluationError(f"asignacion_status debe ser str o None, no {type(asignacion_status).__name__}")
    if not (asignacion_status is None or asignacion_status in _ASSIGNMENT_STATUSES):
        raise EvaluationError(f"asignacion_status inválido: {asignacion_status!r}")

    exc_id = result["excepcion_id_aplicada"]
    if not (exc_id is None or _non_empty_str(exc_id)):
        raise EvaluationError(f"excepcion_id_aplicada debe ser str no vacío o None, no {exc_id!r}")

    if not isinstance(result["excepcion_existente_no_utilizada"], bool):
        raise EvaluationError("excepcion_existente_no_utilizada debe ser booleano real")

    validation_errors = result["validation_errors"]
    if not isinstance(validation_errors, list):
        raise EvaluationError("validation_errors debe ser una lista")
    if not all(isinstance(e, str) for e in validation_errors):
        raise EvaluationError("validation_errors debe contener solo strings")
    if validation_errors != sorted(validation_errors):
        raise EvaluationError("validation_errors debe estar ordenado lexicográficamente")

    # Coherencia reason_code <-> validation_errors.
    if reason_code == "RCI_DENY_INVALID_INPUT":
        if len(validation_errors) == 0:
            raise EvaluationError("RCI_DENY_INVALID_INPUT sin validation_errors")
    elif len(validation_errors) != 0:
        raise EvaluationError(f"{reason_code} no debería traer validation_errors: {validation_errors!r}")

    # Invariantes de excepción.
    if decision == "ALLOW_WITH_EXCEPTION":
        if not _non_empty_str(exc_id):
            raise EvaluationError("ALLOW_WITH_EXCEPTION requiere excepcion_id_aplicada no vacío")
    elif exc_id is not None:
        raise EvaluationError(f"{decision} no debe traer excepcion_id_aplicada: {exc_id!r}")

    if result["excepcion_existente_no_utilizada"] is True and not (
        decision == "ALLOW" and reason_code == "RCI_ALLOW_UNIT_MATCH"
    ):
        raise EvaluationError(
            "excepcion_existente_no_utilizada solo puede ser True con ALLOW + RCI_ALLOW_UNIT_MATCH"
        )

    # Coherencia por combinación: estado y auditoría no vacía según reason_code.
    restr = _CONSTRAINTS[reason_code]
    if asignacion_status not in restr["estados"]:
        permitidos = sorted(str(e) for e in restr["estados"])
        raise EvaluationError(f"{reason_code} exige asignacion_status en {permitidos}, no {asignacion_status!r}")
    if restr["audit_no_vacio"]:
        for campo in ("actor_id", "expediente_id", "evaluated_at"):
            if not _non_empty_str(result[campo]):
                raise EvaluationError(f"{reason_code} exige {campo} como string no vacío, no {result[campo]!r}")
        # evaluated_at de una salida de negocio debe ser RFC3339 del contrato.
        if not _contractual_rfc3339(result["evaluated_at"]):
            raise EvaluationError(f"evaluated_at no es RFC3339 del contrato: {result['evaluated_at']!r}")

    # Vínculo result <-> petición original.
    if entrada is not None:
        _verify_echoes(result, entrada, reason_code, decision)

    return result


def _verify_echoes(result: dict[str, Any], entrada: dict[str, Any], reason_code: str, decision: str) -> None:
    """Comprueba que los ecos de auditoría corresponden al input original."""
    if reason_code == "RCI_DENY_INVALID_INPUT":
        esperado = {
            "actor_id": _sanitise_str(_path_value(entrada, ("actor", "id"))),
            "expediente_id": _sanitise_str(_path_value(entrada, ("resource", "expediente_id"))),
            "asignacion_status": _sanitise_status(_path_value(entrada, ("resource", "asignacion_status"))),
            "evaluated_at": _sanitise_str(_path_value(entrada, ("now",))),
        }
    else:
        esperado = {
            "actor_id": _path_value(entrada, ("actor", "id")),
            "expediente_id": _path_value(entrada, ("resource", "expediente_id")),
            "asignacion_status": _path_value(entrada, ("resource", "asignacion_status")),
            "evaluated_at": _path_value(entrada, ("now",)),
        }
    for campo, valor in esperado.items():
        if result[campo] != valor:
            raise EvaluationError(
                f"eco {campo}={result[campo]!r} no corresponde a la petición ({valor!r})"
            )

    if decision == "ALLOW_WITH_EXCEPTION":
        esperado_id = _path_value(entrada, ("excepcion", "id"))
        if result["excepcion_id_aplicada"] != esperado_id:
            raise EvaluationError(
                f"excepcion_id_aplicada={result['excepcion_id_aplicada']!r} no corresponde a "
                f"la excepción de la petición ({esperado_id!r})"
            )
    elif result["excepcion_id_aplicada"] is not None:
        raise EvaluationError("excepcion_id_aplicada debe ser None salvo en ALLOW_WITH_EXCEPTION")


def _normalise(result: dict[str, Any]) -> dict[str, Any]:
    """Devuelve solo las claves contractuales; los campos desconocidos se eliminan."""
    return {k: result[k] for k in _CONTRACT_FIELDS}


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def evaluate(
    entrada: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    allow_custom_policy: bool = False,
    timeout: float = _DEFAULT_TIMEOUT,
    opa_path: str | Path | None = None,
) -> dict[str, Any]:
    """Evalúa `entrada` contra la política y devuelve el `result` validado y normalizado.

    Usa la política empaquetada salvo que se pase `policy_path` con
    `allow_custom_policy=True` (solo pruebas/desarrollo). `opa_path`
    permite inyectar el binario de OPA en pruebas. Lanza FileNotFoundError,
    OPAUnavailable o EvaluationError según el caso.
    """
    _validate_timeout(timeout)
    policy = _resolve_policy(policy_path, allow_custom_policy)
    payload = _serialise_input(entrada)
    opa_bin = _resolve_opa(opa_path)
    result = _run_opa(payload, policy, timeout, opa_bin)
    validado = _validate_result(result, entrada)
    return _normalise(validado)


def get_decision(result: dict[str, Any]) -> Decision:
    """Valida el result y devuelve su Decision (tipo seguro)."""
    validado = _validate_result(result)
    return Decision(validado["decision"])


def access_allowed(result: dict[str, Any]) -> bool:
    """True solo para ALLOW; False para cualquier DENY.

    ALLOW_WITH_EXCEPTION y ESCALATE NO pueden reducirse a bool: lanzan
    DecisionRequiresExplicitHandling para forzar tratamiento explícito.
    """
    validado = _validate_result(result)
    decision = Decision(validado["decision"])
    if decision is Decision.ALLOW:
        return True
    if decision is Decision.DENY:
        return False
    raise DecisionRequiresExplicitHandling(
        decision=validado["decision"],
        reason_code=validado["reason_code"],
        excepcion_id_aplicada=validado["excepcion_id_aplicada"],
    )


def build_audit_record(
    entrada: dict[str, Any],
    result: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    opa_version: str | None = None,
) -> dict[str, Any]:
    """Construye (sin persistir) un registro de auditoría normalizado. Función pura.

    Revalida el result contra el contrato y la petición para evitar generar
    registros de auditoría a partir de una respuesta incompleta o descontextualizada.
    """
    validado = _validate_result(result, entrada)
    return {
        "actor_id": validado["actor_id"],
        "actor_unidad": _path_value(entrada, ("actor", "unidad")),
        "expediente_id": validado["expediente_id"],
        "action": _path_value(entrada, ("action",)),
        "unidad_asignada": _path_value(entrada, ("resource", "unidad_asignada")),
        "asignacion_status": validado["asignacion_status"],
        "decision": validado["decision"],
        "reason_code": validado["reason_code"],
        "execution_allowed": validado["execution_allowed"],
        "excepcion_id_aplicada": validado["excepcion_id_aplicada"],
        "aprobada_por": _path_value(entrada, ("excepcion", "aprobada_por")),
        "evaluated_at": validado["evaluated_at"],
        "policy_version": validado["policy_version"],
        "policy_sha256": policy_sha256(policy_path),
        "opa_version": opa_version,
    }


if __name__ == "__main__":
    ejemplo = {
        "actor": {"id": "u-001", "unidad": "UNIDAD_A", "acciones_permitidas": ["leer", "modificar"]},
        "action": "leer",
        "resource": {
            "expediente_id": "exp-123",
            "unidad_asignada": "UNIDAD_A",
            "asignacion_status": "FRESH",
            "asignacion_timestamp": "2026-06-28T10:00:00Z",
            "asignacion_max_age_seconds": 3600,
        },
        "excepcion": None,
        "now": "2026-06-28T10:15:00Z",
    }
    try:
        r = evaluate(ejemplo)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        match get_decision(r):
            case Decision.ALLOW:
                print("-> ejecutar")
            case Decision.ALLOW_WITH_EXCEPTION:
                print("-> ejecutar y registrar excepción")
            case Decision.DENY:
                print("-> denegar")
            case Decision.ESCALATE:
                print("-> retener / revisión")
    except (OPAUnavailable, EvaluationError, FileNotFoundError) as e:
        print("[AVISO]", type(e).__name__, "-", e)
