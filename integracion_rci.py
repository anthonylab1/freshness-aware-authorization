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
ejecuta la política empaquetada, valida el `resultado` contra el contrato y contra
la petición original, normaliza la salida (elimina claves desconocidas) y la
entrega. Sin dependencias externas.

Requisitos
----------
- **Python 3.10+**.
- El binario `opa` en el PATH (o inyectado con `opa_path=` solo en pruebas/dev).
  Verificación secundaria sin OPA: `regorus` es compatible.

Uso recomendado (tratamiento exhaustivo de la decisión)
-------------------------------------------------------
    from integracion_rci import evaluar, obtener_decision, Decision

    resultado = evaluar(entrada)
    match obtener_decision(resultado):
        case Decision.ALLOW:                 ...  # ejecutar
        case Decision.ALLOW_WITH_EXCEPTION:  ...  # ejecutar + registrar excepción aplicada
        case Decision.DENY:                  ...  # denegar
        case Decision.ESCALATE:              ...  # retener y enviar a revisión

`acceso_permitido()` es un atajo booleano que NO puede ocultar decisiones
especiales: `ALLOW_WITH_EXCEPTION` y `ESCALATE` lanzan
`DecisionRequiereTratamientoExplicito`.

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
_POLICY_POR_DEFECTO = Path(__file__).with_name("policy.rego")

_QUERY = "data.rci.exp001.resultado"
_TIMEOUT_POR_DEFECTO = 5.0

_POLICY_VERSION_ESPERADA = "3.0.0"
_REGLA_ESPERADA = "RCI-EXP-001"

_ESTADOS_ASIGNACION: set[str] = {"FRESH", "STALE", "UNAVAILABLE"}

# Combinaciones (decision, reason_code, execution_allowed) admitidas por el contrato.
_COMBINACIONES_VALIDAS: set[tuple[str, str, bool]] = {
    ("ALLOW", "RCI_ALLOW_UNIT_MATCH", True),
    ("ALLOW_WITH_EXCEPTION", "RCI_ALLOW_EXCEPTION_APPLIED", True),
    ("DENY", "RCI_DENY_ACTION_NOT_ALLOWED", False),
    ("DENY", "RCI_DENY_UNIT_MISMATCH", False),
    ("DENY", "RCI_DENY_SOURCE_UNAVAILABLE", False),
    ("ESCALATE", "RCI_ESCALATE_STALE_ASSIGNMENT", False),
    ("DENY", "RCI_DENY_INVALID_INPUT", False),
}

# Restricciones por reason_code (estado admitido + auditoría no vacía).
_RESTRICCIONES: dict[str, dict[str, Any]] = {
    "RCI_ALLOW_UNIT_MATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_ALLOW_EXCEPTION_APPLIED": {"estados": {"FRESH", "STALE"}, "audit_no_vacio": True},
    "RCI_DENY_ACTION_NOT_ALLOWED": {"estados": {"FRESH", "STALE", "UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_DENY_UNIT_MISMATCH": {"estados": {"FRESH"}, "audit_no_vacio": True},
    "RCI_DENY_SOURCE_UNAVAILABLE": {"estados": {"UNAVAILABLE"}, "audit_no_vacio": True},
    "RCI_ESCALATE_STALE_ASSIGNMENT": {"estados": {"STALE"}, "audit_no_vacio": True},
    "RCI_DENY_INVALID_INPUT": {"estados": {"FRESH", "STALE", "UNAVAILABLE", None}, "audit_no_vacio": False},
}

# Claves contractuales del resultado. Se exige su presencia y son las únicas que
# se propagan al consumidor (los campos desconocidos se eliminan en esta frontera).
_CAMPOS_CONTRACTUALES: tuple[str, ...] = (
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


class OPANoDisponible(RuntimeError):
    """El binario `opa` no está, no es un archivo o no es ejecutable."""


class ErrorDeEvaluacion(RuntimeError):
    """OPA devolvió un error, agotó el tiempo, o la salida es incoherente."""


class DecisionRequiereTratamientoExplicito(RuntimeError):
    """La decisión (ALLOW_WITH_EXCEPTION/ESCALATE) no puede reducirse a bool."""

    def __init__(self, decision: str, reason_code: str, excepcion_id_aplicada: str | None = None):
        self.decision = decision
        self.reason_code = reason_code
        self.excepcion_id_aplicada = excepcion_id_aplicada
        super().__init__(
            f"La decisión {decision} ({reason_code}) requiere tratamiento explícito; "
            "usa obtener_decision() y trata todos los casos."
        )


# ---------------------------------------------------------------------------
# Utilidades RFC3339 (subconjunto del contrato) — espejo de la política.
# ---------------------------------------------------------------------------

_RFC3339_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})")


def _bisiesto(anio: int) -> bool:
    return anio % 4 == 0 and (anio % 100 != 0 or anio % 400 == 0)


def _dias_mes(anio: int, mes: int) -> int:
    if mes in (1, 3, 5, 7, 8, 10, 12):
        return 31
    if mes in (4, 6, 9, 11):
        return 30
    return 29 if _bisiesto(anio) else 28


def _rfc3339_contractual(s: Any) -> bool:
    """True si `s` es del subconjunto RFC3339 del contrato (año 1678..2261, sin :60)."""
    if not isinstance(s, str) or _RFC3339_RE.fullmatch(s) is None:
        return False
    anio, mes, dia = int(s[0:4]), int(s[5:7]), int(s[8:10])
    hora, minuto, segundo = int(s[11:13]), int(s[14:16]), int(s[17:19])
    if not (1678 <= anio <= 2261):
        return False
    if not (1 <= mes <= 12) or not (1 <= dia <= _dias_mes(anio, mes)):
        return False
    if hora > 23 or minuto > 59 or segundo > 59:
        return False
    if not s.endswith("Z"):
        if int(s[-5:-3]) > 23 or int(s[-2:]) > 59:
            return False
    return True


def _es_str_o_none(v: Any) -> bool:
    return v is None or isinstance(v, str)


def _str_no_vacio(v: Any) -> bool:
    return isinstance(v, str) and v != ""


# ---------------------------------------------------------------------------
# Serialización estricta del input y validación del timeout
# ---------------------------------------------------------------------------

def _serializar_entrada(entrada: Any) -> str:
    """Serializa el input. La raíz debe ser un dict; sin NaN/inf; sin objetos raros."""
    if not isinstance(entrada, dict):
        raise ErrorDeEvaluacion(
            f"la raíz de la entrada debe ser un objeto (dict), no {type(entrada).__name__}"
        )
    try:
        return json.dumps(entrada, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ErrorDeEvaluacion(f"entrada no serializable a JSON: {exc}") from exc


def _validar_timeout(timeout: Any) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ErrorDeEvaluacion(f"timeout debe ser int o float (no bool), no {type(timeout).__name__}")
    if not math.isfinite(timeout):
        raise ErrorDeEvaluacion("timeout debe ser finito (no NaN ni infinito)")
    if timeout <= 0:
        raise ErrorDeEvaluacion("timeout debe ser estrictamente mayor que cero")


# ---------------------------------------------------------------------------
# Resolución segura de OPA y de la política
# ---------------------------------------------------------------------------

def _resolver_opa(opa_path: str | Path | None) -> str:
    """Resuelve OPA una sola vez a una ruta absoluta comprobada (archivo ejecutable)."""
    if opa_path is not None:
        candidato: str | None = str(opa_path)
    else:
        candidato = shutil.which("opa")
    if candidato is None:
        raise OPANoDisponible(
            "No se encontró el binario 'opa' en el PATH. Instálalo o pásalo con opa_path=."
        )
    ruta = Path(candidato).resolve()
    if not ruta.is_file():
        raise OPANoDisponible(f"La ruta de OPA no es un archivo: {ruta}")
    if not os.access(ruta, os.X_OK):
        raise OPANoDisponible(f"El binario de OPA no es ejecutable: {ruta}")
    return str(ruta)


def _resolver_politica(policy_path: str | Path | None, permitir_politica_personalizada: bool) -> Path:
    if policy_path is None:
        ruta = _POLICY_POR_DEFECTO
    else:
        if not permitir_politica_personalizada:
            raise ErrorDeEvaluacion(
                "política personalizada no permitida: usa permitir_politica_personalizada=True "
                "(solo para pruebas o desarrollo). El uso normal emplea la política empaquetada."
            )
        ruta = Path(policy_path)
    ruta = ruta.resolve()
    if not ruta.is_file():
        raise FileNotFoundError(f"La política no es un archivo regular: {ruta}")
    return ruta


def sha256_politica(policy_path: str | Path | None = None) -> str:
    """SHA-256 hex de la política evaluada (auditoría/diagnóstico, no integridad completa)."""
    ruta = Path(policy_path).resolve() if policy_path else _POLICY_POR_DEFECTO
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
        raise ErrorDeEvaluacion(f"OPA excedió el timeout de {timeout} s") from exc
    except OSError as exc:  # PermissionError, FileNotFoundError, etc.
        raise ErrorDeEvaluacion(f"No se pudo ejecutar OPA: {exc}") from exc

    if proc.returncode != 0:
        raise ErrorDeEvaluacion(proc.stderr.strip() or proc.stdout.strip() or "OPA falló")
    try:
        data = json.loads(proc.stdout)
        return data["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ErrorDeEvaluacion(f"Salida de OPA vacía o malformada: {exc}\n{proc.stdout!r}") from exc


# ---------------------------------------------------------------------------
# Validación del resultado (coherencia interna + vínculo con la petición)
# ---------------------------------------------------------------------------

def _valor_ruta(d: Any, ruta: tuple[str, ...]) -> Any:
    cur = d
    for k in ruta:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _san_str(v: Any) -> Any:
    return v if isinstance(v, str) else None


def _san_estado(v: Any) -> Any:
    return v if isinstance(v, str) and v in _ESTADOS_ASIGNACION else None


def _validar_resultado(resultado: Any, entrada: dict[str, Any] | None = None) -> dict[str, Any]:
    """Valida el `resultado` contra el contrato (coherencia interna). Si se pasa
    `entrada`, verifica además que los ecos de auditoría corresponden a la petición.
    Lanza ErrorDeEvaluacion ante cualquier salida malformada (nunca TypeError/KeyError).
    """
    if not isinstance(resultado, dict):
        raise ErrorDeEvaluacion(f"resultado no es un objeto JSON: {resultado!r}")

    faltantes = [c for c in _CAMPOS_CONTRACTUALES if c not in resultado]
    if faltantes:
        raise ErrorDeEvaluacion(f"faltan campos obligatorios: {faltantes}")

    decision = resultado["decision"]
    reason_code = resultado["reason_code"]
    execution_allowed = resultado["execution_allowed"]

    if not isinstance(decision, str):
        raise ErrorDeEvaluacion(f"decision debe ser str, no {type(decision).__name__}")
    if not isinstance(reason_code, str):
        raise ErrorDeEvaluacion(f"reason_code debe ser str, no {type(reason_code).__name__}")
    if not isinstance(execution_allowed, bool):
        raise ErrorDeEvaluacion(
            f"execution_allowed debe ser booleano real, no {type(execution_allowed).__name__}"
        )

    if (decision, reason_code, execution_allowed) not in _COMBINACIONES_VALIDAS:
        raise ErrorDeEvaluacion(
            f"combinación inválida: {(decision, reason_code, execution_allowed)!r}"
        )

    if resultado["policy_version"] != _POLICY_VERSION_ESPERADA:
        raise ErrorDeEvaluacion(
            f"policy_version debe ser {_POLICY_VERSION_ESPERADA!r}, no {resultado['policy_version']!r}"
        )
    if resultado["regla"] != _REGLA_ESPERADA:
        raise ErrorDeEvaluacion(f"regla debe ser {_REGLA_ESPERADA!r}, no {resultado['regla']!r}")

    if not _es_str_o_none(resultado["actor_id"]):
        raise ErrorDeEvaluacion(f"actor_id debe ser str o None, no {resultado['actor_id']!r}")
    if not _es_str_o_none(resultado["expediente_id"]):
        raise ErrorDeEvaluacion(f"expediente_id debe ser str o None, no {resultado['expediente_id']!r}")
    if not _es_str_o_none(resultado["evaluated_at"]):
        raise ErrorDeEvaluacion(f"evaluated_at debe ser str o None, no {resultado['evaluated_at']!r}")

    asignacion_status = resultado["asignacion_status"]
    if not _es_str_o_none(asignacion_status):
        raise ErrorDeEvaluacion(f"asignacion_status debe ser str o None, no {type(asignacion_status).__name__}")
    if not (asignacion_status is None or asignacion_status in _ESTADOS_ASIGNACION):
        raise ErrorDeEvaluacion(f"asignacion_status inválido: {asignacion_status!r}")

    exc_id = resultado["excepcion_id_aplicada"]
    if not (exc_id is None or _str_no_vacio(exc_id)):
        raise ErrorDeEvaluacion(f"excepcion_id_aplicada debe ser str no vacío o None, no {exc_id!r}")

    if not isinstance(resultado["excepcion_existente_no_utilizada"], bool):
        raise ErrorDeEvaluacion("excepcion_existente_no_utilizada debe ser booleano real")

    validation_errors = resultado["validation_errors"]
    if not isinstance(validation_errors, list):
        raise ErrorDeEvaluacion("validation_errors debe ser una lista")
    if not all(isinstance(e, str) for e in validation_errors):
        raise ErrorDeEvaluacion("validation_errors debe contener solo strings")
    if validation_errors != sorted(validation_errors):
        raise ErrorDeEvaluacion("validation_errors debe estar ordenado lexicográficamente")

    # Coherencia reason_code <-> validation_errors.
    if reason_code == "RCI_DENY_INVALID_INPUT":
        if len(validation_errors) == 0:
            raise ErrorDeEvaluacion("RCI_DENY_INVALID_INPUT sin validation_errors")
    elif len(validation_errors) != 0:
        raise ErrorDeEvaluacion(f"{reason_code} no debería traer validation_errors: {validation_errors!r}")

    # Invariantes de excepción.
    if decision == "ALLOW_WITH_EXCEPTION":
        if not _str_no_vacio(exc_id):
            raise ErrorDeEvaluacion("ALLOW_WITH_EXCEPTION requiere excepcion_id_aplicada no vacío")
    elif exc_id is not None:
        raise ErrorDeEvaluacion(f"{decision} no debe traer excepcion_id_aplicada: {exc_id!r}")

    if resultado["excepcion_existente_no_utilizada"] is True and not (
        decision == "ALLOW" and reason_code == "RCI_ALLOW_UNIT_MATCH"
    ):
        raise ErrorDeEvaluacion(
            "excepcion_existente_no_utilizada solo puede ser True con ALLOW + RCI_ALLOW_UNIT_MATCH"
        )

    # Coherencia por combinación: estado y auditoría no vacía según reason_code.
    restr = _RESTRICCIONES[reason_code]
    if asignacion_status not in restr["estados"]:
        permitidos = sorted(str(e) for e in restr["estados"])
        raise ErrorDeEvaluacion(f"{reason_code} exige asignacion_status en {permitidos}, no {asignacion_status!r}")
    if restr["audit_no_vacio"]:
        for campo in ("actor_id", "expediente_id", "evaluated_at"):
            if not _str_no_vacio(resultado[campo]):
                raise ErrorDeEvaluacion(f"{reason_code} exige {campo} como string no vacío, no {resultado[campo]!r}")
        # evaluated_at de una salida de negocio debe ser RFC3339 del contrato.
        if not _rfc3339_contractual(resultado["evaluated_at"]):
            raise ErrorDeEvaluacion(f"evaluated_at no es RFC3339 del contrato: {resultado['evaluated_at']!r}")

    # Vínculo resultado <-> petición original.
    if entrada is not None:
        _verificar_ecos(resultado, entrada, reason_code, decision)

    return resultado


def _verificar_ecos(resultado: dict[str, Any], entrada: dict[str, Any], reason_code: str, decision: str) -> None:
    """Comprueba que los ecos de auditoría corresponden al input original."""
    if reason_code == "RCI_DENY_INVALID_INPUT":
        esperado = {
            "actor_id": _san_str(_valor_ruta(entrada, ("actor", "id"))),
            "expediente_id": _san_str(_valor_ruta(entrada, ("resource", "expediente_id"))),
            "asignacion_status": _san_estado(_valor_ruta(entrada, ("resource", "asignacion_status"))),
            "evaluated_at": _san_str(_valor_ruta(entrada, ("now",))),
        }
    else:
        esperado = {
            "actor_id": _valor_ruta(entrada, ("actor", "id")),
            "expediente_id": _valor_ruta(entrada, ("resource", "expediente_id")),
            "asignacion_status": _valor_ruta(entrada, ("resource", "asignacion_status")),
            "evaluated_at": _valor_ruta(entrada, ("now",)),
        }
    for campo, valor in esperado.items():
        if resultado[campo] != valor:
            raise ErrorDeEvaluacion(
                f"eco {campo}={resultado[campo]!r} no corresponde a la petición ({valor!r})"
            )

    if decision == "ALLOW_WITH_EXCEPTION":
        esperado_id = _valor_ruta(entrada, ("excepcion", "id"))
        if resultado["excepcion_id_aplicada"] != esperado_id:
            raise ErrorDeEvaluacion(
                f"excepcion_id_aplicada={resultado['excepcion_id_aplicada']!r} no corresponde a "
                f"la excepción de la petición ({esperado_id!r})"
            )
    elif resultado["excepcion_id_aplicada"] is not None:
        raise ErrorDeEvaluacion("excepcion_id_aplicada debe ser None salvo en ALLOW_WITH_EXCEPTION")


def _normalizar(resultado: dict[str, Any]) -> dict[str, Any]:
    """Devuelve solo las claves contractuales; los campos desconocidos se eliminan."""
    return {k: resultado[k] for k in _CAMPOS_CONTRACTUALES}


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def evaluar(
    entrada: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    permitir_politica_personalizada: bool = False,
    timeout: float = _TIMEOUT_POR_DEFECTO,
    opa_path: str | Path | None = None,
) -> dict[str, Any]:
    """Evalúa `entrada` contra la política y devuelve el `resultado` validado y normalizado.

    Usa la política empaquetada salvo que se pase `policy_path` con
    `permitir_politica_personalizada=True` (solo pruebas/desarrollo). `opa_path`
    permite inyectar el binario de OPA en pruebas. Lanza FileNotFoundError,
    OPANoDisponible o ErrorDeEvaluacion según el caso.
    """
    _validar_timeout(timeout)
    policy = _resolver_politica(policy_path, permitir_politica_personalizada)
    payload = _serializar_entrada(entrada)
    opa_bin = _resolver_opa(opa_path)
    resultado = _run_opa(payload, policy, timeout, opa_bin)
    validado = _validar_resultado(resultado, entrada)
    return _normalizar(validado)


def obtener_decision(resultado: dict[str, Any]) -> Decision:
    """Valida el resultado y devuelve su Decision (tipo seguro)."""
    validado = _validar_resultado(resultado)
    return Decision(validado["decision"])


def acceso_permitido(resultado: dict[str, Any]) -> bool:
    """True solo para ALLOW; False para cualquier DENY.

    ALLOW_WITH_EXCEPTION y ESCALATE NO pueden reducirse a bool: lanzan
    DecisionRequiereTratamientoExplicito para forzar tratamiento explícito.
    """
    validado = _validar_resultado(resultado)
    decision = Decision(validado["decision"])
    if decision is Decision.ALLOW:
        return True
    if decision is Decision.DENY:
        return False
    raise DecisionRequiereTratamientoExplicito(
        decision=validado["decision"],
        reason_code=validado["reason_code"],
        excepcion_id_aplicada=validado["excepcion_id_aplicada"],
    )


def crear_registro_auditoria(
    entrada: dict[str, Any],
    resultado: dict[str, Any],
    *,
    policy_path: str | Path | None = None,
    opa_version: str | None = None,
) -> dict[str, Any]:
    """Construye (sin persistir) un registro de auditoría normalizado. Función pura.

    Revalida el resultado contra el contrato y la petición para evitar generar
    registros de auditoría a partir de una respuesta incompleta o descontextualizada.
    """
    validado = _validar_resultado(resultado, entrada)
    return {
        "actor_id": validado["actor_id"],
        "actor_unidad": _valor_ruta(entrada, ("actor", "unidad")),
        "expediente_id": validado["expediente_id"],
        "action": _valor_ruta(entrada, ("action",)),
        "unidad_asignada": _valor_ruta(entrada, ("resource", "unidad_asignada")),
        "asignacion_status": validado["asignacion_status"],
        "decision": validado["decision"],
        "reason_code": validado["reason_code"],
        "execution_allowed": validado["execution_allowed"],
        "excepcion_id_aplicada": validado["excepcion_id_aplicada"],
        "aprobada_por": _valor_ruta(entrada, ("excepcion", "aprobada_por")),
        "evaluated_at": validado["evaluated_at"],
        "policy_version": validado["policy_version"],
        "policy_sha256": sha256_politica(policy_path),
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
        r = evaluar(ejemplo)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        match obtener_decision(r):
            case Decision.ALLOW:
                print("-> ejecutar")
            case Decision.ALLOW_WITH_EXCEPTION:
                print("-> ejecutar y registrar excepción")
            case Decision.DENY:
                print("-> denegar")
            case Decision.ESCALATE:
                print("-> retener / revisión")
    except (OPANoDisponible, ErrorDeEvaluacion, FileNotFoundError) as e:
        print("[AVISO]", type(e).__name__, "-", e)
