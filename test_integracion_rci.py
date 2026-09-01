"""Tests unitarios de integracion_rci (v3.0.0). No requieren `opa` real (se mockea)."""

import json
import math
import os
import shutil
import stat
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import integracion_rci as ri
from integracion_rci import (
    Decision,
    DecisionRequiresExplicitHandling,
    EvaluationError,
    OPAUnavailable,
    access_allowed,
    build_audit_record,
    evaluate,
    get_decision,
    policy_sha256,
)


def resultado_valido(**over):
    """Resultado contractual completo y coherente por defecto (ALLOW / FRESH)."""
    base = {
        "decision": "ALLOW",
        "reason_code": "RCI_ALLOW_UNIT_MATCH",
        "execution_allowed": True,
        "regla": "RCI-EXP-001",
        "actor_id": "u-001",
        "expediente_id": "exp-123",
        "asignacion_status": "FRESH",
        "excepcion_id_aplicada": None,
        "excepcion_existente_no_utilizada": False,
        "validation_errors": [],
        "evaluated_at": "2026-06-28T10:15:00Z",
        "policy_version": "3.0.0",
    }
    base.update(over)
    return base


def entrada_valida(**over):
    base = {
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
    base.update(over)
    return base


def _proc(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def _opa_json(value):
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


# ===========================================================================
# _validate_result: coherencia interna (sin entrada)
# ===========================================================================
class TestValidarResultado(unittest.TestCase):
    def v(self, valor):
        return ri._validate_result(valor)

    def test_valido_ok(self):
        self.assertEqual(self.v(resultado_valido())["decision"], "ALLOW")

    def test_no_dict_falla(self):
        with self.assertRaises(EvaluationError):
            self.v(["no", "dict"])

    def test_falta_campo_obligatorio(self):
        for campo in ri._CONTRACT_FIELDS:
            with self.subTest(campo=campo):
                r = resultado_valido()
                del r[campo]
                with self.assertRaises(EvaluationError):
                    self.v(r)

    def test_combinacion_invalida(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(reason_code="RCI_DENY_UNIT_MISMATCH"))  # ALLOW + code DENY

    def test_execution_allowed_string(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(execution_allowed="false"))

    def test_tipos_no_hashables_no_typeerror(self):
        for campo, val in [("decision", []), ("decision", {}), ("reason_code", []),
                           ("reason_code", {}), ("asignacion_status", []), ("asignacion_status", {})]:
            with self.subTest(campo=campo, val=type(val).__name__):
                with self.assertRaises(EvaluationError):
                    self.v(resultado_valido(**{campo: val}))

    def test_version_incorrecta(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(policy_version="2.3.1"))

    def test_regla_incorrecta(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(regla="OTRA"))

    def test_validation_errors_no_string(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=["ok", 5]))

    def test_invalid_input_sin_errores(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=[]))

    def test_validation_errors_desordenados_fallan(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=["z", "a"],
                                    actor_id=None, expediente_id=None, asignacion_status=None,
                                    evaluated_at=None))

    def test_allow_con_estado_incoherente(self):
        for estado in ("STALE", "UNAVAILABLE", None):
            with self.subTest(estado=estado):
                with self.assertRaises(EvaluationError):
                    self.v(resultado_valido(asignacion_status=estado))

    def test_action_not_allowed_valido(self):
        r = self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_ACTION_NOT_ALLOWED",
                                    execution_allowed=False, asignacion_status="FRESH"))
        self.assertEqual(r["reason_code"], "RCI_DENY_ACTION_NOT_ALLOWED")

    def test_source_unavailable_exige_unavailable(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_SOURCE_UNAVAILABLE",
                                    execution_allowed=False, asignacion_status="FRESH"))

    def test_escalate_exige_stale(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="ESCALATE", reason_code="RCI_ESCALATE_STALE_ASSIGNMENT",
                                    execution_allowed=False, asignacion_status="FRESH"))

    def test_audit_vacio_falla(self):
        for campo in ("actor_id", "expediente_id", "evaluated_at"):
            for val in (None, ""):
                with self.subTest(campo=campo, val=val):
                    with self.assertRaises(EvaluationError):
                        self.v(resultado_valido(**{campo: val}))

    def test_evaluated_at_no_rfc3339_en_negocio_falla(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="ayer"))

    def test_evaluated_at_segundo_60_falla(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T10:15:60Z"))

    def test_evaluated_at_con_salto_linea_falla_controladamente(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T10:15:00Z\n"))

    def test_allow_with_exception_sin_id_falla(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="ALLOW_WITH_EXCEPTION",
                                    reason_code="RCI_ALLOW_EXCEPTION_APPLIED", excepcion_id_aplicada=None))

    def test_id_excepcion_en_allow_falla(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(excepcion_id_aplicada="exc-1"))

    def test_seis_mas_una_combinaciones_validas(self):
        casos = [
            ("ALLOW", "RCI_ALLOW_UNIT_MATCH", True, [], None, "FRESH"),
            ("ALLOW_WITH_EXCEPTION", "RCI_ALLOW_EXCEPTION_APPLIED", True, [], "exc-1", "STALE"),
            ("DENY", "RCI_DENY_ACTION_NOT_ALLOWED", False, [], None, "FRESH"),
            ("DENY", "RCI_DENY_UNIT_MISMATCH", False, [], None, "FRESH"),
            ("DENY", "RCI_DENY_SOURCE_UNAVAILABLE", False, [], None, "UNAVAILABLE"),
            ("ESCALATE", "RCI_ESCALATE_STALE_ASSIGNMENT", False, [], None, "STALE"),
            ("DENY", "RCI_DENY_INVALID_INPUT", False, ["x"], None, None),
        ]
        for d, rc, ex, ve, ei, st in casos:
            with self.subTest(rc=rc):
                r = self.v(resultado_valido(decision=d, reason_code=rc, execution_allowed=ex,
                                            validation_errors=ve, excepcion_id_aplicada=ei, asignacion_status=st))
                self.assertEqual(r["reason_code"], rc)


# ===========================================================================
# Vínculo result <-> petición
# ===========================================================================
class TestEcos(unittest.TestCase):
    def v(self, result, entrada):
        return ri._validate_result(result, entrada)

    def test_ecos_correctos_ok(self):
        self.v(resultado_valido(), entrada_valida())

    def test_actor_incorrecto(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(actor_id="OTRO"), entrada_valida())

    def test_expediente_incorrecto(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(expediente_id="OTRO"), entrada_valida())

    def test_estado_incorrecto(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(asignacion_status="STALE"),
                   entrada_valida(resource={**entrada_valida()["resource"], "asignacion_status": "FRESH"}))

    def test_evaluated_at_incorrecto(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T09:00:00Z"), entrada_valida())

    def test_id_excepcion_incorrecto(self):
        ent = entrada_valida(excepcion={"id": "exc-REAL"})
        res = resultado_valido(decision="ALLOW_WITH_EXCEPTION", reason_code="RCI_ALLOW_EXCEPTION_APPLIED",
                               excepcion_id_aplicada="exc-FALSO")
        with self.assertRaises(EvaluationError):
            self.v(res, ent)

    def test_invalid_input_ecos_saneados_ok(self):
        ent = {"actor": {"id": 123}, "resource": {"asignacion_status": "BOGUS"}, "now": 99999}
        res = resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT", execution_allowed=False,
                               validation_errors=["e"], actor_id=None, expediente_id=None,
                               asignacion_status=None, evaluated_at=None)
        self.v(res, ent)  # ecos None coinciden con el saneado de un input basura

    def test_invalid_input_estado_no_hashable_se_sanea_sin_typeerror(self):
        res = resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT", execution_allowed=False,
                               validation_errors=["e"], actor_id=None, expediente_id=None,
                               asignacion_status=None, evaluated_at=None)
        for estado in ([], {}):
            with self.subTest(tipo=type(estado).__name__):
                self.v(res, {"resource": {"asignacion_status": estado}})


# ===========================================================================
# get_decision / access_allowed
# ===========================================================================
class TestDecision(unittest.TestCase):
    def test_obtener_decision(self):
        self.assertIs(get_decision(resultado_valido()), Decision.ALLOW)

    def test_acceso_allow_true(self):
        self.assertIs(access_allowed(resultado_valido()), True)

    def test_acceso_deny_false(self):
        r = resultado_valido(decision="DENY", reason_code="RCI_DENY_UNIT_MISMATCH", execution_allowed=False)
        self.assertIs(access_allowed(r), False)

    def test_acceso_action_not_allowed_false(self):
        r = resultado_valido(decision="DENY", reason_code="RCI_DENY_ACTION_NOT_ALLOWED", execution_allowed=False)
        self.assertIs(access_allowed(r), False)

    def test_allow_with_exception_lanza(self):
        r = resultado_valido(decision="ALLOW_WITH_EXCEPTION", reason_code="RCI_ALLOW_EXCEPTION_APPLIED",
                             excepcion_id_aplicada="exc-9", asignacion_status="STALE")
        with self.assertRaises(DecisionRequiresExplicitHandling) as ctx:
            access_allowed(r)
        self.assertEqual(ctx.exception.decision, "ALLOW_WITH_EXCEPTION")
        self.assertEqual(ctx.exception.reason_code, "RCI_ALLOW_EXCEPTION_APPLIED")
        self.assertEqual(ctx.exception.excepcion_id_aplicada, "exc-9")

    def test_escalate_lanza(self):
        r = resultado_valido(decision="ESCALATE", reason_code="RCI_ESCALATE_STALE_ASSIGNMENT",
                             execution_allowed=False, asignacion_status="STALE")
        with self.assertRaises(DecisionRequiresExplicitHandling) as ctx:
            access_allowed(r)
        self.assertEqual(ctx.exception.decision, "ESCALATE")
        self.assertIsNone(ctx.exception.excepcion_id_aplicada)

    def test_acceso_incompleto_lanza_error(self):
        with self.assertRaises(EvaluationError):
            access_allowed({"execution_allowed": True})


# ===========================================================================
# Serialización estricta
# ===========================================================================
class TestSerializacion(unittest.TestCase):
    def test_dict_ok(self):
        self.assertIn('"a"', ri._serialise_input({"a": 1}))

    def test_raiz_no_dict(self):
        for raiz in (None, [1, 2], "texto", 42, 3.5, True):
            with self.subTest(raiz=type(raiz).__name__):
                with self.assertRaises(EvaluationError):
                    ri._serialise_input(raiz)

    def test_nan_infinitos(self):
        for val in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(val=val):
                with self.assertRaises(EvaluationError):
                    ri._serialise_input({"x": val})

    def test_objeto_no_serializable(self):
        with self.assertRaises(EvaluationError):
            ri._serialise_input({"x": object()})


# ===========================================================================
# Validación de timeout
# ===========================================================================
class TestTimeout(unittest.TestCase):
    def test_validos(self):
        for t in (0.1, 1, 5.0, 30):
            ri._validate_timeout(t)  # no lanza

    def test_invalidos(self):
        for t in (0, -1, -0.5, True, False, "5", float("nan"), float("inf")):
            with self.subTest(t=repr(t)):
                with self.assertRaises(EvaluationError):
                    ri._validate_timeout(t)

    def test_evaluar_rechaza_timeout_invalido_antes_de_opa(self):
        with self.assertRaises(EvaluationError):
            evaluate(entrada_valida(), timeout=0)


# ===========================================================================
# Resolución segura de OPA
# ===========================================================================
class TestOpaResolucion(unittest.TestCase):
    def test_no_en_path(self):
        with mock.patch.object(ri.shutil, "which", return_value=None):
            with self.assertRaises(OPAUnavailable):
                ri._resolve_opa(None)

    def test_inexistente(self):
        with self.assertRaises(OPAUnavailable):
            ri._resolve_opa("/no/existe/opa_zzz")

    def test_no_ejecutable(self):
        with tempfile.NamedTemporaryFile(suffix="opa", delete=False) as f:
            ruta = f.name
        os.chmod(ruta, 0o644)
        try:
            with self.assertRaises(OPAUnavailable):
                ri._resolve_opa(ruta)
        finally:
            os.unlink(ruta)

    def test_ruta_absoluta_ejecutable(self):
        with tempfile.NamedTemporaryFile(suffix="opa", delete=False) as f:
            ruta = f.name
        os.chmod(ruta, 0o755)
        try:
            resuelta = ri._resolve_opa(ruta)
            self.assertTrue(os.path.isabs(resuelta))
        finally:
            os.unlink(ruta)


# ===========================================================================
# evaluate(): camino completo con mocks
# ===========================================================================
class TestEvaluar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".rego", delete=False)
        self.tmp.write(b"package rci.exp001\n")
        self.tmp.close()
        self.policy = self.tmp.name

    def tearDown(self):
        Path(self.policy).unlink(missing_ok=True)

    def _evaluar(self, valor_opa, entrada=None, **kw):
        entrada = entrada if entrada is not None else entrada_valida()
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri, "_run_opa", return_value=valor_opa):
            return evaluate(entrada, policy_path=self.policy, allow_custom_policy=True, **kw)

    def test_allow_ok(self):
        r = self._evaluar(resultado_valido())
        self.assertEqual(r["decision"], "ALLOW")

    def test_campos_adicionales_eliminados(self):
        r = self._evaluar(resultado_valido(campo_extra="no-contractual", otro=123))
        self.assertNotIn("campo_extra", r)
        self.assertNotIn("otro", r)
        self.assertEqual(set(r.keys()), set(ri._CONTRACT_FIELDS))

    def test_cross_check_actor_incorrecto(self):
        with self.assertRaises(EvaluationError):
            self._evaluar(resultado_valido(actor_id="INTRUSO"))

    def test_politica_personalizada_bloqueada_por_defecto(self):
        with self.assertRaises(EvaluationError):
            evaluate(entrada_valida(), policy_path=self.policy)  # sin permitir_...

    def test_politica_inexistente(self):
        with self.assertRaises(FileNotFoundError):
            evaluate(entrada_valida(), policy_path="/no/existe.rego", allow_custom_policy=True)

    def test_timeout_en_run(self):
        def _raise(*a, **k):
            raise subprocess.TimeoutExpired(cmd="opa", timeout=5)
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", side_effect=_raise):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_json_malformado(self):
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(stdout="{no json")):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_returncode_no_cero(self):
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(returncode=1, stderr="boom")):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_camino_completo_subprocess_real_mock(self):
        salida = _opa_json(resultado_valido())
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(stdout=salida)):
            r = evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)
            self.assertEqual(r["reason_code"], "RCI_ALLOW_UNIT_MATCH")


# ===========================================================================
# Política empaquetada / SHA-256
# ===========================================================================
class TestPolitica(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".rego", delete=False)
        self.tmp.write(b"package rci.exp001\n# contenido\n")
        self.tmp.close()
        self.policy = self.tmp.name

    def tearDown(self):
        Path(self.policy).unlink(missing_ok=True)

    def test_sha256_estable_y_correcto(self):
        import hashlib
        h1 = policy_sha256(self.policy)
        h2 = policy_sha256(self.policy)
        self.assertEqual(h1, h2)
        self.assertEqual(h1, hashlib.sha256(Path(self.policy).read_bytes()).hexdigest())

    def test_resolver_politica_personalizada_bloqueada(self):
        with self.assertRaises(EvaluationError):
            ri._resolve_policy(self.policy, allow_custom_policy=False)

    def test_resolver_politica_personalizada_habilitada(self):
        p = ri._resolve_policy(self.policy, allow_custom_policy=True)
        self.assertTrue(p.is_absolute())


# ===========================================================================
# Auditoría mínima
# ===========================================================================
class TestAuditoria(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".rego", delete=False)
        self.tmp.write(b"package rci.exp001\n")
        self.tmp.close()
        self.policy = self.tmp.name

    def tearDown(self):
        Path(self.policy).unlink(missing_ok=True)

    def test_registro_minimo(self):
        ent = entrada_valida()
        res = resultado_valido()
        reg = build_audit_record(ent, res, policy_path=self.policy, opa_version="1.0.0")
        for k in ("actor_id", "expediente_id", "action", "actor_unidad", "unidad_asignada",
                  "asignacion_status", "decision", "reason_code", "execution_allowed",
                  "excepcion_id_aplicada", "aprobada_por", "evaluated_at", "policy_version",
                  "policy_sha256", "opa_version"):
            self.assertIn(k, reg)
        self.assertEqual(reg["decision"], "ALLOW")
        self.assertEqual(reg["action"], "leer")
        self.assertEqual(len(reg["policy_sha256"]), 64)

    def test_registro_rechaza_resultado_descontextualizado(self):
        with self.assertRaises(EvaluationError):
            build_audit_record(
                entrada_valida(), resultado_valido(actor_id="otro"), policy_path=self.policy
            )


# ===========================================================================
# Prueba integral opcional con OPA real (se omite si no hay opa)
# ===========================================================================
_POLICY_REAL = Path(__file__).with_name("policy.rego")


@unittest.skipUnless(shutil.which("opa") and _POLICY_REAL.is_file(),
                     "OPA no disponible o falta policy.rego: se omite la prueba integral")
class TestIntegracionOpaReal(unittest.TestCase):
    def test_input_valido_da_unit_match(self):
        r = evaluate(entrada_valida())
        self.assertEqual(r["reason_code"], "RCI_ALLOW_UNIT_MATCH")
        self.assertIs(access_allowed(r), True)

    def test_accion_no_permitida(self):
        r = evaluate(entrada_valida(actor={"id": "u-001", "unidad": "UNIDAD_A", "acciones_permitidas": ["modificar"]}))
        self.assertEqual(r["reason_code"], "RCI_DENY_ACTION_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
