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

import rci_integration as ri
from rci_integration import (
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
        "rule": "RCI-EXP-001",
        "actor_id": "u-001",
        "record_id": "exp-123",
        "assignment_status": "FRESH",
        "applied_exception_id": None,
        "unused_exception_present": False,
        "validation_errors": [],
        "evaluated_at": "2026-06-28T10:15:00Z",
        "policy_version": "4.0.0",
    }
    base.update(over)
    return base


def entrada_valida(**over):
    base = {
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
    base.update(over)
    return base


def _proc(stdout="", returncode=0, stderr=""):
    return types.SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def _opa_json(value):
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


# ===========================================================================
# _validate_result: coherencia interna (sin entrada)
# ===========================================================================
class TestValidateResult(unittest.TestCase):
    def v(self, valor):
        return ri._validate_result(valor)

    def test_valid_result_passes(self):
        self.assertEqual(self.v(resultado_valido())["decision"], "ALLOW")

    def test_non_dict_fails(self):
        with self.assertRaises(EvaluationError):
            self.v(["no", "dict"])

    def test_missing_required_field(self):
        for campo in ri._CONTRACT_FIELDS:
            with self.subTest(campo=campo):
                r = resultado_valido()
                del r[campo]
                with self.assertRaises(EvaluationError):
                    self.v(r)

    def test_invalid_combination(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(reason_code="RCI_DENY_UNIT_MISMATCH"))  # ALLOW + code DENY

    def test_execution_allowed_as_string(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(execution_allowed="false"))

    def test_unhashable_types_do_not_raise_typeerror(self):
        for campo, val in [("decision", []), ("decision", {}), ("reason_code", []),
                           ("reason_code", {}), ("assignment_status", []), ("assignment_status", {})]:
            with self.subTest(campo=campo, val=type(val).__name__):
                with self.assertRaises(EvaluationError):
                    self.v(resultado_valido(**{campo: val}))

    def test_wrong_version(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(policy_version="2.3.1"))

    def test_wrong_rule(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(rule="OTRA"))

    def test_non_string_validation_errors(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=["ok", 5]))

    def test_invalid_input_without_errors(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=[]))

    def test_unsorted_validation_errors_fail(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT",
                                    execution_allowed=False, validation_errors=["z", "a"],
                                    actor_id=None, record_id=None, assignment_status=None,
                                    evaluated_at=None))

    def test_allow_with_inconsistent_status(self):
        for estado in ("STALE", "UNAVAILABLE", None):
            with self.subTest(estado=estado):
                with self.assertRaises(EvaluationError):
                    self.v(resultado_valido(assignment_status=estado))

    def test_action_not_allowed_is_valid(self):
        r = self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_ACTION_NOT_ALLOWED",
                                    execution_allowed=False, assignment_status="FRESH"))
        self.assertEqual(r["reason_code"], "RCI_DENY_ACTION_NOT_ALLOWED")

    def test_source_unavailable_requires_unavailable(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="DENY", reason_code="RCI_DENY_SOURCE_UNAVAILABLE",
                                    execution_allowed=False, assignment_status="FRESH"))

    def test_escalate_requires_stale(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="ESCALATE", reason_code="RCI_ESCALATE_STALE_ASSIGNMENT",
                                    execution_allowed=False, assignment_status="FRESH"))

    def test_empty_audit_fails(self):
        for campo in ("actor_id", "record_id", "evaluated_at"):
            for val in (None, ""):
                with self.subTest(campo=campo, val=val):
                    with self.assertRaises(EvaluationError):
                        self.v(resultado_valido(**{campo: val}))

    def test_non_rfc3339_evaluated_at_in_business_result_fails(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="ayer"))

    def test_evaluated_at_leap_second_fails(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T10:15:60Z"))

    def test_evaluated_at_with_newline_fails_gracefully(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T10:15:00Z\n"))

    def test_allow_with_exception_without_id_fails(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(decision="ALLOW_WITH_EXCEPTION",
                                    reason_code="RCI_ALLOW_EXCEPTION_APPLIED", applied_exception_id=None))

    def test_exception_id_in_allow_fails(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(applied_exception_id="exc-1"))

    def test_seven_valid_combinations(self):
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
                                            validation_errors=ve, applied_exception_id=ei, assignment_status=st))
                self.assertEqual(r["reason_code"], rc)


# ===========================================================================
# result <-> request binding
# ===========================================================================
class TestEchoes(unittest.TestCase):
    def v(self, result, entrada):
        return ri._validate_result(result, entrada)

    def test_correct_echoes_pass(self):
        self.v(resultado_valido(), entrada_valida())

    def test_wrong_actor(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(actor_id="OTRO"), entrada_valida())

    def test_wrong_record(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(record_id="OTRO"), entrada_valida())

    def test_wrong_status(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(assignment_status="STALE"),
                   entrada_valida(resource={**entrada_valida()["resource"], "assignment_status": "FRESH"}))

    def test_wrong_evaluated_at(self):
        with self.assertRaises(EvaluationError):
            self.v(resultado_valido(evaluated_at="2026-06-28T09:00:00Z"), entrada_valida())

    def test_wrong_exception_id(self):
        ent = entrada_valida(exception={"id": "exc-REAL"})
        res = resultado_valido(decision="ALLOW_WITH_EXCEPTION", reason_code="RCI_ALLOW_EXCEPTION_APPLIED",
                               applied_exception_id="exc-FALSO")
        with self.assertRaises(EvaluationError):
            self.v(res, ent)

    def test_invalid_input_sanitised_echoes_pass(self):
        ent = {"actor": {"id": 123}, "resource": {"assignment_status": "BOGUS"}, "now": 99999}
        res = resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT", execution_allowed=False,
                               validation_errors=["e"], actor_id=None, record_id=None,
                               assignment_status=None, evaluated_at=None)
        self.v(res, ent)  # ecos None coinciden con el saneado de un input basura

    def test_invalid_input_unhashable_status_sanitised_without_typeerror(self):
        res = resultado_valido(decision="DENY", reason_code="RCI_DENY_INVALID_INPUT", execution_allowed=False,
                               validation_errors=["e"], actor_id=None, record_id=None,
                               assignment_status=None, evaluated_at=None)
        for estado in ([], {}):
            with self.subTest(tipo=type(estado).__name__):
                self.v(res, {"resource": {"assignment_status": estado}})


# ===========================================================================
# get_decision / access_allowed
# ===========================================================================
class TestDecision(unittest.TestCase):
    def test_get_decision(self):
        self.assertIs(get_decision(resultado_valido()), Decision.ALLOW)

    def test_access_allow_is_true(self):
        self.assertIs(access_allowed(resultado_valido()), True)

    def test_access_deny_is_false(self):
        r = resultado_valido(decision="DENY", reason_code="RCI_DENY_UNIT_MISMATCH", execution_allowed=False)
        self.assertIs(access_allowed(r), False)

    def test_access_action_not_allowed_is_false(self):
        r = resultado_valido(decision="DENY", reason_code="RCI_DENY_ACTION_NOT_ALLOWED", execution_allowed=False)
        self.assertIs(access_allowed(r), False)

    def test_allow_with_exception_raises(self):
        r = resultado_valido(decision="ALLOW_WITH_EXCEPTION", reason_code="RCI_ALLOW_EXCEPTION_APPLIED",
                             applied_exception_id="exc-9", assignment_status="STALE")
        with self.assertRaises(DecisionRequiresExplicitHandling) as ctx:
            access_allowed(r)
        self.assertEqual(ctx.exception.decision, "ALLOW_WITH_EXCEPTION")
        self.assertEqual(ctx.exception.reason_code, "RCI_ALLOW_EXCEPTION_APPLIED")
        self.assertEqual(ctx.exception.applied_exception_id, "exc-9")

    def test_escalate_raises(self):
        r = resultado_valido(decision="ESCALATE", reason_code="RCI_ESCALATE_STALE_ASSIGNMENT",
                             execution_allowed=False, assignment_status="STALE")
        with self.assertRaises(DecisionRequiresExplicitHandling) as ctx:
            access_allowed(r)
        self.assertEqual(ctx.exception.decision, "ESCALATE")
        self.assertIsNone(ctx.exception.applied_exception_id)

    def test_incomplete_access_raises_error(self):
        with self.assertRaises(EvaluationError):
            access_allowed({"execution_allowed": True})


# ===========================================================================
# Strict serialisation
# ===========================================================================
class TestSerialisation(unittest.TestCase):
    def test_dict_passes(self):
        self.assertIn('"a"', ri._serialise_input({"a": 1}))

    def test_root_not_a_dict(self):
        for raiz in (None, [1, 2], "texto", 42, 3.5, True):
            with self.subTest(raiz=type(raiz).__name__):
                with self.assertRaises(EvaluationError):
                    ri._serialise_input(raiz)

    def test_nan_and_infinities(self):
        for val in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(val=val):
                with self.assertRaises(EvaluationError):
                    ri._serialise_input({"x": val})

    def test_non_serialisable_object(self):
        with self.assertRaises(EvaluationError):
            ri._serialise_input({"x": object()})


# ===========================================================================
# Timeout validation
# ===========================================================================
class TestTimeout(unittest.TestCase):
    def test_valid_values(self):
        for t in (0.1, 1, 5.0, 30):
            ri._validate_timeout(t)  # no lanza

    def test_invalid_values(self):
        for t in (0, -1, -0.5, True, False, "5", float("nan"), float("inf")):
            with self.subTest(t=repr(t)):
                with self.assertRaises(EvaluationError):
                    ri._validate_timeout(t)

    def test_evaluate_rejects_invalid_timeout_before_opa(self):
        with self.assertRaises(EvaluationError):
            evaluate(entrada_valida(), timeout=0)


# ===========================================================================
# Safe OPA resolution
# ===========================================================================
class TestOpaResolution(unittest.TestCase):
    def test_not_on_path(self):
        with mock.patch.object(ri.shutil, "which", return_value=None):
            with self.assertRaises(OPAUnavailable):
                ri._resolve_opa(None)

    def test_missing_binary(self):
        with self.assertRaises(OPAUnavailable):
            ri._resolve_opa("/no/existe/opa_zzz")

    def test_not_executable(self):
        with tempfile.NamedTemporaryFile(suffix="opa", delete=False) as f:
            ruta = f.name
        os.chmod(ruta, 0o644)
        try:
            with self.assertRaises(OPAUnavailable):
                ri._resolve_opa(ruta)
        finally:
            os.unlink(ruta)

    def test_absolute_executable_path(self):
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
class TestEvaluate(unittest.TestCase):
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

    def test_allow_passes(self):
        r = self._evaluar(resultado_valido())
        self.assertEqual(r["decision"], "ALLOW")

    def test_extra_fields_are_stripped(self):
        r = self._evaluar(resultado_valido(campo_extra="no-contractual", otro=123))
        self.assertNotIn("campo_extra", r)
        self.assertNotIn("otro", r)
        self.assertEqual(set(r.keys()), set(ri._CONTRACT_FIELDS))

    def test_cross_check_wrong_actor(self):
        with self.assertRaises(EvaluationError):
            self._evaluar(resultado_valido(actor_id="INTRUSO"))

    def test_custom_policy_blocked_by_default(self):
        with self.assertRaises(EvaluationError):
            evaluate(entrada_valida(), policy_path=self.policy)  # sin permitir_...

    def test_missing_policy_file(self):
        with self.assertRaises(FileNotFoundError):
            evaluate(entrada_valida(), policy_path="/no/existe.rego", allow_custom_policy=True)

    def test_timeout_during_run(self):
        def _raise(*a, **k):
            raise subprocess.TimeoutExpired(cmd="opa", timeout=5)
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", side_effect=_raise):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_malformed_json(self):
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(stdout="{no json")):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_non_zero_return_code(self):
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(returncode=1, stderr="boom")):
            with self.assertRaises(EvaluationError):
                evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)

    def test_full_path_with_mocked_subprocess(self):
        salida = _opa_json(resultado_valido())
        with mock.patch.object(ri, "_resolve_opa", return_value="/opa"), \
             mock.patch.object(ri.subprocess, "run", return_value=_proc(stdout=salida)):
            r = evaluate(entrada_valida(), policy_path=self.policy, allow_custom_policy=True)
            self.assertEqual(r["reason_code"], "RCI_ALLOW_UNIT_MATCH")


# ===========================================================================
# Bundled policy / SHA-256
# ===========================================================================
class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".rego", delete=False)
        self.tmp.write(b"package rci.exp001\n# contenido\n")
        self.tmp.close()
        self.policy = self.tmp.name

    def tearDown(self):
        Path(self.policy).unlink(missing_ok=True)

    def test_sha256_is_stable_and_correct(self):
        import hashlib
        h1 = policy_sha256(self.policy)
        h2 = policy_sha256(self.policy)
        self.assertEqual(h1, h2)
        self.assertEqual(h1, hashlib.sha256(Path(self.policy).read_bytes()).hexdigest())

    def test_resolve_custom_policy_blocked(self):
        with self.assertRaises(EvaluationError):
            ri._resolve_policy(self.policy, allow_custom_policy=False)

    def test_resolve_custom_policy_enabled(self):
        p = ri._resolve_policy(self.policy, allow_custom_policy=True)
        self.assertTrue(p.is_absolute())


# ===========================================================================
# Minimal audit
# ===========================================================================
class TestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".rego", delete=False)
        self.tmp.write(b"package rci.exp001\n")
        self.tmp.close()
        self.policy = self.tmp.name

    def tearDown(self):
        Path(self.policy).unlink(missing_ok=True)

    def test_minimal_record(self):
        ent = entrada_valida()
        res = resultado_valido()
        reg = build_audit_record(ent, res, policy_path=self.policy, opa_version="1.0.0")
        for k in ("actor_id", "record_id", "action", "actor_unit", "assigned_unit",
                  "assignment_status", "decision", "reason_code", "execution_allowed",
                  "applied_exception_id", "approved_by", "evaluated_at", "policy_version",
                  "policy_sha256", "opa_version"):
            self.assertIn(k, reg)
        self.assertEqual(reg["decision"], "ALLOW")
        self.assertEqual(reg["action"], "leer")
        self.assertEqual(len(reg["policy_sha256"]), 64)

    def test_record_rejects_out_of_context_result(self):
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
class TestRealOpaIntegration(unittest.TestCase):
    def test_valid_input_yields_unit_match(self):
        r = evaluate(entrada_valida())
        self.assertEqual(r["reason_code"], "RCI_ALLOW_UNIT_MATCH")
        self.assertIs(access_allowed(r), True)

    def test_disallowed_action(self):
        r = evaluate(entrada_valida(actor={"id": "u-001", "unit": "UNIDAD_A", "allowed_actions": ["modificar"]}))
        self.assertEqual(r["reason_code"], "RCI_DENY_ACTION_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
