package rci.exp001_test

import rego.v1

# -----------------------------------------------------------------------------
# Fixtures base — se sobreescriben campos puntuales con object.union anidado
# para no perder el resto del recurso al hacer overrides parciales.
# -----------------------------------------------------------------------------

base_input := {
	"actor": {"id": "u-001", "unidad": "UNIDAD_A", "acciones_permitidas": ["leer", "modificar"]},
	"action": "leer",
	"resource": {
		"expediente_id": "exp-123",
		"unidad_asignada": "UNIDAD_A",
		"asignacion_status": "FRESH",
		"asignacion_timestamp": "2026-06-28T10:00:00Z",
		"asignacion_max_age_seconds": 3600,
	},
	"excepcion": null,
	"now": "2026-06-28T10:15:00Z",
}

# Excepción válida (dentro de ventana, con fuente_status FRESH y su propia
# frescura coherente: edad 15 min <= fuente_max_age 3600 s).
excepcion_valida := {
	"id": "exc-777",
	"actor_id": "u-001",
	"expediente_id": "exp-123",
	"acciones_autorizadas": ["leer"],
	"vigente_desde": "2026-06-28T00:00:00Z",
	"vigente_hasta": "2026-06-29T00:00:00Z",
	"fuente_status": "FRESH",
	"fuente_timestamp": "2026-06-28T10:00:00Z",
	"fuente_max_age_seconds": 3600,
	"aprobada_por": "responsable-x",
}

# Excepción con fuente STALE coherente: edad 75 min > fuente_max_age 3600 s.
excepcion_stale := object.union(excepcion_valida, {
	"fuente_status": "STALE",
	"fuente_timestamp": "2026-06-28T09:00:00Z",
})

# Recurso STALE coherente: la edad (now - timestamp) supera el max_age, de modo
# que STALE no contradice al timestamp y no dispara error de validación.
resource_stale := object.union(base_input.resource, {
	"asignacion_status": "STALE",
	"asignacion_timestamp": "2026-06-28T09:00:00Z",
})

# =============================================================================
# 1. UNAVAILABLE -> DENY, sin importar nada más
# =============================================================================

test_unavailable_deny if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_status": "UNAVAILABLE"})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_SOURCE_UNAVAILABLE"
	r.execution_allowed == false
}

test_unavailable_deny_aunque_unidad_coincida if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_status": "UNAVAILABLE", "unidad_asignada": "UNIDAD_A"})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
}

# =============================================================================
# 2. FRESH + unidad coincide -> ALLOW
# =============================================================================

test_fresh_unidad_coincide_allow if {
	r := data.rci.exp001.resultado with input as base_input
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
	r.execution_allowed == true
	r.excepcion_existente_no_utilizada == false
	r.excepcion_id_aplicada == null
}

test_fresh_unidad_coincide_con_excepcion_aplicable_marca_no_utilizada if {
	inp := object.union(base_input, {"excepcion": excepcion_valida})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW"
	r.excepcion_existente_no_utilizada == true
	r.excepcion_id_aplicada == null # ALLOW por unidad, la excepción NO se aplicó
}

test_fresh_unidad_coincide_con_excepcion_de_otro_actor_no_marca if {
	otra := object.union(excepcion_valida, {"actor_id": "u-999"})
	inp := object.union(base_input, {"excepcion": otra})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW"
	r.excepcion_existente_no_utilizada == false
}

# =============================================================================
# 3. FRESH + unidad NO coincide + excepción válida -> ALLOW_WITH_EXCEPTION
# =============================================================================

test_fresh_unidad_no_coincide_con_excepcion_valida_allow_with_exception if {
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": excepcion_valida,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
	r.execution_allowed == true
	r.excepcion_id_aplicada == "exc-777"
}

test_excepcion_fuera_de_ventana_no_aplica if {
	vencida := object.union(excepcion_valida, {
		"vigente_desde": "2026-01-01T00:00:00Z",
		"vigente_hasta": "2026-01-02T00:00:00Z",
	})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": vencida,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

test_excepcion_no_cubre_la_accion_no_aplica if {
	otra_accion := object.union(excepcion_valida, {"acciones_autorizadas": ["modificar"]})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": otra_accion,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

test_excepcion_de_otro_expediente_no_aplica if {
	otro_exp := object.union(excepcion_valida, {"expediente_id": "exp-OTRO"})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": otro_exp,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 4. FRESH + unidad NO coincide + sin excepción válida -> DENY
# =============================================================================

test_fresh_unidad_no_coincide_sin_excepcion_deny if {
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
	r.execution_allowed == false
}

# Nuevo requisito: la excepción solo compensa si ELLA MISMA está FRESH.
test_fresh_unidad_no_coincide_excepcion_stale_deny if {
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": excepcion_stale,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
	r.execution_allowed == false
}

test_fresh_unidad_no_coincide_excepcion_unavailable_deny if {
	exc_unavail := object.union(excepcion_valida, {"fuente_status": "UNAVAILABLE"})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"excepcion": exc_unavail,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 5. STALE + excepción válida y FRESH -> ALLOW_WITH_EXCEPTION
# =============================================================================

test_stale_con_excepcion_fresh_allow_with_exception if {
	inp := object.union(base_input, {"resource": resource_stale, "excepcion": excepcion_valida})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
	r.execution_allowed == true
	r.excepcion_id_aplicada == "exc-777"
}

# =============================================================================
# 6. STALE + excepción obsoleta / vencida -> ESCALATE (no compensa)
# =============================================================================

test_stale_con_excepcion_tambien_stale_no_compensa_escalate if {
	inp := object.union(base_input, {"resource": resource_stale, "excepcion": excepcion_stale})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
	r.execution_allowed == false
}

test_stale_con_excepcion_vencida_escalate if {
	vencida := object.union(excepcion_valida, {
		"vigente_desde": "2026-01-01T00:00:00Z",
		"vigente_hasta": "2026-01-02T00:00:00Z",
	})
	inp := object.union(base_input, {"resource": resource_stale, "excepcion": vencida})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
}

# =============================================================================
# 7. STALE sin excepción -> ESCALATE, operación retenida
# =============================================================================

test_stale_sin_excepcion_escalate_retenida if {
	inp := object.union(base_input, {"resource": resource_stale})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
	r.execution_allowed == false
}

# =============================================================================
# 8. Timestamps con offsets horarios (comparación por instante, no por string)
# =============================================================================

# Ventana de excepción expresada en +02:00 que, comparada como string, dejaría
# fuera a now=10:15Z; comparada como instante lo contiene. El timestamp de
# asignación también viene con offset y es coherente con FRESH.
test_offsets_horarios_ventana_allow_with_exception if {
	exc := object.union(excepcion_valida, {
		"vigente_desde": "2026-06-28T12:00:00+02:00", # == 10:00Z
		"vigente_hasta": "2026-06-28T12:30:00+02:00", # == 10:30Z
	})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unidad": "UNIDAD_B"},
		"resource": object.union(base_input.resource, {"asignacion_timestamp": "2026-06-28T12:00:00+02:00"}),
		"excepcion": exc,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
}

# =============================================================================
# 9. Límites exactos de vigencia (ventana inclusiva en ambos extremos)
# =============================================================================

test_limite_exacto_vigente_desde_incluido if {
	exc := object.union(excepcion_valida, {"vigente_desde": base_input.now})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
}

test_limite_exacto_vigente_hasta_incluido if {
	exc := object.union(excepcion_valida, {"vigente_hasta": base_input.now})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
}

test_un_segundo_despues_de_vigente_hasta_deny if {
	exc := object.union(excepcion_valida, {"vigente_hasta": "2026-06-28T10:14:59Z"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 10. Input inválido -> siempre resultado estructurado con RCI_DENY_INVALID_INPUT
# =============================================================================

test_estado_invalido_es_input_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_status": "BOGUS"})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
}

test_campo_ausente_actor_id_es_input_invalido if {
	# object.union hace merge profundo, así que para OMITIR actor.id se construye
	# el input de forma explícita (sin esa clave).
	inp := {
		"actor": {"unidad": "UNIDAD_A"},
		"action": "leer",
		"resource": base_input.resource,
		"excepcion": null,
		"now": base_input.now,
	}
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_now_no_rfc3339_es_input_invalido if {
	inp := object.union(base_input, {"now": "no-es-una-fecha"})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_excepcion_con_timestamp_invalido_es_input_invalido if {
	exc := object.union(excepcion_valida, {"vigente_hasta": "ayer"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# excepcion es obligatorio: la clave debe existir aunque valga null.
test_excepcion_ausente_es_input_invalido if {
	inp := {
		"actor": base_input.actor,
		"action": base_input.action,
		"resource": base_input.resource,
		"now": base_input.now,
	}
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# Un timestamp de asignación en el futuro no puede ser FRESH (sería ALLOW sin
# esta validación, porque la unidad coincide).
test_asignacion_timestamp_futuro_es_input_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"asignacion_status": "FRESH",
		"asignacion_timestamp": "2026-06-28T11:00:00Z", # 45 min DESPUÉS de now
		"asignacion_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_max_age_negativo_es_input_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_max_age_seconds": -1})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# Frescura de la excepción declarada FRESH pero contradicha por su timestamp:
# edad 75 min > fuente_max_age 3600 s -> input inválido.
test_contradiccion_frescura_excepcion_timestamp if {
	exc := object.union(excepcion_valida, {"fuente_timestamp": "2026-06-28T09:00:00Z"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# --- Endurecimiento 2.2.0 -----------------------------------------------------

# La raíz del input debe ser un objeto: null, string y array son inválidos, y el
# resultado sigue definido (no aborta).
test_raiz_null_es_input_invalido if {
	r := data.rci.exp001.resultado with input as null
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
}

test_raiz_string_es_input_invalido if {
	r := data.rci.exp001.resultado with input as "texto"
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_raiz_array_es_input_invalido if {
	r := data.rci.exp001.resultado with input as [1, 2, 3]
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Fecha con forma correcta pero imposible en el calendario (31 de febrero). No
# debe abortar aunque se use --strict-builtin-errors.
test_fecha_imposible_now_es_input_invalido if {
	inp := object.union(base_input, {"now": "2026-02-31T10:15:00Z"})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_fecha_imposible_en_timestamp_asignacion if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_timestamp": "2026-02-31T10:00:00Z"})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_fecha_febrero_29_no_bisiesto_es_invalida if {
	inp := object.union(base_input, {"now": "2025-02-29T10:15:00Z"})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Ventana de vigencia invertida.
test_vigente_desde_posterior_a_hasta_es_invalido if {
	exc := object.union(excepcion_valida, {
		"vigente_desde": "2026-06-29T00:00:00Z",
		"vigente_hasta": "2026-06-28T00:00:00Z",
	})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# acciones_autorizadas debe ser array de strings NO vacíos.
test_acciones_con_string_vacio_es_invalido if {
	exc := object.union(excepcion_valida, {"acciones_autorizadas": ["leer", ""]})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_acciones_con_elemento_no_string_es_invalido if {
	exc := object.union(excepcion_valida, {"acciones_autorizadas": ["leer", 123]})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# --- Endurecimiento 2.3.0: representabilidad de fechas y strings vacíos --------

# Años fuera del rango representable como ns int64 por OPA -> input inválido, y
# resultado SIEMPRE definido (no aborta ni con --strict-builtin-errors).
test_anio_9999_no_representable_es_invalido if {
	inp := object.union(base_input, {"now": "9999-12-31T23:59:59Z"})
	r := data.rci.exp001.resultado with input as inp
	is_object(r)
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
}

test_anio_0000_no_representable_es_invalido if {
	inp := object.union(base_input, {"now": "0000-01-01T00:00:00Z"})
	r := data.rci.exp001.resultado with input as inp
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_asignacion_timestamp_anio_9999_es_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_timestamp": "9999-01-01T00:00:00Z"})})
	r := data.rci.exp001.resultado with input as inp
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Extremo representable (año 2261): sí se procesa con normalidad.
test_anio_2261_representable_ok if {
	inp := object.union(base_input, {
		"now": "2261-01-01T00:00:00Z",
		"resource": object.union(base_input.resource, {"asignacion_timestamp": "2261-01-01T00:00:00Z"}),
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
}

# Strings vacíos en campos obligatorios -> input inválido.
test_actor_id_vacio_es_invalido if {
	inp := object.union(base_input, {"actor": {"id": "", "unidad": "UNIDAD_A"}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_actor_unidad_vacia_es_invalido if {
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": ""}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_action_vacia_es_invalido if {
	inp := object.union(base_input, {"action": ""})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_expediente_id_vacio_es_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"expediente_id": ""})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_unidad_asignada_vacia_es_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"unidad_asignada": ""})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_excepcion_id_vacio_es_invalido if {
	exc := object.union(excepcion_valida, {"id": ""})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_excepcion_aprobada_por_vacia_es_invalido if {
	exc := object.union(excepcion_valida, {"aprobada_por": ""})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# =============================================================================
# 11. Coherencia status vs timestamp/max_age detectada por Rego
# =============================================================================

test_status_fresh_incompatible_con_timestamp_maxage if {
	# edad = 75 min = 4500 s > max_age 3600 s, pero status dice FRESH -> contradicción
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"asignacion_status": "FRESH",
		"asignacion_timestamp": "2026-06-28T09:00:00Z",
		"asignacion_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_status_stale_incompatible_con_timestamp_maxage if {
	# edad = 15 min = 900 s <= max_age 3600 s, pero status dice STALE -> contradicción
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"asignacion_status": "STALE",
		"asignacion_timestamp": "2026-06-28T10:00:00Z",
		"asignacion_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# =============================================================================
# 12. resultado SIEMPRE definido (incluso con input vacío o basura)
# =============================================================================

test_resultado_siempre_definido_input_vacio if {
	r := data.rci.exp001.resultado with input as {}
	is_object(r) # está definido
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
}

# =============================================================================
# 13. Metadatos de trazabilidad siempre presentes
# =============================================================================

test_resultado_incluye_metadatos_de_trazabilidad if {
	r := data.rci.exp001.resultado with input as base_input
	r.regla == "RCI-EXP-001"
	r.policy_version == "3.0.0"
	r.evaluated_at == base_input.now
	r.actor_id == "u-001"
	r.expediente_id == "exp-123"
	r.asignacion_status == "FRESH"
}

# --- Saneado de auditoría 2.3.1: valores mal tipados -> null en los ecos, sin
#     alterar decisión ni validation_errors --------------------------------------

test_actor_id_no_string_se_sanea_a_null if {
	inp := object.union(base_input, {"actor": {"id": 123, "unidad": "UNIDAD_A"}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.actor_id == null
}

test_expediente_id_no_string_se_sanea_a_null if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"expediente_id": 456})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.expediente_id == null
}

test_asignacion_status_invalido_se_sanea_a_null if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_status": "BOGUS"})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.asignacion_status == null
}

test_evaluated_at_no_string_se_sanea_a_null if {
	inp := object.union(base_input, {"now": 99999})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.evaluated_at == null
}

test_saneado_no_altera_validation_errors if {
	inp := object.union(base_input, {"actor": {"id": 123, "unidad": "UNIDAD_A"}})
	r := data.rci.exp001.resultado with input as inp
	count(r.validation_errors) > 0
	r.decision == "DENY"
	r.execution_allowed == false
}

# --- Cobertura adicional: casos de input inválido no cubiertos explícitamente ---
# Todos deben: DENY / RCI_DENY_INVALID_INPUT / exec false / errores>0 / resultado
# definido con todos los campos contractuales.

_campos_obligatorios_presentes(r) if {
	r.decision
	r.reason_code
	r.regla == "RCI-EXP-001"
	r.policy_version == "3.0.0"

	# claves presentes aunque su valor sea null/false/[]
	object.get(r, "actor_id", "__NO__") != "__NO__"
	object.get(r, "expediente_id", "__NO__") != "__NO__"
	object.get(r, "asignacion_status", "__NO__") != "__NO__"
	object.get(r, "excepcion_id_aplicada", "__NO__") != "__NO__"
	object.get(r, "excepcion_existente_no_utilizada", "__NO__") != "__NO__"
	object.get(r, "evaluated_at", "__NO__") != "__NO__"
	is_boolean(r.execution_allowed)
	is_array(r.validation_errors)
}

test_raiz_numerica_es_input_invalido if {
	r := data.rci.exp001.resultado with input as 42
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_campos_obligatorios_presentes(r)
}

test_excepcion_fuente_timestamp_futuro_es_invalido if {
	exc := object.union(excepcion_valida, {"fuente_timestamp": "2026-06-28T11:00:00Z"}) # 45 min > now
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_campos_obligatorios_presentes(r)
}

test_excepcion_fuente_max_age_negativo_es_invalido if {
	exc := object.union(excepcion_valida, {"fuente_max_age_seconds": -1})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_campos_obligatorios_presentes(r)
}

# fuente_status=STALE pero la edad real (5 min) corresponde a FRESH -> incoherente.
test_excepcion_fuente_stale_con_edad_fresh_es_invalido if {
	exc := object.union(excepcion_valida, {
		"fuente_status": "STALE",
		"fuente_timestamp": "2026-06-28T10:10:00Z",
	})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_campos_obligatorios_presentes(r)
}

test_excepcion_acciones_no_array_es_invalido if {
	exc := object.union(excepcion_valida, {"acciones_autorizadas": "leer"}) # string, no array
	inp := object.union(base_input, {"actor": {"id": "u-001", "unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_campos_obligatorios_presentes(r)
}

# =============================================================================
# 3.0.0 — Autorización por acción (actor.acciones_permitidas)
# =============================================================================

# Excepción idéntica pero sin la clave `fuente_status` (para probar "ausente").
excepcion_sin_fuente_status := {k: excepcion_valida[k] |
	some k in object.keys(excepcion_valida)
	k != "fuente_status"
}

test_accion_permitida_unit_match_allow if {
	r := data.rci.exp001.resultado with input as base_input
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
	r.execution_allowed == true
}

test_accion_no_permitida_deny if {
	inp := object.union(base_input, {"actor": {"acciones_permitidas": ["modificar"]}}) # "leer" no está
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
	r.execution_allowed == false
}

test_accion_permitida_via_excepcion_allow_with_exception if {
	inp := object.union(base_input, {
		"actor": {"unidad": "UNIDAD_B", "acciones_permitidas": ["leer"]},
		"excepcion": excepcion_valida,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
}

# Aunque la excepción autorice "leer", si no está en acciones_permitidas -> DENY acción.
test_excepcion_no_puede_conceder_accion_no_permitida if {
	inp := object.union(base_input, {
		"actor": {"unidad": "UNIDAD_B", "acciones_permitidas": ["modificar"]},
		"excepcion": excepcion_valida,
	})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
}

test_acciones_permitidas_ausente_es_invalido if {
	inp := {
		"actor": {"id": "u-001", "unidad": "UNIDAD_A"},
		"action": "leer",
		"resource": base_input.resource,
		"excepcion": null,
		"now": base_input.now,
	}
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_acciones_permitidas_no_array_es_invalido if {
	inp := object.union(base_input, {"actor": {"acciones_permitidas": "leer"}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_acciones_permitidas_elemento_no_string_es_invalido if {
	inp := object.union(base_input, {"actor": {"acciones_permitidas": ["leer", 123]}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_acciones_permitidas_elemento_vacio_es_invalido if {
	inp := object.union(base_input, {"actor": {"acciones_permitidas": ["leer", ""]}})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_acciones_permitidas_vacia_con_accion_solicitada_deny if {
	inp := object.union(base_input, {"actor": {"acciones_permitidas": []}})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
}

# UNAVAILABLE tiene prioridad sobre las excepciones (pero la acción va antes).
test_unavailable_con_excepcion_fresh_sigue_source_unavailable if {
	res := object.union(base_input.resource, {"asignacion_status": "UNAVAILABLE"})
	inp := object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}, "resource": res, "excepcion": excepcion_valida})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_SOURCE_UNAVAILABLE"
}

test_excepcion_como_string_es_invalido if {
	inp := object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}, "excepcion": "no-soy-objeto"})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_excepcion_fuente_status_ausente_es_invalido if {
	inp := object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}, "excepcion": excepcion_sin_fuente_status})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_asignacion_max_age_no_numerico_es_invalido if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_max_age_seconds": "3600"})})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_excepcion_fuente_max_age_no_numerico_es_invalido if {
	exc := object.union(excepcion_valida, {"fuente_max_age_seconds": "3600"})
	inp := object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}, "excepcion": exc})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# max_age = 0: solo es FRESH una edad exactamente 0 (now == timestamp).
test_max_age_cero_edad_cero_es_fresh_allow if {
	res := object.union(base_input.resource, {"asignacion_max_age_seconds": 0, "asignacion_timestamp": base_input.now})
	inp := object.union(base_input, {"resource": res})
	r := data.rci.exp001.resultado with input as inp
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
}

test_max_age_cero_edad_positiva_fresh_es_incoherente if {
	# status FRESH con edad 15 min pero max_age 0 -> contradicción -> inválido.
	res := object.union(base_input.resource, {"asignacion_max_age_seconds": 0})
	inp := object.union(base_input, {"resource": res})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Segundos intercalares :60 no admitidos por este contrato.
test_segundo_60_en_now_es_invalido if {
	inp := object.union(base_input, {"now": "2026-06-28T10:15:60Z"})
	r := data.rci.exp001.resultado with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Toda salida producida tiene una terna (decision, reason_code, execution_allowed) coherente.
test_todas_las_ternas_coherentes if {
	combos := {
		["ALLOW", "RCI_ALLOW_UNIT_MATCH", true],
		["ALLOW_WITH_EXCEPTION", "RCI_ALLOW_EXCEPTION_APPLIED", true],
		["DENY", "RCI_DENY_UNIT_MISMATCH", false],
		["DENY", "RCI_DENY_SOURCE_UNAVAILABLE", false],
		["ESCALATE", "RCI_ESCALATE_STALE_ASSIGNMENT", false],
		["DENY", "RCI_DENY_INVALID_INPUT", false],
		["DENY", "RCI_DENY_ACTION_NOT_ALLOWED", false],
	}
	entradas := [
		base_input,
		object.union(base_input, {"actor": {"acciones_permitidas": ["modificar"]}}),
		object.union(base_input, {"resource": object.union(base_input.resource, {"asignacion_status": "UNAVAILABLE"})}),
		object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}, "excepcion": excepcion_valida}),
		object.union(base_input, {"actor": {"unidad": "UNIDAD_B"}}),
		object.union(base_input, {"resource": resource_stale}),
		{},
	]
	every inp in entradas {
		r := data.rci.exp001.resultado with input as inp
		[r.decision, r.reason_code, r.execution_allowed] in combos
	}
}
