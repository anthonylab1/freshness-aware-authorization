package rci.exp001

import rego.v1

# =============================================================================
# RCI-EXP-001 — Coherencia procedimental para acceso a expediente
#
# Política puramente declarativa. Cambios respecto a la 1.0.0 (ver contrato.md,
# sección "Changelog 2.0.0"):
#
#   1. Toda excepción que conceda acceso exige `fuente_status == "FRESH"`,
#      tanto con asignación FRESH como STALE.
#   2. Los instantes (`now`, `vigente_desde`, `vigente_hasta`,
#      `asignacion_timestamp`) se comparan como nanosegundos vía
#      `time.parse_rfc3339_ns`, nunca como strings.
#   3. La política SIEMPRE devuelve un resultado estructurado. Si el input no
#      cumple el contrato -> DENY / RCI_DENY_INVALID_INPUT con `validation_errors`.
#   4. `decision`, `reason_code` y `execution_allowed` se emiten juntos en un
#      único objeto `outcome`, de modo que no pueden desincronizarse entre reglas.
#   5. Nuevo `excepcion.id` en input y `excepcion_id_aplicada` en output.
#   6. Rego NO recalcula el estado, pero SÍ detecta contradicciones entre
#      `asignacion_status`, `asignacion_timestamp` y `asignacion_max_age_seconds`
#      y las trata como input inválido.
#
# Cambios 2.1.0:
#   7. `excepcion` es obligatorio: se valida que la CLAVE exista aunque valga null.
#   8. Nuevas validaciones: `asignacion_timestamp <= now` (sin futuros),
#      `asignacion_max_age_seconds >= 0`.
#   9. La frescura de la excepción se modela igual que la de la asignación:
#      `excepcion.fuente_timestamp` + `excepcion.fuente_max_age_seconds`, y se
#      valida que `fuente_status` no contradiga su edad real.
#
# Cambios 2.2.0 (endurecimiento):
#  10. Se valida que la raíz del input sea un objeto (null/string/array -> inválido).
#  11. Se rechazan excepciones con `vigente_desde` posterior a `vigente_hasta`.
#  12. `acciones_autorizadas` debe ser array de strings NO vacíos.
#  13. Fechas: validación de calendario (p. ej. 2026-02-31 se rechaza) ANTES de
#      parsear. `time.parse_rfc3339_ns` solo recibe fechas ya validadas, por lo
#      que la política no aborta ni con --strict-builtin-errors.
#
# Cambios 2.3.0 (endurecimiento):
#  14. Representabilidad: además de forma+calendario, el año se limita al rango
#      que OPA puede representar como ns int64 (~1678..2261) y se exige que
#      `time.parse_rfc3339_ns` devuelva realmente un número (`_ns`). Fechas no
#      representables (p. ej. años 0000 o 9999) -> RCI_DENY_INVALID_INPUT.
#  15. Se rechazan strings vacíos en actor.id, actor.unidad, action,
#      resource.expediente_id, resource.unidad_asignada, y en los ids y
#      aprobada_por de la excepción.
# Cambios 2.3.1 (saneado de auditoría):
#  16. Los ecos de auditoría del output (actor_id, expediente_id,
#      asignacion_status, evaluated_at) se sanean por tipo: se refleja el
#      valor del input solo si tiene el tipo contractual; si no, null. No
#      cambia la decisión, el reason_code ni validation_errors.
# Cambios 3.0.0 (autorización por acción + frontera de confianza):
#  17. Nuevo actor.acciones_permitidas (array de strings no vacíos, obligatorio):
#      lista de acciones ya resuelta por el sistema corporativo (dato del PEP).
#  18. Nueva decisión DENY/RCI_DENY_ACTION_NOT_ALLOWED cuando el input es válido
#      pero la accion no está en actor.acciones_permitidas. Se comprueba ANTES de
#      unidad y excepciones: una excepción no puede conceder una acción no permitida.
# =============================================================================

policy_version := "3.0.0"

# Enums cerrados reutilizados en validación y lógica.
estados_validos := {"FRESH", "STALE", "UNAVAILABLE"}

# -----------------------------------------------------------------------------
# Utilidades puras
# -----------------------------------------------------------------------------

# Raíz segura: si `input` no es un objeto (null, string, array, número...), se
# trabaja sobre {} para que ningún object.get falle y el resultado siga definido.
_root := input if is_object(input)

_root := {} if not is_object(input)

# Forma RFC3339 (fecha-hora con `Z` u offset ±hh:mm). Se usa [0-9] en vez de \d
# para no depender de las clases Perl del motor de regex.
_rfc3339_re := `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+][0-9]{2}:[0-9]{2}|[-][0-9]{2}:[0-9]{2})$`

# Días por mes, con año bisiesto para febrero.
_divisible(a, b) if a / b == floor(a / b)

_bisiesto(y) if {
	_divisible(y, 4)
	not _divisible(y, 100)
}

_bisiesto(y) if _divisible(y, 400)

_dias_mes(_, m) := 31 if m in {1, 3, 5, 7, 8, 10, 12}

_dias_mes(_, m) := 30 if m in {4, 6, 9, 11}

_dias_mes(y, m) := 29 if {
	m == 2
	_bisiesto(y)
}

_dias_mes(y, m) := 28 if {
	m == 2
	not _bisiesto(y)
}

# Lectura de enteros por posición sin `to_number` (que en algunos motores rechaza
# ceros a la izquierda como "06"). _dos lee dos dígitos; el año son dos pares.
_digito := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_dos(s, pos) := (10 * _digito[substring(s, pos, 1)]) + _digito[substring(s, pos + 1, 1)]

_anio(s) := (100 * _dos(s, 0)) + _dos(s, 2)

# Validación de calendario a partir de posiciones fijas (la forma ya la garantiza
# el regex). Rechaza fechas imposibles como 2026-02-31 o 2026-13-01 SIN parsear.
# El año se limita al rango representable como nanosegundos int64 por OPA
# (rango aceptado 1678..2261 inclusive): fuera de él time.parse_rfc3339_ns desborda.
_fecha_valida(s) if {
	anio := _anio(s)
	mes := _dos(s, 5)
	dia := _dos(s, 8)
	anio >= 1678
	anio <= 2261
	mes >= 1
	mes <= 12
	dia >= 1
	dia <= _dias_mes(anio, mes)
	_dos(s, 11) <= 23
	_dos(s, 14) <= 59
	_dos(s, 17) <= 59
}

# Offset horario válido: `Z`, o ±hh:mm con hh<=23 y mm<=59.
_offset_valido(s) if endswith(s, "Z")

_offset_valido(s) if {
	not endswith(s, "Z")
	n := count(s)
	_dos(s, n - 5) <= 23
	_dos(s, n - 2) <= 59
}

# Devuelve el propio string SOLO si es un RFC3339 real (forma + calendario +
# offset). Es la única puerta por la que pasan los strings antes de parsear: así
# `time.parse_rfc3339_ns` nunca recibe una fecha imposible y no puede abortar,
# ni siquiera con --strict-builtin-errors.
_rfc3339_ok(s) := s if {
	is_string(s)
	regex.match(_rfc3339_re, s)
	_fecha_valida(s)
	_offset_valido(s)
}

# Nanosegundos del instante, PERO solo si el parseo produce realmente un número.
# No basta con forma+calendario: se confirma que OPA puede representar la fecha.
# Si no, `_ns` queda indefinido -> el campo se marca inválido.
_ns(s) := n if {
	n := time.parse_rfc3339_ns(_rfc3339_ok(s))
	is_number(n)
}

# Booleano de conveniencia para las comprobaciones de validación.
es_rfc3339(s) if _ns(s)

# -----------------------------------------------------------------------------
# Validación de input -> conjunto `_verr` de mensajes de error.
# Cada comprobación usa accesos seguros (object.get con default) para que la
# ausencia de un campo produzca un error de validación en vez de dejar la
# política indefinida.
# -----------------------------------------------------------------------------

# La raíz del input debe ser un objeto JSON (no null, string, array ni número).
_verr contains "input: la raíz debe ser un objeto JSON" if {
	not is_object(input)
}

_verr contains "actor.id: ausente, no string o vacío" if {
	not _string_no_vacio(object.get(_root, ["actor", "id"], null))
}

_verr contains "actor.unidad: ausente, no string o vacío" if {
	not _string_no_vacio(object.get(_root, ["actor", "unidad"], null))
}

_verr contains "action: ausente, no string o vacío" if {
	not _string_no_vacio(object.get(_root, ["action"], null))
}

_verr contains "actor.acciones_permitidas: ausente o no array" if {
	not is_array(object.get(_root, ["actor", "acciones_permitidas"], null))
}

_verr contains "actor.acciones_permitidas: debe contener solo strings no vacíos" if {
	is_array(object.get(_root, ["actor", "acciones_permitidas"], null))
	some x in input.actor.acciones_permitidas
	not _string_no_vacio(x)
}

_verr contains "resource.expediente_id: ausente, no string o vacío" if {
	not _string_no_vacio(object.get(_root, ["resource", "expediente_id"], null))
}

_verr contains "resource.asignacion_status: ausente o fuera de enum {FRESH,STALE,UNAVAILABLE}" if {
	not object.get(_root, ["resource", "asignacion_status"], null) in estados_validos
}

_verr contains "resource.asignacion_max_age_seconds: ausente o no número" if {
	not is_number(object.get(_root, ["resource", "asignacion_max_age_seconds"], null))
}

_verr contains "resource.asignacion_max_age_seconds: debe ser >= 0" if {
	is_number(object.get(_root, ["resource", "asignacion_max_age_seconds"], null))
	input.resource.asignacion_max_age_seconds < 0
}

_verr contains "now: instante RFC3339 ausente o inválido" if {
	not es_rfc3339(object.get(_root, ["now"], null))
}

# Con FRESH/STALE el dato de asignación es relevante: se exige unidad y timestamp.
_estado_con_dato if object.get(_root, ["resource", "asignacion_status"], null) in {"FRESH", "STALE"}

_verr contains "resource.unidad_asignada: ausente, no string o vacío (requerido si FRESH/STALE)" if {
	_estado_con_dato
	not _string_no_vacio(object.get(_root, ["resource", "unidad_asignada"], null))
}

_verr contains "resource.asignacion_timestamp: RFC3339 ausente o inválido (requerido si FRESH/STALE)" if {
	_estado_con_dato
	not es_rfc3339(object.get(_root, ["resource", "asignacion_timestamp"], null))
}

# Un timestamp de asignación en el futuro no puede considerarse FRESH/STALE.
_verr contains "resource.asignacion_timestamp: está en el futuro (> now)" if {
	_estado_con_dato
	_edad_segundos < 0
}

# --- Coherencia asignacion_status vs (timestamp, max_age) -------------------
# Rego confía en el adaptador para el ESTADO, pero rechaza como inválido todo
# input donde el estado declarado contradiga la edad calculada. Convención:
# edad <= max_age  => FRESH ;  edad > max_age => STALE.

_edad_segundos := s if {
	ns_now := _ns(input.now)
	ns_ts := _ns(input.resource.asignacion_timestamp)
	s := (ns_now - ns_ts) / 1000000000
}

_verr contains "coherencia: status=FRESH pero edad > max_age (el adaptador debería haber marcado STALE)" if {
	input.resource.asignacion_status == "FRESH"
	is_number(object.get(_root, ["resource", "asignacion_max_age_seconds"], null))
	_edad_segundos > input.resource.asignacion_max_age_seconds
}

_verr contains "coherencia: status=STALE pero edad <= max_age (el adaptador debería haber marcado FRESH)" if {
	input.resource.asignacion_status == "STALE"
	is_number(object.get(_root, ["resource", "asignacion_max_age_seconds"], null))
	_edad_segundos <= input.resource.asignacion_max_age_seconds
}

# --- Validación de la excepción (solo si viene una) -------------------------

_hay_excepcion if is_object(input.excepcion)

# `excepcion` es OBLIGATORIO: debe existir la clave aunque su valor sea null.
# El centinela distingue "clave ausente" de "valor null" (object.get con path
# existente devuelve null; con path inexistente devuelve el default).
_verr contains "excepcion: campo obligatorio ausente (usa null si no hay excepción)" if {
	object.get(_root, ["excepcion"], "__AUSENTE__") == "__AUSENTE__"
}

_verr contains "excepcion: debe ser un objeto o null" if {
	input.excepcion != null
	not is_object(input.excepcion)
}

_verr contains "excepcion.id: ausente, no string o vacío" if {
	_hay_excepcion
	not _string_no_vacio(object.get(input.excepcion, ["id"], null))
}

_verr contains "excepcion.actor_id: ausente, no string o vacío" if {
	_hay_excepcion
	not _string_no_vacio(object.get(input.excepcion, ["actor_id"], null))
}

_verr contains "excepcion.expediente_id: ausente, no string o vacío" if {
	_hay_excepcion
	not _string_no_vacio(object.get(input.excepcion, ["expediente_id"], null))
}

_verr contains "excepcion.acciones_autorizadas: ausente o no array" if {
	_hay_excepcion
	not is_array(object.get(input.excepcion, ["acciones_autorizadas"], null))
}

_string_no_vacio(x) if {
	is_string(x)
	count(x) > 0
}

_verr contains "excepcion.acciones_autorizadas: debe contener solo strings no vacíos" if {
	_hay_excepcion
	is_array(object.get(input.excepcion, ["acciones_autorizadas"], null))
	some x in input.excepcion.acciones_autorizadas
	not _string_no_vacio(x)
}

_verr contains "excepcion.vigente_desde: RFC3339 ausente o inválido" if {
	_hay_excepcion
	not es_rfc3339(object.get(input.excepcion, ["vigente_desde"], null))
}

_verr contains "excepcion.vigente_hasta: RFC3339 ausente o inválido" if {
	_hay_excepcion
	not es_rfc3339(object.get(input.excepcion, ["vigente_hasta"], null))
}

# La ventana de vigencia debe ser coherente: inicio no puede ir después del fin.
_verr contains "excepcion: vigente_desde posterior a vigente_hasta" if {
	_hay_excepcion
	ns_desde := _ns(input.excepcion.vigente_desde)
	ns_hasta := _ns(input.excepcion.vigente_hasta)
	ns_desde > ns_hasta
}

_verr contains "excepcion.fuente_status: ausente o fuera de enum {FRESH,STALE,UNAVAILABLE}" if {
	_hay_excepcion
	not object.get(input.excepcion, ["fuente_status"], null) in estados_validos
}

_verr contains "excepcion.aprobada_por: ausente, no string o vacío" if {
	_hay_excepcion
	not _string_no_vacio(object.get(input.excepcion, ["aprobada_por"], null))
}

# --- Frescura propia de la excepción (paralela a la de la asignación) -------
# Con fuente_status FRESH/STALE, la excepción debe traer su propio timestamp y
# umbral, y el fuente_status no puede contradecir su edad real.
_exc_fuente_con_dato if object.get(input.excepcion, ["fuente_status"], null) in {"FRESH", "STALE"}

_verr contains "excepcion.fuente_timestamp: RFC3339 ausente o inválido (requerido si FRESH/STALE)" if {
	_hay_excepcion
	_exc_fuente_con_dato
	not es_rfc3339(object.get(input.excepcion, ["fuente_timestamp"], null))
}

_verr contains "excepcion.fuente_max_age_seconds: ausente o no número (requerido si FRESH/STALE)" if {
	_hay_excepcion
	_exc_fuente_con_dato
	not is_number(object.get(input.excepcion, ["fuente_max_age_seconds"], null))
}

_verr contains "excepcion.fuente_max_age_seconds: debe ser >= 0" if {
	_hay_excepcion
	is_number(object.get(input.excepcion, ["fuente_max_age_seconds"], null))
	input.excepcion.fuente_max_age_seconds < 0
}

_edad_excepcion_segundos := s if {
	ns_now := _ns(input.now)
	ns_ts := _ns(input.excepcion.fuente_timestamp)
	s := (ns_now - ns_ts) / 1000000000
}

_verr contains "excepcion.fuente_timestamp: está en el futuro (> now)" if {
	_hay_excepcion
	_exc_fuente_con_dato
	_edad_excepcion_segundos < 0
}

_verr contains "coherencia excepción: fuente_status=FRESH pero edad > fuente_max_age" if {
	_hay_excepcion
	object.get(input.excepcion, ["fuente_status"], null) == "FRESH"
	is_number(object.get(input.excepcion, ["fuente_max_age_seconds"], null))
	_edad_excepcion_segundos > input.excepcion.fuente_max_age_seconds
}

_verr contains "coherencia excepción: fuente_status=STALE pero edad <= fuente_max_age" if {
	_hay_excepcion
	object.get(input.excepcion, ["fuente_status"], null) == "STALE"
	is_number(object.get(input.excepcion, ["fuente_max_age_seconds"], null))
	_edad_excepcion_segundos <= input.excepcion.fuente_max_age_seconds
}

# Lista ordenada y estable para el output.
validation_errors := sort([e | some e in _verr])

input_valido if count(_verr) == 0

# -----------------------------------------------------------------------------
# Lógica de negocio (solo se evalúa sobre input válido)
# -----------------------------------------------------------------------------

fuente_disponible if input.resource.asignacion_status != "UNAVAILABLE"

# La acción solicitada debe estar en la lista de acciones ya autorizadas por el
# sistema corporativo (dato confiable del PEP). La política no calcula permisos.
accion_permitida if input.action in input.actor.acciones_permitidas

unidad_coincide if {
	input.resource.asignacion_status == "FRESH"
	input.actor.unidad == input.resource.unidad_asignada
}

# Excepción que apunta al actor/expediente/acción correctos y dentro de ventana
# (comparación por nanosegundos, robusta ante offsets horarios).
excepcion_basica_aplicable if {
	_hay_excepcion
	input.excepcion.actor_id == input.actor.id
	input.excepcion.expediente_id == input.resource.expediente_id
	input.action in input.excepcion.acciones_autorizadas
	ns_now := _ns(input.now)
	ns_desde := _ns(input.excepcion.vigente_desde)
	ns_hasta := _ns(input.excepcion.vigente_hasta)
	ns_now >= ns_desde
	ns_now <= ns_hasta
}

# Requisito unificado: una excepción solo es válida si ELLA MISMA está FRESH,
# con independencia de si la asignación está FRESH o STALE.
excepcion_valida if {
	excepcion_basica_aplicable
	input.excepcion.fuente_status == "FRESH"
}

excepcion_aplicable_y_valida if {
	input.resource.asignacion_status in {"FRESH", "STALE"}
	excepcion_valida
}

# -----------------------------------------------------------------------------
# outcome: decision + reason_code + execution_allowed SIEMPRE juntos.
# Ramas mutuamente excluyentes por construcción; `default` garantiza definición.
# -----------------------------------------------------------------------------

default outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_INVALID_INPUT",
	"execution_allowed": false,
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_INVALID_INPUT",
	"execution_allowed": false,
} if {
	not input_valido
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_ACTION_NOT_ALLOWED",
	"execution_allowed": false,
} if {
	input_valido
	not accion_permitida
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_SOURCE_UNAVAILABLE",
	"execution_allowed": false,
} if {
	input_valido
	accion_permitida
	not fuente_disponible
}

outcome := {
	"decision": "ALLOW",
	"reason_code": "RCI_ALLOW_UNIT_MATCH",
	"execution_allowed": true,
} if {
	input_valido
	accion_permitida
	fuente_disponible
	unidad_coincide
}

outcome := {
	"decision": "ALLOW_WITH_EXCEPTION",
	"reason_code": "RCI_ALLOW_EXCEPTION_APPLIED",
	"execution_allowed": true,
} if {
	input_valido
	accion_permitida
	fuente_disponible
	not unidad_coincide
	excepcion_aplicable_y_valida
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_UNIT_MISMATCH",
	"execution_allowed": false,
} if {
	input_valido
	accion_permitida
	fuente_disponible
	not unidad_coincide
	not excepcion_aplicable_y_valida
	input.resource.asignacion_status == "FRESH"
}

outcome := {
	"decision": "ESCALATE",
	"reason_code": "RCI_ESCALATE_STALE_ASSIGNMENT",
	"execution_allowed": false,
} if {
	input_valido
	accion_permitida
	fuente_disponible
	not unidad_coincide
	not excepcion_aplicable_y_valida
	input.resource.asignacion_status == "STALE"
}

# -----------------------------------------------------------------------------
# Señales derivadas
# -----------------------------------------------------------------------------

# id de la excepción efectivamente aplicada (solo en ALLOW_WITH_EXCEPTION).
default excepcion_id_aplicada := null

excepcion_id_aplicada := input.excepcion.id if {
	outcome.decision == "ALLOW_WITH_EXCEPTION"
}

# Señal de auditoría: se permitió por coincidencia directa de unidad PERO
# existía además una excepción básica aplicable al mismo actor/expediente/acción.
default excepcion_existente_no_utilizada := false

excepcion_existente_no_utilizada if {
	outcome.decision == "ALLOW"
	excepcion_basica_aplicable
}

# -----------------------------------------------------------------------------
# resultado: SIEMPRE definido. Los ecos de auditoría se SANEAN por tipo: se
# refleja el valor del input solo si tiene el tipo contractual; si no, null.
# Esto NO altera la decisión, el reason_code ni validation_errors: solo evita
# arrastrar valores mal tipados (p. ej. actor_id numérico) a los metadatos.
# -----------------------------------------------------------------------------

default _echo_actor_id := null

_echo_actor_id := v if {
	v := object.get(_root, ["actor", "id"], null)
	is_string(v)
}

default _echo_expediente_id := null

_echo_expediente_id := v if {
	v := object.get(_root, ["resource", "expediente_id"], null)
	is_string(v)
}

default _echo_asignacion_status := null

_echo_asignacion_status := v if {
	v := object.get(_root, ["resource", "asignacion_status"], null)
	v in estados_validos
}

default _echo_evaluated_at := null

_echo_evaluated_at := v if {
	v := object.get(_root, ["now"], null)
	is_string(v)
}

resultado := object.union(outcome, {
	"regla": "RCI-EXP-001",
	"actor_id": _echo_actor_id,
	"expediente_id": _echo_expediente_id,
	"asignacion_status": _echo_asignacion_status,
	"excepcion_id_aplicada": excepcion_id_aplicada,
	"excepcion_existente_no_utilizada": excepcion_existente_no_utilizada,
	"validation_errors": validation_errors,
	"evaluated_at": _echo_evaluated_at,
	"policy_version": policy_version,
})
