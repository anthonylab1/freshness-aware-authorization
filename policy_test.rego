package rci.exp001_test

import rego.v1

# -----------------------------------------------------------------------------
# Base fixtures — individual fields are overridden with nested object.union
# so partial overrides do not drop the rest of the resource.
# -----------------------------------------------------------------------------

base_input := {
	"actor": {"id": "u-001", "unit": "UNIDAD_A", "allowed_actions": ["leer", "modificar"]},
	"action": "leer",
	"resource": {
		"record_id": "exp-123",
		"assigned_unit": "UNIDAD_A",
		"assignment_status": "FRESH",
		"assignment_timestamp": "2026-06-28T10:00:00Z",
		"assignment_max_age_seconds": 3600,
	},
	"exception": null,
	"now": "2026-06-28T10:15:00Z",
}

# Valid exception (inside the window, with source_status FRESH and its own
# coherent freshness: age 15 min <= source_max_age 3600 s).
exception_valid := {
	"id": "exc-777",
	"actor_id": "u-001",
	"record_id": "exp-123",
	"authorised_actions": ["leer"],
	"valid_from": "2026-06-28T00:00:00Z",
	"valid_until": "2026-06-29T00:00:00Z",
	"source_status": "FRESH",
	"source_timestamp": "2026-06-28T10:00:00Z",
	"source_max_age_seconds": 3600,
	"approved_by": "responsable-x",
}

# Exception with a coherent STALE source: age 75 min > source_max_age 3600 s.
stale_exception := object.union(exception_valid, {
	"source_status": "STALE",
	"source_timestamp": "2026-06-28T09:00:00Z",
})

# Coherent STALE resource: the age (now - timestamp) exceeds max_age, so that
# STALE does not contradict the timestamp and raises no validation error.
stale_resource := object.union(base_input.resource, {
	"assignment_status": "STALE",
	"assignment_timestamp": "2026-06-28T09:00:00Z",
})

# =============================================================================
# 1. UNAVAILABLE -> DENY, regardless of anything else
# =============================================================================

test_unavailable_denies if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_status": "UNAVAILABLE"})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_SOURCE_UNAVAILABLE"
	r.execution_allowed == false
}

test_unavailable_denies_even_when_unit_matches if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_status": "UNAVAILABLE", "assigned_unit": "UNIDAD_A"})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
}

# =============================================================================
# 2. FRESH + unit matches -> ALLOW
# =============================================================================

test_fresh_unit_match_allows if {
	r := data.rci.exp001.result with input as base_input
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
	r.execution_allowed == true
	r.unused_exception_present == false
	r.applied_exception_id == null
}

test_fresh_unit_match_with_applicable_exception_flags_unused if {
	inp := object.union(base_input, {"exception": exception_valid})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW"
	r.unused_exception_present == true
	r.applied_exception_id == null # ALLOW by unit; the exception was NOT applied
}

test_fresh_unit_match_with_other_actor_exception_does_not_flag if {
	otra := object.union(exception_valid, {"actor_id": "u-999"})
	inp := object.union(base_input, {"exception": otra})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW"
	r.unused_exception_present == false
}

# =============================================================================
# 3. FRESH + unit does NOT match + valid exception -> ALLOW_WITH_EXCEPTION
# =============================================================================

test_fresh_unit_mismatch_with_valid_exception_allows_with_exception if {
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": exception_valid,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
	r.execution_allowed == true
	r.applied_exception_id == "exc-777"
}

test_exception_outside_window_does_not_apply if {
	vencida := object.union(exception_valid, {
		"valid_from": "2026-01-01T00:00:00Z",
		"valid_until": "2026-01-02T00:00:00Z",
	})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": vencida,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

test_exception_not_covering_action_does_not_apply if {
	otra_accion := object.union(exception_valid, {"authorised_actions": ["modificar"]})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": otra_accion,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

test_exception_for_other_record_does_not_apply if {
	otro_exp := object.union(exception_valid, {"record_id": "exp-OTRO"})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": otro_exp,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 4. FRESH + unit does NOT match + no valid exception -> DENY
# =============================================================================

test_fresh_unit_mismatch_without_exception_denies if {
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
	r.execution_allowed == false
}

# New requirement: the exception only compensates if IT IS ITSELF FRESH.
test_fresh_unit_mismatch_stale_exception_denies if {
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": stale_exception,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
	r.execution_allowed == false
}

test_fresh_unit_mismatch_unavailable_exception_denies if {
	exc_unavail := object.union(exception_valid, {"source_status": "UNAVAILABLE"})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"exception": exc_unavail,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 5. STALE + valid and FRESH exception -> ALLOW_WITH_EXCEPTION
# =============================================================================

test_stale_with_fresh_exception_allows_with_exception if {
	inp := object.union(base_input, {"resource": stale_resource, "exception": exception_valid})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
	r.execution_allowed == true
	r.applied_exception_id == "exc-777"
}

# =============================================================================
# 6. STALE + stale / expired exception -> ESCALATE (does not compensate)
# =============================================================================

test_stale_with_stale_exception_does_not_compensate_escalates if {
	inp := object.union(base_input, {"resource": stale_resource, "exception": stale_exception})
	r := data.rci.exp001.result with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
	r.execution_allowed == false
}

test_stale_with_expired_exception_escalates if {
	vencida := object.union(exception_valid, {
		"valid_from": "2026-01-01T00:00:00Z",
		"valid_until": "2026-01-02T00:00:00Z",
	})
	inp := object.union(base_input, {"resource": stale_resource, "exception": vencida})
	r := data.rci.exp001.result with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
}

# =============================================================================
# 7. STALE without exception -> ESCALATE, operation held
# =============================================================================

test_stale_without_exception_escalates_held if {
	inp := object.union(base_input, {"resource": stale_resource})
	r := data.rci.exp001.result with input as inp
	r.decision == "ESCALATE"
	r.reason_code == "RCI_ESCALATE_STALE_ASSIGNMENT"
	r.execution_allowed == false
}

# =============================================================================
# 8. Timestamps with time offsets (compared by instant, not by string)
# =============================================================================

# Exception window expressed in +02:00 which, compared as a string, would leave
# now=10:15Z outside; compared as an instant it contains it. The assignment
# timestamp also carries an offset and is coherent with FRESH.
test_time_offsets_in_window_allow_with_exception if {
	exc := object.union(exception_valid, {
		"valid_from": "2026-06-28T12:00:00+02:00", # == 10:00Z
		"valid_until": "2026-06-28T12:30:00+02:00", # == 10:30Z
	})
	inp := object.union(base_input, {
		"actor": {"id": "u-001", "unit": "UNIDAD_B"},
		"resource": object.union(base_input.resource, {"assignment_timestamp": "2026-06-28T12:00:00+02:00"}),
		"exception": exc,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
}

# =============================================================================
# 9. Exact validity bounds (window inclusive at both ends)
# =============================================================================

test_exact_valid_from_bound_is_inclusive if {
	exc := object.union(exception_valid, {"valid_from": base_input.now})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
}

test_exact_valid_until_bound_is_inclusive if {
	exc := object.union(exception_valid, {"valid_until": base_input.now})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
}

test_one_second_after_valid_until_denies if {
	exc := object.union(exception_valid, {"valid_until": "2026-06-28T10:14:59Z"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_UNIT_MISMATCH"
}

# =============================================================================
# 10. Invalid input -> always a structured result with RCI_DENY_INVALID_INPUT
# =============================================================================

test_invalid_status_is_invalid_input if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_status": "BOGUS"})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
}

test_missing_actor_id_is_invalid_input if {
	# object.union does a deep merge, so to OMIT actor.id the input is built
	# explicitly (without that key).
	inp := {
		"actor": {"unit": "UNIDAD_A"},
		"action": "leer",
		"resource": base_input.resource,
		"exception": null,
		"now": base_input.now,
	}
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_now_not_rfc3339_is_invalid_input if {
	inp := object.union(base_input, {"now": "no-es-una-fecha"})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_exception_with_invalid_timestamp_is_invalid_input if {
	exc := object.union(exception_valid, {"valid_until": "ayer"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# exception es obligatorio: la clave debe existir aunque valga null.
test_missing_exception_key_is_invalid_input if {
	inp := {
		"actor": base_input.actor,
		"action": base_input.action,
		"resource": base_input.resource,
		"now": base_input.now,
	}
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# A future assignment timestamp cannot be FRESH (it would be ALLOW without
# this validation, because the unit matches).
test_future_assignment_timestamp_is_invalid_input if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"assignment_status": "FRESH",
		"assignment_timestamp": "2026-06-28T11:00:00Z", # 45 min AFTER now
		"assignment_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_negative_max_age_is_invalid_input if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_max_age_seconds": -1})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# Exception freshness declared FRESH but contradicted by its timestamp:
# age 75 min > source_max_age 3600 s -> invalid input.
test_exception_freshness_contradicts_timestamp if {
	exc := object.union(exception_valid, {"source_timestamp": "2026-06-28T09:00:00Z"})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# --- Hardening 2.2.0 ----------------------------------------------------------

# The input root must be an object: null, string and array are invalid, and the
# result stays defined (it does not abort).
test_null_root_is_invalid_input if {
	r := data.rci.exp001.result with input as null
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
}

test_string_root_is_invalid_input if {
	r := data.rci.exp001.result with input as "texto"
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_array_root_is_invalid_input if {
	r := data.rci.exp001.result with input as [1, 2, 3]
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# A date with correct shape but impossible in the calendar (31 February). It
# must not abort even under --strict-builtin-errors.
test_impossible_date_in_now_is_invalid_input if {
	inp := object.union(base_input, {"now": "2026-02-31T10:15:00Z"})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_impossible_date_in_assignment_timestamp if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_timestamp": "2026-02-31T10:00:00Z"})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_february_29_non_leap_year_is_invalid if {
	inp := object.union(base_input, {"now": "2025-02-29T10:15:00Z"})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Inverted validity window.
test_valid_from_after_valid_until_is_invalid if {
	exc := object.union(exception_valid, {
		"valid_from": "2026-06-29T00:00:00Z",
		"valid_until": "2026-06-28T00:00:00Z",
	})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

# authorised_actions must be an array of NON-empty strings.
test_actions_with_empty_string_is_invalid if {
	exc := object.union(exception_valid, {"authorised_actions": ["leer", ""]})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_actions_with_non_string_element_is_invalid if {
	exc := object.union(exception_valid, {"authorised_actions": ["leer", 123]})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# --- Hardening 2.3.0: date representability and empty strings -----------------

# Years outside the range OPA can represent as int64 ns -> invalid input, and
# result ALWAYS defined (it does not abort, not even under --strict-builtin-errors).
test_year_9999_not_representable_is_invalid if {
	inp := object.union(base_input, {"now": "9999-12-31T23:59:59Z"})
	r := data.rci.exp001.result with input as inp
	is_object(r)
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
}

test_year_0000_not_representable_is_invalid if {
	inp := object.union(base_input, {"now": "0000-01-01T00:00:00Z"})
	r := data.rci.exp001.result with input as inp
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_assignment_timestamp_year_9999_is_invalid if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_timestamp": "9999-01-01T00:00:00Z"})})
	r := data.rci.exp001.result with input as inp
	is_object(r)
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Representable boundary (year 2261): processed normally.
test_year_2261_is_representable if {
	inp := object.union(base_input, {
		"now": "2261-01-01T00:00:00Z",
		"resource": object.union(base_input.resource, {"assignment_timestamp": "2261-01-01T00:00:00Z"}),
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
}

# Empty strings in required fields -> invalid input.
test_empty_actor_id_is_invalid if {
	inp := object.union(base_input, {"actor": {"id": "", "unit": "UNIDAD_A"}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_actor_unit_is_invalid if {
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": ""}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_action_is_invalid if {
	inp := object.union(base_input, {"action": ""})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_record_id_is_invalid if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"record_id": ""})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_assigned_unit_is_invalid if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assigned_unit": ""})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_exception_id_is_invalid if {
	exc := object.union(exception_valid, {"id": ""})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_exception_approved_by_is_invalid if {
	exc := object.union(exception_valid, {"approved_by": ""})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# =============================================================================
# 11. Status vs timestamp/max_age consistency detected by Rego
# =============================================================================

test_fresh_status_inconsistent_with_timestamp_and_max_age if {
	# age = 75 min = 4500 s > max_age 3600 s, but status says FRESH -> contradiction
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"assignment_status": "FRESH",
		"assignment_timestamp": "2026-06-28T09:00:00Z",
		"assignment_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_stale_status_inconsistent_with_timestamp_and_max_age if {
	# age = 15 min = 900 s <= max_age 3600 s, but status says STALE -> contradiction
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {
		"assignment_status": "STALE",
		"assignment_timestamp": "2026-06-28T10:00:00Z",
		"assignment_max_age_seconds": 3600,
	})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# =============================================================================
# 12. result ALWAYS defined (even with empty or garbage input)
# =============================================================================

test_result_always_defined_for_empty_input if {
	r := data.rci.exp001.result with input as {}
	is_object(r) # it is defined
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
}

# =============================================================================
# 13. Traceability metadata always present
# =============================================================================

test_result_includes_traceability_metadata if {
	r := data.rci.exp001.result with input as base_input
	r.rule == "RCI-EXP-001"
	r.policy_version == "4.0.0"
	r.evaluated_at == base_input.now
	r.actor_id == "u-001"
	r.record_id == "exp-123"
	r.assignment_status == "FRESH"
}

# --- Audit sanitisation 2.3.1: mistyped values -> null in the echoes, without
#     changing the decision or validation_errors ------------------------------

test_non_string_actor_id_is_sanitised_to_null if {
	inp := object.union(base_input, {"actor": {"id": 123, "unit": "UNIDAD_A"}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.actor_id == null
}

test_non_string_record_id_is_sanitised_to_null if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"record_id": 456})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.record_id == null
}

test_invalid_assignment_status_is_sanitised_to_null if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_status": "BOGUS"})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.assignment_status == null
}

test_non_string_evaluated_at_is_sanitised_to_null if {
	inp := object.union(base_input, {"now": 99999})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.evaluated_at == null
}

test_sanitisation_does_not_change_validation_errors if {
	inp := object.union(base_input, {"actor": {"id": 123, "unit": "UNIDAD_A"}})
	r := data.rci.exp001.result with input as inp
	count(r.validation_errors) > 0
	r.decision == "DENY"
	r.execution_allowed == false
}

# --- Additional coverage: invalid input cases not covered explicitly ----------
# All must give: DENY / RCI_DENY_INVALID_INPUT / exec false / errors>0 / result
# defined with every contractual field.

_required_fields_present(r) if {
	r.decision
	r.reason_code
	r.rule == "RCI-EXP-001"
	r.policy_version == "4.0.0"

	# keys present even when their value is null/false/[]
	object.get(r, "actor_id", "__NO__") != "__NO__"
	object.get(r, "record_id", "__NO__") != "__NO__"
	object.get(r, "assignment_status", "__NO__") != "__NO__"
	object.get(r, "applied_exception_id", "__NO__") != "__NO__"
	object.get(r, "unused_exception_present", "__NO__") != "__NO__"
	object.get(r, "evaluated_at", "__NO__") != "__NO__"
	is_boolean(r.execution_allowed)
	is_array(r.validation_errors)
}

test_numeric_root_is_invalid_input if {
	r := data.rci.exp001.result with input as 42
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_required_fields_present(r)
}

test_future_exception_source_timestamp_is_invalid if {
	exc := object.union(exception_valid, {"source_timestamp": "2026-06-28T11:00:00Z"}) # 45 min > now
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_required_fields_present(r)
}

test_negative_exception_source_max_age_is_invalid if {
	exc := object.union(exception_valid, {"source_max_age_seconds": -1})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_required_fields_present(r)
}

# source_status=STALE but the real age (5 min) corresponds to FRESH -> inconsistent.
test_stale_exception_source_with_fresh_age_is_invalid if {
	exc := object.union(exception_valid, {
		"source_status": "STALE",
		"source_timestamp": "2026-06-28T10:10:00Z",
	})
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_required_fields_present(r)
}

test_exception_actions_not_an_array_is_invalid if {
	exc := object.union(exception_valid, {"authorised_actions": "leer"}) # string, not an array
	inp := object.union(base_input, {"actor": {"id": "u-001", "unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	r.execution_allowed == false
	count(r.validation_errors) > 0
	_required_fields_present(r)
}

# =============================================================================
# 3.0.0 — Per-action authorization (actor.allowed_actions)
# =============================================================================

# Identical exception but without the `source_status` key (to test "missing").
exception_without_source_status := {k: exception_valid[k] |
	some k in object.keys(exception_valid)
	k != "source_status"
}

test_allowed_action_with_unit_match_allows if {
	r := data.rci.exp001.result with input as base_input
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
	r.execution_allowed == true
}

test_disallowed_action_denies if {
	inp := object.union(base_input, {"actor": {"allowed_actions": ["modificar"]}}) # "leer" is not there
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
	r.execution_allowed == false
}

test_allowed_action_via_exception_allows_with_exception if {
	inp := object.union(base_input, {
		"actor": {"unit": "UNIDAD_B", "allowed_actions": ["leer"]},
		"exception": exception_valid,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW_WITH_EXCEPTION"
	r.reason_code == "RCI_ALLOW_EXCEPTION_APPLIED"
}

# Even if the exception authorises "leer", if it is not in allowed_actions -> action DENY.
test_exception_cannot_grant_disallowed_action if {
	inp := object.union(base_input, {
		"actor": {"unit": "UNIDAD_B", "allowed_actions": ["modificar"]},
		"exception": exception_valid,
	})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
}

test_missing_allowed_actions_is_invalid if {
	inp := {
		"actor": {"id": "u-001", "unit": "UNIDAD_A"},
		"action": "leer",
		"resource": base_input.resource,
		"exception": null,
		"now": base_input.now,
	}
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
	count(r.validation_errors) > 0
}

test_allowed_actions_not_an_array_is_invalid if {
	inp := object.union(base_input, {"actor": {"allowed_actions": "leer"}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_allowed_actions_non_string_element_is_invalid if {
	inp := object.union(base_input, {"actor": {"allowed_actions": ["leer", 123]}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_allowed_actions_empty_element_is_invalid if {
	inp := object.union(base_input, {"actor": {"allowed_actions": ["leer", ""]}})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_empty_allowed_actions_denies_requested_action if {
	inp := object.union(base_input, {"actor": {"allowed_actions": []}})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_ACTION_NOT_ALLOWED"
}

# UNAVAILABLE takes precedence over exceptions (but the action check comes first).
test_unavailable_with_fresh_exception_still_source_unavailable if {
	res := object.union(base_input.resource, {"assignment_status": "UNAVAILABLE"})
	inp := object.union(base_input, {"actor": {"unit": "UNIDAD_B"}, "resource": res, "exception": exception_valid})
	r := data.rci.exp001.result with input as inp
	r.decision == "DENY"
	r.reason_code == "RCI_DENY_SOURCE_UNAVAILABLE"
}

test_exception_as_string_is_invalid if {
	inp := object.union(base_input, {"actor": {"unit": "UNIDAD_B"}, "exception": "no-soy-objeto"})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_missing_exception_source_status_is_invalid if {
	inp := object.union(base_input, {"actor": {"unit": "UNIDAD_B"}, "exception": exception_without_source_status})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_non_numeric_assignment_max_age_is_invalid if {
	inp := object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_max_age_seconds": "3600"})})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

test_non_numeric_exception_source_max_age_is_invalid if {
	exc := object.union(exception_valid, {"source_max_age_seconds": "3600"})
	inp := object.union(base_input, {"actor": {"unit": "UNIDAD_B"}, "exception": exc})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# max_age = 0: only an age of exactly 0 is FRESH (now == timestamp).
test_zero_max_age_with_zero_age_is_fresh_and_allows if {
	res := object.union(base_input.resource, {"assignment_max_age_seconds": 0, "assignment_timestamp": base_input.now})
	inp := object.union(base_input, {"resource": res})
	r := data.rci.exp001.result with input as inp
	r.decision == "ALLOW"
	r.reason_code == "RCI_ALLOW_UNIT_MATCH"
}

test_zero_max_age_with_positive_age_fresh_is_inconsistent if {
	# FRESH status with an age of 15 min but max_age 0 -> contradiction -> invalid.
	res := object.union(base_input.resource, {"assignment_max_age_seconds": 0})
	inp := object.union(base_input, {"resource": res})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Leap seconds :60 are not accepted by this contract.
test_leap_second_in_now_is_invalid if {
	inp := object.union(base_input, {"now": "2026-06-28T10:15:60Z"})
	r := data.rci.exp001.result with input as inp
	r.reason_code == "RCI_DENY_INVALID_INPUT"
}

# Every produced output has a coherent (decision, reason_code, execution_allowed) triple.
test_all_decision_triples_are_coherent if {
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
		object.union(base_input, {"actor": {"allowed_actions": ["modificar"]}}),
		object.union(base_input, {"resource": object.union(base_input.resource, {"assignment_status": "UNAVAILABLE"})}),
		object.union(base_input, {"actor": {"unit": "UNIDAD_B"}, "exception": exception_valid}),
		object.union(base_input, {"actor": {"unit": "UNIDAD_B"}}),
		object.union(base_input, {"resource": stale_resource}),
		{},
	]
	every inp in entradas {
		r := data.rci.exp001.result with input as inp
		[r.decision, r.reason_code, r.execution_allowed] in combos
	}
}
