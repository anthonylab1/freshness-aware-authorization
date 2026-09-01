package rci.exp001

import rego.v1

# =============================================================================
# RCI-EXP-001 — Procedural consistency for record access
#
# A purely declarative policy. Changes from 1.0.0 (see contract.md,
# section "Changelog 2.0.0"):
#
#   1. Any exception granting access requires `source_status == "FRESH"`,
#      with both FRESH and STALE assignments.
#   2. Instants (`now`, `valid_from`, `valid_until`, `assignment_timestamp`)
#      are compared as nanoseconds via `time.parse_rfc3339_ns`, never as
#      strings.
#   3. The policy ALWAYS returns a structured result. If the input does not
#      meet the contract -> DENY / RCI_DENY_INVALID_INPUT with
#      `validation_errors`.
#   4. `decision`, `reason_code` and `execution_allowed` are emitted together
#      in a single `outcome` object, so they cannot fall out of sync across
#      rules.
#   5. New `exception.id` in the input and `applied_exception_id` in the output.
#   6. Rego does NOT recompute the status, but it DOES detect contradictions
#      between `assignment_status`, `assignment_timestamp` and
#      `assignment_max_age_seconds`, and treats them as invalid input.
#
# Changes in 2.1.0:
#   7. `exception` is required: the KEY must exist even when its value is null.
#   8. New validations: `assignment_timestamp <= now` (no future values),
#      `assignment_max_age_seconds >= 0`.
#   9. Exception freshness is modelled like assignment freshness:
#      `exception.source_timestamp` + `exception.source_max_age_seconds`, and
#      `source_status` is validated against the real age.
#
# Changes in 2.2.0 (hardening):
#  10. The input root is validated to be an object (null/string/array ->
#      invalid).
#  11. Exceptions with `valid_from` later than `valid_until` are rejected.
#  12. `authorised_actions` must be an array of NON-empty strings.
#  13. Dates: calendar validation (for example 2026-02-31 is rejected) BEFORE
#      parsing. `time.parse_rfc3339_ns` only ever receives validated dates, so
#      the policy does not abort even under --strict-builtin-errors.
#
# Changes in 2.3.0 (hardening):
#  14. Representability: beyond shape and calendar, the year is limited to the
#      range OPA can represent as int64 nanoseconds (~1678..2261), and
#      `time.parse_rfc3339_ns` is required to actually return a number (`_ns`).
#      Non-representable dates (for example years 0000 or 9999) ->
#      RCI_DENY_INVALID_INPUT.
#  15. Empty strings are rejected in actor.id, actor.unit, action,
#      resource.record_id, resource.assigned_unit, and in the exception ids and
#      approved_by.
#
# Changes in 2.3.1 (audit echo sanitisation):
#  16. Audit echoes in the output (actor_id, record_id, assignment_status,
#      evaluated_at) are sanitised by type: the input value is reflected only
#      if it has the contractual type; otherwise null. This does not change the
#      decision, the reason_code or validation_errors.
#
# Changes in 3.0.0 (per-action authorization + trust boundary):
#  17. New actor.allowed_actions (array of non-empty strings, required): list
#      of actions already resolved by the corporate system (PEP data).
#  18. New decision DENY/RCI_DENY_ACTION_NOT_ALLOWED when the input is valid
#      but the action is not in actor.allowed_actions. Checked BEFORE unit and
#      exceptions: an exception cannot grant a disallowed action.
# =============================================================================

policy_version := "4.0.0"

# Closed enums reused in validation and logic.
valid_statuses := {"FRESH", "STALE", "UNAVAILABLE"}

# -----------------------------------------------------------------------------
# Pure helpers
# -----------------------------------------------------------------------------

# Safe root: if `input` is not an object (null, string, array, number...), we
# work over {} so no object.get fails and the result stays defined.
_root := input if is_object(input)

_root := {} if not is_object(input)

# RFC 3339 shape (date-time with `Z` or ±hh:mm offset). [0-9] is used instead of \d
# so as not to depend on the Perl classes of the regex engine.
_rfc3339_re := `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+][0-9]{2}:[0-9]{2}|[-][0-9]{2}:[0-9]{2})$`

# Days per month, with leap year handling for February.
_divisible(a, b) if a / b == floor(a / b)

_is_leap_year(y) if {
	_divisible(y, 4)
	not _divisible(y, 100)
}

_is_leap_year(y) if _divisible(y, 400)

_days_in_month(_, m) := 31 if m in {1, 3, 5, 7, 8, 10, 12}

_days_in_month(_, m) := 30 if m in {4, 6, 9, 11}

_days_in_month(y, m) := 29 if {
	m == 2
	_is_leap_year(y)
}

_days_in_month(y, m) := 28 if {
	m == 2
	not _is_leap_year(y)
}

# Reads integers by position without `to_number` (which in some engines rejects
# leading zeros such as "06"). _two_digits reads two digits; the year is two pairs.
_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_two_digits(s, pos) := (10 * _digit[substring(s, pos, 1)]) + _digit[substring(s, pos + 1, 1)]

_year(s) := (100 * _two_digits(s, 0)) + _two_digits(s, 2)

# Calendar validation from fixed positions (the shape is already guaranteed by
# the regex). Rejects impossible dates such as 2026-02-31 or 2026-13-01 WITHOUT parsing.
# The year is limited to the range OPA can represent as int64 nanoseconds
# (accepted range 1678..2261 inclusive): outside it time.parse_rfc3339_ns overflows.
_valid_calendar_date(s) if {
	anio := _year(s)
	mes := _two_digits(s, 5)
	dia := _two_digits(s, 8)
	anio >= 1678
	anio <= 2261
	mes >= 1
	mes <= 12
	dia >= 1
	dia <= _days_in_month(anio, mes)
	_two_digits(s, 11) <= 23
	_two_digits(s, 14) <= 59
	_two_digits(s, 17) <= 59
}

# Valid time offset: `Z`, or ±hh:mm with hh<=23 and mm<=59.
_valid_offset(s) if endswith(s, "Z")

_valid_offset(s) if {
	not endswith(s, "Z")
	n := count(s)
	_two_digits(s, n - 5) <= 23
	_two_digits(s, n - 2) <= 59
}

# Returns the string itself ONLY if it is a real RFC 3339 value (shape + calendar +
# offset). It is the only gate strings pass through before parsing, so that
# `time.parse_rfc3339_ns` never receives an impossible date and cannot abort,
# not even under --strict-builtin-errors.
_rfc3339_ok(s) := s if {
	is_string(s)
	regex.match(_rfc3339_re, s)
	_valid_calendar_date(s)
	_valid_offset(s)
}

# Nanoseconds of the instant, BUT only if the parse actually produces a number.
# Shape and calendar are not enough: we confirm OPA can represent the date.
# Otherwise `_ns` is undefined -> the field is marked invalid.
_ns(s) := n if {
	n := time.parse_rfc3339_ns(_rfc3339_ok(s))
	is_number(n)
}

# Convenience boolean for the validation checks.
is_rfc3339(s) if _ns(s)

# -----------------------------------------------------------------------------
# Input validation -> set `_verr` of error messages.
# Every check uses safe access (object.get with a default) so that a missing
# field produces a validation error instead of leaving the policy
# undefined.
# -----------------------------------------------------------------------------

# The input root must be a JSON object (not null, string, array or number).
_verr contains "input: root must be a JSON object" if {
	not is_object(input)
}

_verr contains "actor.id: missing, not a string, or empty" if {
	not _non_empty_string(object.get(_root, ["actor", "id"], null))
}

_verr contains "actor.unit: missing, not a string, or empty" if {
	not _non_empty_string(object.get(_root, ["actor", "unit"], null))
}

_verr contains "action: missing, not a string, or empty" if {
	not _non_empty_string(object.get(_root, ["action"], null))
}

_verr contains "actor.allowed_actions: missing or not an array" if {
	not is_array(object.get(_root, ["actor", "allowed_actions"], null))
}

_verr contains "actor.allowed_actions: must contain only non-empty strings" if {
	is_array(object.get(_root, ["actor", "allowed_actions"], null))
	some x in input.actor.allowed_actions
	not _non_empty_string(x)
}

_verr contains "resource.record_id: missing, not a string, or empty" if {
	not _non_empty_string(object.get(_root, ["resource", "record_id"], null))
}

_verr contains "resource.assignment_status: missing or outside enum {FRESH,STALE,UNAVAILABLE}" if {
	not object.get(_root, ["resource", "assignment_status"], null) in valid_statuses
}

_verr contains "resource.assignment_max_age_seconds: missing or not a number" if {
	not is_number(object.get(_root, ["resource", "assignment_max_age_seconds"], null))
}

_verr contains "resource.assignment_max_age_seconds: must be >= 0" if {
	is_number(object.get(_root, ["resource", "assignment_max_age_seconds"], null))
	input.resource.assignment_max_age_seconds < 0
}

_verr contains "now: RFC 3339 instant missing or invalid" if {
	not is_rfc3339(object.get(_root, ["now"], null))
}

# With FRESH/STALE the assignment data matters: unit and timestamp are required.
_status_has_data if object.get(_root, ["resource", "assignment_status"], null) in {"FRESH", "STALE"}

_verr contains "resource.assigned_unit: missing, not a string, or empty (required if FRESH/STALE)" if {
	_status_has_data
	not _non_empty_string(object.get(_root, ["resource", "assigned_unit"], null))
}

_verr contains "resource.assignment_timestamp: RFC 3339 missing or invalid (required if FRESH/STALE)" if {
	_status_has_data
	not is_rfc3339(object.get(_root, ["resource", "assignment_timestamp"], null))
}

# A future assignment timestamp cannot be considered FRESH/STALE.
_verr contains "resource.assignment_timestamp: is in the future (> now)" if {
	_status_has_data
	_age_seconds < 0
}

# --- Consistency of assignment_status vs (timestamp, max_age) ---------------
# Rego trusts the adapter for the STATUS, but rejects as invalid any input
# where the declared status contradicts the computed age. Convention:
# age <= max_age  => FRESH ;  age > max_age => STALE.

_age_seconds := s if {
	ns_now := _ns(input.now)
	ns_ts := _ns(input.resource.assignment_timestamp)
	s := (ns_now - ns_ts) / 1000000000
}

_verr contains "consistency: status=FRESH but age > max_age (the adapter should have marked it STALE)" if {
	input.resource.assignment_status == "FRESH"
	is_number(object.get(_root, ["resource", "assignment_max_age_seconds"], null))
	_age_seconds > input.resource.assignment_max_age_seconds
}

_verr contains "consistency: status=STALE but age <= max_age (the adapter should have marked it FRESH)" if {
	input.resource.assignment_status == "STALE"
	is_number(object.get(_root, ["resource", "assignment_max_age_seconds"], null))
	_age_seconds <= input.resource.assignment_max_age_seconds
}

# --- Exception validation (only when one is supplied) -----------------------

_has_exception if is_object(input.exception)

# `exception` is REQUIRED: the key must exist even when its value is null.
# The sentinel distinguishes "missing key" from "null value" (object.get with an
# existing path returns null; with a missing path it returns the default).
_verr contains "exception: required field missing (use null when there is no exception)" if {
	object.get(_root, ["exception"], "__AUSENTE__") == "__AUSENTE__"
}

_verr contains "exception: must be an object or null" if {
	input.exception != null
	not is_object(input.exception)
}

_verr contains "exception.id: missing, not a string, or empty" if {
	_has_exception
	not _non_empty_string(object.get(input.exception, ["id"], null))
}

_verr contains "exception.actor_id: missing, not a string, or empty" if {
	_has_exception
	not _non_empty_string(object.get(input.exception, ["actor_id"], null))
}

_verr contains "exception.record_id: missing, not a string, or empty" if {
	_has_exception
	not _non_empty_string(object.get(input.exception, ["record_id"], null))
}

_verr contains "exception.authorised_actions: missing or not an array" if {
	_has_exception
	not is_array(object.get(input.exception, ["authorised_actions"], null))
}

_non_empty_string(x) if {
	is_string(x)
	count(x) > 0
}

_verr contains "exception.authorised_actions: must contain only non-empty strings" if {
	_has_exception
	is_array(object.get(input.exception, ["authorised_actions"], null))
	some x in input.exception.authorised_actions
	not _non_empty_string(x)
}

_verr contains "exception.valid_from: RFC 3339 missing or invalid" if {
	_has_exception
	not is_rfc3339(object.get(input.exception, ["valid_from"], null))
}

_verr contains "exception.valid_until: RFC 3339 missing or invalid" if {
	_has_exception
	not is_rfc3339(object.get(input.exception, ["valid_until"], null))
}

# The validity window must be coherent: the start cannot come after the end.
_verr contains "exception: valid_from is later than valid_until" if {
	_has_exception
	ns_from := _ns(input.exception.valid_from)
	ns_until := _ns(input.exception.valid_until)
	ns_from > ns_until
}

_verr contains "exception.source_status: missing or outside enum {FRESH,STALE,UNAVAILABLE}" if {
	_has_exception
	not object.get(input.exception, ["source_status"], null) in valid_statuses
}

_verr contains "exception.approved_by: missing, not a string, or empty" if {
	_has_exception
	not _non_empty_string(object.get(input.exception, ["approved_by"], null))
}

# --- The exception's own freshness (parallel to the assignment's) -----------
# With source_status FRESH/STALE, the exception must carry its own timestamp and
# threshold, and source_status cannot contradict its real age.
_exception_source_has_data if object.get(input.exception, ["source_status"], null) in {"FRESH", "STALE"}

_verr contains "exception.source_timestamp: RFC 3339 missing or invalid (required if FRESH/STALE)" if {
	_has_exception
	_exception_source_has_data
	not is_rfc3339(object.get(input.exception, ["source_timestamp"], null))
}

_verr contains "exception.source_max_age_seconds: missing or not a number (required if FRESH/STALE)" if {
	_has_exception
	_exception_source_has_data
	not is_number(object.get(input.exception, ["source_max_age_seconds"], null))
}

_verr contains "exception.source_max_age_seconds: must be >= 0" if {
	_has_exception
	is_number(object.get(input.exception, ["source_max_age_seconds"], null))
	input.exception.source_max_age_seconds < 0
}

_exception_age_seconds := s if {
	ns_now := _ns(input.now)
	ns_ts := _ns(input.exception.source_timestamp)
	s := (ns_now - ns_ts) / 1000000000
}

_verr contains "exception.source_timestamp: is in the future (> now)" if {
	_has_exception
	_exception_source_has_data
	_exception_age_seconds < 0
}

_verr contains "exception consistency: source_status=FRESH but age > source_max_age" if {
	_has_exception
	object.get(input.exception, ["source_status"], null) == "FRESH"
	is_number(object.get(input.exception, ["source_max_age_seconds"], null))
	_exception_age_seconds > input.exception.source_max_age_seconds
}

_verr contains "exception consistency: source_status=STALE but age <= source_max_age" if {
	_has_exception
	object.get(input.exception, ["source_status"], null) == "STALE"
	is_number(object.get(input.exception, ["source_max_age_seconds"], null))
	_exception_age_seconds <= input.exception.source_max_age_seconds
}

# Sorted, stable list for the output.
validation_errors := sort([e | some e in _verr])

input_valid if count(_verr) == 0

# -----------------------------------------------------------------------------
# Business logic (only evaluated over valid input)
# -----------------------------------------------------------------------------

source_available if input.resource.assignment_status != "UNAVAILABLE"

# The requested action must be in the list of actions already authorised by the
# corporate system (trusted PEP data). The policy does not compute permissions.
action_allowed if input.action in input.actor.allowed_actions

unit_matches if {
	input.resource.assignment_status == "FRESH"
	input.actor.unit == input.resource.assigned_unit
}

# An exception pointing at the right actor/record/action and inside the window
# (nanosecond comparison, robust against time offsets).
exception_basically_applicable if {
	_has_exception
	input.exception.actor_id == input.actor.id
	input.exception.record_id == input.resource.record_id
	input.action in input.exception.authorised_actions
	ns_now := _ns(input.now)
	ns_from := _ns(input.exception.valid_from)
	ns_until := _ns(input.exception.valid_until)
	ns_now >= ns_from
	ns_now <= ns_until
}

# Unified requirement: an exception is only valid if IT IS ITSELF FRESH,
# regardless of whether the assignment is FRESH or STALE.
exception_valid if {
	exception_basically_applicable
	input.exception.source_status == "FRESH"
}

exception_applicable_and_valid if {
	input.resource.assignment_status in {"FRESH", "STALE"}
	exception_valid
}

# -----------------------------------------------------------------------------
# outcome: decision + reason_code + execution_allowed ALWAYS together.
# Mutually exclusive branches by construction; `default` guarantees definition.
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
	not input_valid
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_ACTION_NOT_ALLOWED",
	"execution_allowed": false,
} if {
	input_valid
	not action_allowed
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_SOURCE_UNAVAILABLE",
	"execution_allowed": false,
} if {
	input_valid
	action_allowed
	not source_available
}

outcome := {
	"decision": "ALLOW",
	"reason_code": "RCI_ALLOW_UNIT_MATCH",
	"execution_allowed": true,
} if {
	input_valid
	action_allowed
	source_available
	unit_matches
}

outcome := {
	"decision": "ALLOW_WITH_EXCEPTION",
	"reason_code": "RCI_ALLOW_EXCEPTION_APPLIED",
	"execution_allowed": true,
} if {
	input_valid
	action_allowed
	source_available
	not unit_matches
	exception_applicable_and_valid
}

outcome := {
	"decision": "DENY",
	"reason_code": "RCI_DENY_UNIT_MISMATCH",
	"execution_allowed": false,
} if {
	input_valid
	action_allowed
	source_available
	not unit_matches
	not exception_applicable_and_valid
	input.resource.assignment_status == "FRESH"
}

outcome := {
	"decision": "ESCALATE",
	"reason_code": "RCI_ESCALATE_STALE_ASSIGNMENT",
	"execution_allowed": false,
} if {
	input_valid
	action_allowed
	source_available
	not unit_matches
	not exception_applicable_and_valid
	input.resource.assignment_status == "STALE"
}

# -----------------------------------------------------------------------------
# Derived signals
# -----------------------------------------------------------------------------

# id of the exception actually applied (only in ALLOW_WITH_EXCEPTION).
default applied_exception_id := null

applied_exception_id := input.exception.id if {
	outcome.decision == "ALLOW_WITH_EXCEPTION"
}

# Audit signal: access was allowed by direct unit match BUT an applicable
# basic exception also existed for the same actor/record/action.
default unused_exception_present := false

unused_exception_present if {
	outcome.decision == "ALLOW"
	exception_basically_applicable
}

# -----------------------------------------------------------------------------
# result: ALWAYS defined. Audit echoes are SANITISED by type: the input
# value is reflected only if it has the contractual type; otherwise null.
# This does NOT change the decision, reason_code or validation_errors: it only
# avoids dragging mistyped values (for example a numeric actor_id) into metadata.
# -----------------------------------------------------------------------------

default _echo_actor_id := null

_echo_actor_id := v if {
	v := object.get(_root, ["actor", "id"], null)
	is_string(v)
}

default _echo_record_id := null

_echo_record_id := v if {
	v := object.get(_root, ["resource", "record_id"], null)
	is_string(v)
}

default _echo_assignment_status := null

_echo_assignment_status := v if {
	v := object.get(_root, ["resource", "assignment_status"], null)
	v in valid_statuses
}

default _echo_evaluated_at := null

_echo_evaluated_at := v if {
	v := object.get(_root, ["now"], null)
	is_string(v)
}

result := object.union(outcome, {
	"rule": "RCI-EXP-001",
	"actor_id": _echo_actor_id,
	"record_id": _echo_record_id,
	"assignment_status": _echo_assignment_status,
	"applied_exception_id": applied_exception_id,
	"unused_exception_present": unused_exception_present,
	"validation_errors": validation_errors,
	"evaluated_at": _echo_evaluated_at,
	"policy_version": policy_version,
})
