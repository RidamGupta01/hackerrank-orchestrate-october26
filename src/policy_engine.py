"""Deterministic interpreter for the supplied deletion policy table."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping


class PolicyAction(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class ConditionOutcome(str, Enum):
    APPLIES = "APPLIES"
    DOES_NOT_APPLY = "DOES_NOT_APPLY"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: PolicyAction | None
    unresolved_mapping_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "data_category": self.data_category,
            "condition": self.condition,
            "required_action": self.required_action.value if self.required_action else None,
            "unresolved_mapping_reason": self.unresolved_mapping_reason,
        }


@dataclass(frozen=True)
class PolicyDecision:
    rule_id: str | None
    data_category: str
    condition: str | None
    condition_outcome: ConditionOutcome
    required_action: PolicyAction | None
    decision: str
    reason: str
    required_identifier_removal: tuple[str, ...]
    permitted_identifier_types: tuple[str, ...]
    preserve_record: bool
    required_process_state: str | None
    unresolved_policy: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "data_category": self.data_category,
            "condition": self.condition,
            "condition_outcome": self.condition_outcome.value,
            "required_action": self.required_action.value if self.required_action else None,
            "decision": self.decision,
            "reason": self.reason,
            "required_identifier_removal": list(self.required_identifier_removal),
            "permitted_identifier_types": list(self.permitted_identifier_types),
            "preserve_record": self.preserve_record,
            "required_process_state": self.required_process_state,
            "unresolved_policy": self.unresolved_policy,
        }


_FIELD_ALIASES: dict[str, set[str]] = {
    "rule_id": {"ruleid", "id", "policyid"},
    "data_category": {"datacategory", "category", "recordcategory", "resourcecategory"},
    "condition": {"condition", "policycondition", "when", "applicabilitycondition"},
    "required_action": {"requiredaction", "action", "treatment", "requiredtreatment"},
}
_IDENTIFYING_FIELDS = ("name", "email", "phone", "email_hash", "user_id")
_CONDITION_FACTS = {
    "conversation contains shared customer agent or order context that must be retained":
        ("shared_context_must_be_retained",),
    "attachment belongs only to the deletion subject": ("attachment_belongs_only_to_subject",),
    "record is still attributable to a user": ("record_attributable_to_user",),
    "log contains a user email address": ("log_contains_user_email",),
    "record is within the supplied retention period": ("within_retention_period",),
    "a supplied legal hold is active": ("legal_hold_active",),
    "restore access can be blocked": ("restore_access_can_be_blocked",),
    (
        "account is deleted and only a stable internal user_id is needed "
        "to preserve references to retained records"
    ): ("account_deleted", "stable_user_id_needed_for_retained_references"),
}


class PolicyEngine:
    """Load policy rows dynamically and fail closed on unknown mappings."""

    def __init__(self, rows: Iterable[Mapping[str, str]]) -> None:
        self.rules = tuple(self._parse_rule(row, number) for number, row in enumerate(rows, 1))
        self._by_category: dict[str, PolicyRule] = {}
        for rule in self.rules:
            key = _normalize_category(rule.data_category)
            if key in self._by_category:
                raise ValueError(f"duplicate policy category: {rule.data_category}")
            self._by_category[key] = rule

    @classmethod
    def from_csv(cls, path: str | Path) -> PolicyEngine:
        with Path(path).open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None:
                raise ValueError("deletion policy file is missing a header")
            columns = _resolve_columns(reader.fieldnames)
            rows: list[dict[str, str]] = []
            for row in reader:
                rows.append(
                    {
                        semantic: str(row.get(column, "") or "")
                        for semantic, column in columns.items()
                    }
                )
        return cls(rows)

    def evaluate(
        self,
        data_category: str,
        *,
        facts: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        rule = self._by_category.get(_normalize_category(data_category))
        if rule is None:
            return _unresolved_decision(
                data_category,
                "No supplied policy rule maps to this data category.",
            )
        if rule.unresolved_mapping_reason:
            return _unresolved_decision(
                data_category,
                rule.unresolved_mapping_reason,
                rule=rule,
            )
        if rule.required_action is None:
            return _unresolved_decision(
                data_category,
                "The policy action is absent or not one of the supported actions.",
                rule=rule,
            )
        context = facts or {}
        outcome = _evaluate_condition(rule.condition, context)
        if outcome is ConditionOutcome.UNRESOLVED:
            return PolicyDecision(
                rule.rule_id,
                rule.data_category,
                rule.condition,
                outcome,
                rule.required_action,
                "UNRESOLVED",
                "Required facts for the supplied policy condition are missing or ambiguous.",
                (),
                (),
                rule.required_action is PolicyAction.RETAIN,
                None,
                True,
            )
        if outcome is ConditionOutcome.DOES_NOT_APPLY:
            return PolicyDecision(
                rule.rule_id,
                rule.data_category,
                rule.condition,
                outcome,
                rule.required_action,
                "NO_OBLIGATION",
                "The supplied policy condition was established as not applicable.",
                (),
                (),
                False,
                None,
                False,
            )

        tombstone = _is_tombstone_exception(rule)
        removed_fields: tuple[str, ...] = ()
        permitted: tuple[str, ...] = ()
        if rule.required_action in {PolicyAction.REDACT, PolicyAction.ANONYMIZE}:
            removed_fields = (
                ("name", "email", "phone", "email_hash")
                if tombstone
                else _IDENTIFYING_FIELDS
            )
        if tombstone:
            permitted = ("user_id",)
        return PolicyDecision(
            rule.rule_id,
            rule.data_category,
            rule.condition,
            outcome,
            rule.required_action,
            "APPLIES",
            "The supplied policy condition is established.",
            removed_fields,
            permitted,
            rule.required_action is PolicyAction.RETAIN,
            "BLOCKED" if rule.data_category.casefold() == "backup_archive" else None,
            False,
        )

    def evaluate_record(
        self,
        data_category: str | None,
        *,
        facts: Mapping[str, Any] | None = None,
    ) -> PolicyDecision:
        if not data_category or not data_category.strip():
            return _unresolved_decision(
                data_category or "",
                "The evidence record has no data category for policy lookup.",
            )
        return self.evaluate(data_category, facts=facts)

    @staticmethod
    def _parse_rule(row: Mapping[str, str], row_number: int) -> PolicyRule:
        normalized = {str(key): str(value or "").strip() for key, value in row.items()}
        missing = [
            field
            for field in ("rule_id", "data_category", "condition", "required_action")
            if not normalized.get(field)
        ]
        if missing:
            raise ValueError(
                f"policy row {row_number} is missing fields: {', '.join(missing)}"
            )
        action_text = normalized["required_action"].upper()
        try:
            action: PolicyAction | None = PolicyAction(action_text)
            unresolved_reason = None
        except ValueError:
            action = None
            unresolved_reason = f"Unsupported policy action: {action_text}"
        return PolicyRule(
            normalized["rule_id"],
            normalized["data_category"],
            normalized["condition"],
            action,
            unresolved_reason,
        )


def _resolve_columns(headers: Iterable[str]) -> dict[str, str]:
    available: dict[str, list[str]] = {}
    for header in headers:
        normalized = _normalize_header(header)
        for semantic, aliases in _FIELD_ALIASES.items():
            if normalized in aliases:
                available.setdefault(semantic, []).append(header)
    unresolved = [
        semantic for semantic in _FIELD_ALIASES if len(available.get(semantic, [])) != 1
    ]
    if unresolved:
        raise ValueError(
            "policy columns are missing or ambiguous for: " + ", ".join(unresolved)
        )
    return {semantic: matches[0] for semantic, matches in available.items()}


def _normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _normalize_condition(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9_]+", " ", value.casefold()).split())


def _evaluate_condition(
    condition: str,
    facts: Mapping[str, Any],
) -> ConditionOutcome:
    normalized = _normalize_condition(condition)
    if normalized == "always":
        return ConditionOutcome.APPLIES
    required_facts = _CONDITION_FACTS.get(normalized)
    if required_facts is None:
        return ConditionOutcome.UNRESOLVED
    values = [facts.get(key) for key in required_facts]
    if any(value is False for value in values):
        return ConditionOutcome.DOES_NOT_APPLY
    if any(not isinstance(value, bool) for value in values):
        return ConditionOutcome.UNRESOLVED
    applies = all(values)
    return (
        ConditionOutcome.APPLIES
        if applies
        else ConditionOutcome.DOES_NOT_APPLY
    )


def _is_tombstone_exception(rule: PolicyRule) -> bool:
    return (
        _normalize_category(rule.data_category) == "accounttombstone"
        and _normalize_condition(rule.condition)
        == _normalize_condition(
            "Account is deleted and only a stable internal user_id is needed "
            "to preserve references to retained records"
        )
        and rule.required_action is PolicyAction.REDACT
    )


def _unresolved_decision(
    category: str,
    reason: str,
    *,
    rule: PolicyRule | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        rule.rule_id if rule else None,
        category,
        rule.condition if rule else None,
        ConditionOutcome.UNRESOLVED,
        rule.required_action if rule else None,
        "UNRESOLVED",
        reason,
        (),
        (),
        False,
        None,
        True,
    )


def _normalize_category(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())
