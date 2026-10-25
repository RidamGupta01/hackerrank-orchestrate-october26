# Policy enforcement and state reconstruction

## Policy engine

`src.policy_engine.PolicyEngine` loads the supplied rules CSV at runtime:

```python
from src.policy_engine import PolicyEngine

policy = PolicyEngine.from_csv("dataset/deletion_rules.csv")
decision = policy.evaluate(
    "SECURITY_AUDIT_LOG",
    facts={"within_retention_period": True},
)
```

The loader resolves the four semantic fields (rule ID, category, condition,
and required action) from recognized header names and does not depend on CSV
column order. Duplicate categories, missing or ambiguous columns, and
malformed rows are rejected. Policy actions are restricted to the supplied
`DELETE`, `REDACT`, `ANONYMIZE`, and `RETAIN` values. Unknown categories,
actions, or conditions produce an explicit unresolved decision; no fallback
policy is inferred.

Conditions are evaluated deterministically from explicit boolean facts. A
missing fact remains unresolved. Facts are named for the underlying condition
(for example, `legal_hold_active`, `within_retention_period`, or
`restore_access_can_be_blocked`); the state reconstructor can establish
attribution and a user-email-in-log fact from matched evidence identifiers.
Callers must provide other context, such as shared support context or an
active legal hold, from evidence. A false conjunct makes an `all` condition
not applicable; unsupported or incomplete conditions do not succeed.

The loaded dataset mappings were verified from `dataset/deletion_rules.csv`:

| Rule | Category | Condition summary | Action |
|---|---|---|---|
| `rule_01` | `USER_PROFILE` | Always | `DELETE` |
| `rule_02` | `SECONDARY_IDENTIFIER` | Always | `DELETE` |
| `rule_03` | `SEARCH_INDEX_ENTRY` | Always | `DELETE` |
| `rule_04` | `CACHE_ENTRY` | Always | `DELETE` |
| `rule_05` | `SUPPORT_MESSAGE` | Shared customer/agent/order context must be retained | `REDACT` |
| `rule_06` | `SUPPORT_ATTACHMENT` | Attachment belongs only to the deletion subject | `DELETE` |
| `rule_07` | `ANALYTICS_PROFILE` | Still attributable to a user | `ANONYMIZE` |
| `rule_08` | `PRODUCT_TELEMETRY` | Still attributable to a user | `ANONYMIZE` |
| `rule_09` | `USER_EXPORT` | Always | `DELETE` |
| `rule_10` | `MARKETING_PROFILE` | Always | `DELETE` |
| `rule_11` | `EMAIL_DELIVERY_LOG` | Contains the user's email address | `REDACT` |
| `rule_12` | `SECURITY_AUDIT_LOG` | Within supplied retention period | `RETAIN` |
| `rule_13` | `LEGAL_HOLD_RECORD` | Supplied legal hold is active | `RETAIN` |
| `rule_14` | `BACKUP_ARCHIVE` | Restore access can be blocked | `RETAIN` |
| `rule_15` | `ACCOUNT_TOMBSTONE` | Deleted account needs stable `user_id` references only | `REDACT` |

For redaction/anonymization, decisions enumerate identifying field types
requiring removal, including `email_hash`. `ACCOUNT_TOMBSTONE` is the
policy-specific exception: the stable `user_id` is permitted when its exact
condition applies; direct identifiers and `email_hash` remain required to be
removed. These requirements describe what the state reconstructor must
verify; a policy decision alone is not evidence that treatment occurred.

## State reconstruction

`src.state_reconstructor.StateReconstructor` accepts one identity result,
its normalized evidence, the matching activity report, an explicit
authorization assessment, and optional evidence-backed condition facts.
The activity report cutoff must exactly match the identity result's `audit_at`.
The caller must separately determine whether deletion was requested; the
engine does not infer authorization from workflow status.

The main input models are:

- `AuthorizationAssessment`: `REQUESTED`, `NOT_REQUESTED`, or `UNKNOWN`, with
  source evidence IDs and an explanation. `NOT_APPLICABLE` is returned only
  when non-request is supported by provenance.
- `PolicyDecision`: rule, action, condition outcome, identifier removal
  requirements, permitted identifier types, retention flag, and unresolved
  mapping status.
- `EvidenceObservation`: the shared provenance contract documented in
  [evidence investigation](./evidence_investigation.md).
- `ActivityReport`: identity-linked events and cutoff-aware process
  assessments documented in [activity and restore analysis](./activity_and_restore_analysis.md).

Each resource is grouped by its supplied system, resource, and category IDs.
Only confirmed identity-linked observations are considered. A file captured
exactly at `audit_at` can establish the snapshot state at that cutoff even
when its record's own update timestamp is older. Older snapshots remain
historical and cannot prove the state at `audit_at`; later observations are
excluded. Operation-attempt observations cannot establish a result. Conflicting
states in cutoff evidence fail the resource condition.

For `DELETE`, explicit `ABSENT` state at the cutoff is required. For
`REDACT`/`ANONYMIZE`, the expected explicit state and removed-field evidence
must cover all policy-required identifiers, and any remaining matched
identifiers fail the condition. For `RETAIN`, explicit `PRESENT` state is
required. Missing resource evidence is unresolved, not absent. Historical
claims and reported activity results do not establish current state.

`DATA_FLOW` and `RESTORE_PATH` process assessments create mandatory
recreation-prevention conditions: cutoff-valid `DISABLED`/`BLOCKED` satisfies
the condition; `ACTIVE`/`RESTORABLE` fails it; unknown or historical state is
unresolved. For a retained backup, the engine separately requires a
cutoff-valid `BLOCKED` or `RESTORABLE` backup assessment to establish backup
presence; `RESTORABLE` still fails the separate recreation-prevention
condition. If no identity-linked flow or restore-path assessment exists, path
coverage is unresolved rather than assumed safe. Activity events only
corroborate provenance and are not treated as proof of operation results.

The final result is:

- `COMPLETE` only when every generated mandatory condition is satisfied or
  explicitly not applicable.
- `INCOMPLETE` when a mandatory condition fails or is unresolved.
- `NOT_APPLICABLE` only for an evidenced `NOT_REQUESTED` authorization.

Every condition carries a reason and available evidence/activity provenance.
The engine does not generate remediation steps or the final submission CSV.
