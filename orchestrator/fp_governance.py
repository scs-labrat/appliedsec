"""FP pattern governance — Story 14.4.

Two-person approval, 90-day expiry with reaffirmation, blast-radius
scoping, and rollback workflow for revoked patterns.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

EXPIRY_DAYS = 90


class GovernanceError(Exception):
    """Raised when a governance constraint is violated."""


class FPGovernanceManager:
    """Manages FP pattern governance lifecycle.

    - Two-person approval (distinct approvers required)
    - 90-day expiry with reaffirmation
    - Revocation with rollback of closed investigations
    """

    def __init__(self, audit_producer: Any | None = None) -> None:
        self._audit = audit_producer

    def approve(self, pattern: dict, approver: str) -> dict:
        """Record an approval on a pattern.

        First approver sets approved_by_1.
        Second (distinct) approver sets approved_by_2, computes expiry_date,
        and sets status to 'approved'.
        Same person twice raises GovernanceError.

        Returns the updated pattern dict.
        """
        approver_1 = pattern.get("approved_by_1", "")
        approver_2 = pattern.get("approved_by_2", "")

        if not approver_1:
            # First approval
            pattern["approved_by_1"] = approver
            pattern["status"] = "pending_review"
            return pattern

        if approver_1 == approver:
            raise GovernanceError(
                f"Same person '{approver}' cannot be both approver_1 and approver_2. "
                "Two-person approval requires distinct approvers."
            )

        if approver_2:
            raise GovernanceError(
                f"Pattern already has two approvals: "
                f"'{approver_1}' and '{approver_2}'"
            )

        # Second approval
        now = datetime.now(timezone.utc)
        pattern["approved_by_2"] = approver
        pattern["approval_date"] = now.isoformat()
        pattern["expiry_date"] = (now + timedelta(days=EXPIRY_DAYS)).isoformat()
        pattern["status"] = "approved"

        # H-06: Emit audit event on two-person approval
        if self._audit is not None:
            try:
                self._audit.emit(
                    event_type="fp_pattern.approved",
                    tenant_id=pattern.get("scope_tenant_id", ""),
                    data={
                        "pattern_id": pattern.get("pattern_id", ""),
                        "approved_by_1": approver_1,
                        "approved_by_2": approver,
                        "expiry_date": pattern["expiry_date"],
                    },
                )
            except Exception:
                logger.warning("Failed to emit fp_pattern.approved audit event", exc_info=True)

        return pattern

    def check_expiry(self, patterns: list[dict]) -> list[str]:
        """Return pattern_ids that have expired.

        A pattern is expired if:
        - expiry_date is set and in the past
        - status is not already 'expired' or 'revoked'
        """
        now = datetime.now(timezone.utc)
        expired_ids: list[str] = []

        for p in patterns:
            expiry_str = p.get("expiry_date", "")
            if not expiry_str:
                continue

            status = p.get("status", "")
            if status in ("expired", "revoked", "deprecated"):
                continue

            try:
                expiry_dt = datetime.fromisoformat(expiry_str)
                if expiry_dt.tzinfo is None:
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                if expiry_dt < now:
                    expired_ids.append(p.get("pattern_id", ""))
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid expiry_date for pattern %s: %s",
                    p.get("pattern_id", ""),
                    expiry_str,
                )

        return expired_ids

    def reaffirm(self, pattern: dict, reaffirmed_by: str) -> dict:
        """Extend a pattern's expiry by 90 days.

        Records reaffirmed_date and reaffirmed_by.
        Returns the updated pattern dict.
        """
        now = datetime.now(timezone.utc)
        pattern["reaffirmed_date"] = now.isoformat()
        pattern["reaffirmed_by"] = reaffirmed_by
        pattern["expiry_date"] = (now + timedelta(days=EXPIRY_DAYS)).isoformat()

        # If pattern was expired, re-activate it
        if pattern.get("status") == "expired":
            pattern["status"] = "approved"

        return pattern

    def revoke(
        self,
        pattern: dict,
        revoked_by: str,
        closed_investigations: list[str] | None = None,
    ) -> list[str]:
        """Revoke a pattern and return investigation_ids for re-opening.

        Sets status to 'revoked'.
        Returns list of investigation_ids that were closed by this pattern.
        """
        pattern["status"] = "revoked"
        pattern["revoked_by"] = revoked_by
        pattern["revoked_at"] = datetime.now(timezone.utc).isoformat()

        investigations = closed_investigations or []
        return investigations

    async def rollback_pattern(
        self,
        pattern_id: str,
        postgres_client: Any,
        audit_producer: Any | None = None,
    ) -> int:
        """Revoke a pattern and re-open investigations closed by it.

        Queries investigations with decision_chain containing
        {"action": "auto_close_fp", "pattern_id": pattern_id}.
        Re-opens by setting state to PARSING.

        Returns count of re-opened investigations.
        """
        # Query for investigations closed by this pattern
        query = """
            SELECT investigation_id, state, tenant_id
            FROM investigations
            WHERE state = 'CLOSED'
            AND classification = 'false_positive'
            AND decision_chain::text LIKE $1
        """
        pattern_marker = f'%"pattern_id": "{pattern_id}"%'

        rows = await postgres_client.fetch(query, pattern_marker)
        count = 0

        for row in rows:
            inv_id = row["investigation_id"]
            old_state = row["state"]
            row_tenant_id = row.get("tenant_id", "")
            update_query = """
                UPDATE investigations
                SET state = 'PARSING', updated_at = NOW()
                WHERE investigation_id = $1
            """
            await postgres_client.execute(update_query, inv_id)
            count += 1

            # Emit audit event
            producer = audit_producer or self._audit
            if producer is not None:
                try:
                    await producer.emit(
                        event_type="fp_pattern.revoked",
                        tenant_id=row_tenant_id,
                        data={
                            "pattern_id": pattern_id,
                            "investigation_id": inv_id,
                            "outcome": {
                                "state_before": old_state,
                                "state_after": "PARSING",
                            },
                        },
                    )
                except Exception:
                    logger.warning(
                        "Failed to emit fp_pattern.revoked audit event for %s",
                        inv_id,
                        exc_info=True,
                    )

        return count


def matches_scope(
    pattern: dict,
    alert_rule_family: str = "",
    alert_tenant_id: str = "",
    alert_asset_class: str = "",
) -> bool:
    """Check whether an alert falls within a pattern's blast-radius scope.

    Empty scope fields mean "global" — match everything.
    If a scope field is set, the alert must match it.
    """
    scope_rf = pattern.get("scope_rule_family", "")
    scope_tid = pattern.get("scope_tenant_id", "")
    scope_ac = pattern.get("scope_asset_class", "")

    if scope_rf and scope_rf != alert_rule_family:
        return False
    if scope_tid and scope_tid != alert_tenant_id:
        return False
    if scope_ac and scope_ac != alert_asset_class:
        return False

    return True
