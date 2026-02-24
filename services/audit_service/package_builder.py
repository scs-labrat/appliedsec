"""Evidence package builder — Story 13.6.

Assembles self-contained evidence packages from audit records.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from services.audit_service.chain import verify_chain
from services.audit_service.models import EvidencePackage


class EvidencePackageBuilder:
    """Builds evidence packages from audit records for an investigation."""

    def __init__(self, postgres_client: Any, evidence_store: Any = None) -> None:
        self._db = postgres_client
        self._evidence_store = evidence_store

    async def build_package(
        self,
        investigation_id: str,
        tenant_id: str,
        include_raw_prompts: bool = False,
    ) -> EvidencePackage:
        """Query audit_records for investigation, categorize, verify chain."""
        records = await self._db.fetch_many(
            "SELECT * FROM audit_records WHERE investigation_id = $1 "
            "AND tenant_id = $2 ORDER BY sequence_number",
            investigation_id,
            tenant_id,
        )

        events = [dict(r) for r in records]

        # Categorize events
        state_transitions = [e for e in events if e.get("event_type", "").startswith("investigation.")]
        llm_interactions = [e for e in events if "llm_" in json.dumps(e.get("context", {}))]
        actions = [e for e in events if e.get("event_type", "").startswith("response.")]
        approvals = [e for e in events if e.get("event_type", "").startswith("approval.")]
        retrieval = [e for e in events if e.get("context", {}).get("retrieval_stores_queried")]

        # Fetch raw prompts from S3 if requested
        if include_raw_prompts and self._evidence_store:
            for event in llm_interactions:
                refs = event.get("context", {}).get("evidence_refs", [])
                for ref in refs:
                    try:
                        content = await self._evidence_store.retrieve_evidence(ref)
                        event.setdefault("raw_evidence", {})[ref] = content.decode("utf-8", errors="replace")
                    except Exception:
                        pass

        # Verify chain
        chain_valid, chain_errors = verify_chain(events)

        # Extract final classification from last classify event
        classify_events = [e for e in events if e.get("event_type") == "alert.classified"]
        last_classify = classify_events[-1] if classify_events else {}
        decision = last_classify.get("decision", {}) if isinstance(last_classify.get("decision"), dict) else {}

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        pkg = EvidencePackage(
            package_id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            tenant_id=tenant_id,
            generated_at=now,
            events=events,
            state_transitions=state_transitions,
            retrieval_context=retrieval,
            llm_interactions=llm_interactions,
            final_classification=decision.get("classification", ""),
            final_confidence=decision.get("confidence", 0.0),
            final_severity=decision.get("severity_assigned", ""),
            reasoning_chain=[e.get("decision", {}).get("reasoning_summary", "") for e in events if e.get("decision", {}).get("reasoning_summary")],
            actions_executed=[e for e in actions if e.get("outcome", {}).get("outcome_status") == "success"],
            actions_pending=[e for e in actions if e.get("outcome", {}).get("outcome_status") == "pending_approval"],
            approvals=approvals,
            chain_verified=chain_valid,
            chain_verification_errors=chain_errors,
        )

        # Compute package hash
        pkg_dict = pkg.model_dump()
        pkg_dict.pop("package_hash", None)
        pkg.package_hash = hashlib.sha256(
            json.dumps(pkg_dict, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()

        return pkg
