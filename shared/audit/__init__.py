"""Shared audit library — re-exports AuditProducer."""

from shared.audit.producer import AuditProducer, build_llm_context, create_audit_producer

__all__ = ["AuditProducer", "build_llm_context", "create_audit_producer"]
