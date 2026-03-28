"""Playbook Browser routes — library of SOC response playbooks.

Provides a browsable card-grid of playbooks with filtering, detail
expansion showing ordered step lists, and JSON API endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

DEMO_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "playbook_id": "PB-001",
        "name": "Ransomware Containment",
        "description": "Immediate containment and eradication procedure for ransomware incidents targeting endpoints and file servers.",
        "severity": "critical",
        "tactics": ["impact", "execution"],
        "steps": [
            {"step": 1, "action": "isolate_host", "description": "Network-isolate all affected hosts via EDR policy push", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 2, "action": "snapshot_vm", "description": "Capture forensic VM snapshots before remediation", "automated": True, "requires_approval": False, "timeout": "10m"},
            {"step": 3, "action": "collect_forensics", "description": "Collect memory dumps, prefetch, and MFT from isolated hosts", "automated": True, "requires_approval": False, "timeout": "30m"},
            {"step": 4, "action": "block_ip", "description": "Block C2 IPs and domains at perimeter firewall and DNS sinkhole", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 5, "action": "scan_endpoints", "description": "Run full IOC sweep across all endpoints in the affected VLAN", "automated": True, "requires_approval": False, "timeout": "60m"},
            {"step": 6, "action": "escalate_to_l3", "description": "Escalate to L3 / IR team with full evidence package", "automated": False, "requires_approval": True, "timeout": "15m"},
        ],
        "times_used": 47,
        "avg_execution_time": "2h 15m",
        "success_rate": 91.5,
        "last_used": "2026-03-27",
        "status": "active",
    },
    {
        "playbook_id": "PB-002",
        "name": "Phishing Response",
        "description": "Triage and response workflow for reported phishing emails including credential compromise assessment.",
        "severity": "high",
        "tactics": ["initial-access"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Extract email headers, URLs, and attachments for analysis", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 2, "action": "block_ip", "description": "Block sender domain and extracted malicious URLs at mail gateway", "automated": True, "requires_approval": False, "timeout": "3m"},
            {"step": 3, "action": "scan_endpoints", "description": "Scan recipient endpoints for payload execution indicators", "automated": True, "requires_approval": False, "timeout": "20m"},
            {"step": 4, "action": "disable_account", "description": "Force password reset for users who clicked links or opened attachments", "automated": False, "requires_approval": True, "timeout": "15m"},
            {"step": 5, "action": "notify_team", "description": "Send org-wide phishing advisory with IOCs to security awareness channel", "automated": True, "requires_approval": False, "timeout": "5m"},
        ],
        "times_used": 132,
        "avg_execution_time": "45m",
        "success_rate": 96.2,
        "last_used": "2026-03-28",
        "status": "active",
    },
    {
        "playbook_id": "PB-003",
        "name": "Lateral Movement Investigation",
        "description": "Deep investigation workflow for detected lateral movement patterns including credential harvesting and RDP/SMB abuse.",
        "severity": "high",
        "tactics": ["lateral-movement", "discovery"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Gather authentication logs, RDP session data, and SMB access logs", "automated": True, "requires_approval": False, "timeout": "10m"},
            {"step": 2, "action": "scan_endpoints", "description": "Run credential dumping detection across all domain controllers", "automated": True, "requires_approval": False, "timeout": "30m"},
            {"step": 3, "action": "isolate_host", "description": "Isolate the source host exhibiting lateral movement behaviour", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 4, "action": "revoke_tokens", "description": "Revoke all Kerberos tickets and active sessions for compromised accounts", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 5, "action": "disable_account", "description": "Disable compromised service and user accounts pending investigation", "automated": False, "requires_approval": True, "timeout": "10m"},
            {"step": 6, "action": "collect_forensics", "description": "Map complete lateral movement path via graph analysis of auth logs", "automated": True, "requires_approval": False, "timeout": "45m"},
            {"step": 7, "action": "escalate_to_l3", "description": "Escalate with full attack path visualization to L3 threat hunting team", "automated": False, "requires_approval": False, "timeout": "15m"},
        ],
        "times_used": 28,
        "avg_execution_time": "3h 30m",
        "success_rate": 85.7,
        "last_used": "2026-03-25",
        "status": "active",
    },
    {
        "playbook_id": "PB-004",
        "name": "Insider Threat Escalation",
        "description": "Escalation procedure for confirmed insider threat indicators including data staging, unusual access, and policy violations.",
        "severity": "critical",
        "tactics": ["collection", "exfiltration"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Pull DLP alerts, file access logs, and USB activity for the suspect user", "automated": True, "requires_approval": False, "timeout": "15m"},
            {"step": 2, "action": "snapshot_vm", "description": "Snapshot user workstation and any accessed file servers", "automated": True, "requires_approval": True, "timeout": "10m"},
            {"step": 3, "action": "notify_team", "description": "Alert insider threat investigation team and legal/HR stakeholders", "automated": False, "requires_approval": True, "timeout": "10m"},
            {"step": 4, "action": "disable_account", "description": "Disable user account and revoke VPN/remote access credentials", "automated": False, "requires_approval": True, "timeout": "5m"},
            {"step": 5, "action": "create_ticket", "description": "Create formal insider threat case with chain-of-custody documentation", "automated": True, "requires_approval": False, "timeout": "5m"},
        ],
        "times_used": 8,
        "avg_execution_time": "1h 45m",
        "success_rate": 87.5,
        "last_used": "2026-03-15",
        "status": "active",
    },
    {
        "playbook_id": "PB-005",
        "name": "Cloud IAM Compromise",
        "description": "Response to compromised cloud IAM credentials including role escalation, unauthorized resource creation, and persistence mechanisms.",
        "severity": "critical",
        "tactics": ["privilege-escalation", "persistence"],
        "steps": [
            {"step": 1, "action": "revoke_tokens", "description": "Immediately revoke all active sessions and API keys for the compromised identity", "automated": True, "requires_approval": False, "timeout": "2m"},
            {"step": 2, "action": "collect_forensics", "description": "Pull CloudTrail/Activity logs for the last 72 hours for the identity", "automated": True, "requires_approval": False, "timeout": "10m"},
            {"step": 3, "action": "disable_account", "description": "Disable IAM user/role and rotate all associated access keys", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 4, "action": "scan_endpoints", "description": "Audit all resources created or modified by the compromised identity", "automated": True, "requires_approval": False, "timeout": "30m"},
            {"step": 5, "action": "block_ip", "description": "Block source IPs from CloudTrail in WAF and security groups", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 6, "action": "escalate_to_l3", "description": "Escalate to cloud security team with resource audit and blast radius assessment", "automated": False, "requires_approval": False, "timeout": "15m"},
        ],
        "times_used": 19,
        "avg_execution_time": "1h 30m",
        "success_rate": 94.7,
        "last_used": "2026-03-26",
        "status": "active",
    },
    {
        "playbook_id": "PB-006",
        "name": "Malware Triage",
        "description": "Standard triage for endpoint malware detections including automated sandboxing and IOC extraction.",
        "severity": "medium",
        "tactics": ["execution", "defense-evasion"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Retrieve malware sample and execution artifacts from endpoint", "automated": True, "requires_approval": False, "timeout": "10m"},
            {"step": 2, "action": "scan_endpoints", "description": "Submit sample to sandbox and extract behavioural IOCs", "automated": True, "requires_approval": False, "timeout": "20m"},
            {"step": 3, "action": "block_ip", "description": "Block extracted network IOCs at perimeter and update threat intel feed", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 4, "action": "create_ticket", "description": "Create triage report with verdict and recommended follow-up actions", "automated": True, "requires_approval": False, "timeout": "5m"},
        ],
        "times_used": 215,
        "avg_execution_time": "35m",
        "success_rate": 97.2,
        "last_used": "2026-03-28",
        "status": "active",
    },
    {
        "playbook_id": "PB-007",
        "name": "DDoS Mitigation",
        "description": "Rapid mitigation of volumetric and application-layer DDoS attacks against public-facing infrastructure.",
        "severity": "high",
        "tactics": ["impact"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Capture traffic sample and classify attack vector (volumetric, protocol, app-layer)", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 2, "action": "block_ip", "description": "Enable upstream DDoS scrubbing and deploy rate-limiting rules", "automated": True, "requires_approval": True, "timeout": "3m"},
            {"step": 3, "action": "notify_team", "description": "Notify NOC and stakeholders of active DDoS and mitigation status", "automated": True, "requires_approval": False, "timeout": "2m"},
            {"step": 4, "action": "create_ticket", "description": "Document attack characteristics, mitigation timeline, and impact assessment", "automated": True, "requires_approval": False, "timeout": "10m"},
        ],
        "times_used": 34,
        "avg_execution_time": "25m",
        "success_rate": 94.1,
        "last_used": "2026-03-22",
        "status": "active",
    },
    {
        "playbook_id": "PB-008",
        "name": "Data Exfiltration Response",
        "description": "Response to confirmed or suspected data exfiltration via network, cloud storage, or removable media channels.",
        "severity": "critical",
        "tactics": ["exfiltration"],
        "steps": [
            {"step": 1, "action": "isolate_host", "description": "Isolate source hosts to stop active exfiltration channels", "automated": True, "requires_approval": True, "timeout": "3m"},
            {"step": 2, "action": "collect_forensics", "description": "Capture network flows, proxy logs, and DLP alerts for exfiltration timeline", "automated": True, "requires_approval": False, "timeout": "15m"},
            {"step": 3, "action": "block_ip", "description": "Block destination IPs/domains and revoke cloud storage sharing links", "automated": True, "requires_approval": False, "timeout": "5m"},
            {"step": 4, "action": "disable_account", "description": "Suspend accounts involved in data access and transfer", "automated": False, "requires_approval": True, "timeout": "10m"},
            {"step": 5, "action": "notify_team", "description": "Alert data protection officer and legal team for breach assessment", "automated": False, "requires_approval": True, "timeout": "15m"},
            {"step": 6, "action": "create_ticket", "description": "Create data breach investigation case with data classification and volume estimate", "automated": True, "requires_approval": False, "timeout": "10m"},
        ],
        "times_used": 12,
        "avg_execution_time": "2h 00m",
        "success_rate": 83.3,
        "last_used": "2026-03-20",
        "status": "active",
    },
    {
        "playbook_id": "PB-009",
        "name": "OT/ICS Incident Response",
        "description": "Specialized response for incidents affecting operational technology and industrial control systems in Purdue Zone 0-2.",
        "severity": "critical",
        "tactics": ["impact", "inhibit-response-function"],
        "steps": [
            {"step": 1, "action": "notify_team", "description": "Immediately notify OT operations and plant safety team", "automated": True, "requires_approval": False, "timeout": "2m"},
            {"step": 2, "action": "collect_forensics", "description": "Capture historian data, PLC program states, and network traffic from OT DMZ", "automated": True, "requires_approval": False, "timeout": "15m"},
            {"step": 3, "action": "isolate_host", "description": "Segment affected OT zone from IT network at Zone 3.5 DMZ firewall", "automated": False, "requires_approval": True, "timeout": "5m"},
            {"step": 4, "action": "snapshot_vm", "description": "Backup current PLC/HMI configurations before any remediation", "automated": True, "requires_approval": True, "timeout": "20m"},
            {"step": 5, "action": "scan_endpoints", "description": "Scan engineering workstations and jump hosts for compromise indicators", "automated": True, "requires_approval": False, "timeout": "30m"},
            {"step": 6, "action": "block_ip", "description": "Block unauthorized remote access paths and disable OT VPN tunnels", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 7, "action": "escalate_to_l3", "description": "Escalate to OT security specialist and ICS-CERT if warranted", "automated": False, "requires_approval": True, "timeout": "15m"},
            {"step": 8, "action": "create_ticket", "description": "Create ICS incident report with safety impact assessment and NERC CIP documentation", "automated": True, "requires_approval": False, "timeout": "20m"},
        ],
        "times_used": 5,
        "avg_execution_time": "4h 30m",
        "success_rate": 80.0,
        "last_used": "2026-02-28",
        "status": "active",
    },
    {
        "playbook_id": "PB-010",
        "name": "Adversarial ML Detection Response",
        "description": "Response to detected adversarial attacks against ML models including prompt injection, model evasion, and data poisoning.",
        "severity": "high",
        "tactics": ["ml-attack-staging"],
        "steps": [
            {"step": 1, "action": "collect_forensics", "description": "Capture adversarial inputs, model inference logs, and confidence score anomalies", "automated": True, "requires_approval": False, "timeout": "10m"},
            {"step": 2, "action": "block_ip", "description": "Rate-limit or block source of adversarial requests at API gateway", "automated": True, "requires_approval": False, "timeout": "3m"},
            {"step": 3, "action": "revoke_tokens", "description": "Revoke API keys and tokens associated with adversarial requests", "automated": True, "requires_approval": True, "timeout": "5m"},
            {"step": 4, "action": "scan_endpoints", "description": "Run ATLAS-aligned evaluation suite against affected model endpoints", "automated": True, "requires_approval": False, "timeout": "45m"},
            {"step": 5, "action": "escalate_to_l3", "description": "Escalate to ML security team with adversarial sample analysis and ATLAS mapping", "automated": False, "requires_approval": False, "timeout": "15m"},
        ],
        "times_used": 15,
        "avg_execution_time": "1h 10m",
        "success_rate": 86.7,
        "last_used": "2026-03-24",
        "status": "draft",
    },
]


def _compute_stats(playbooks: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute summary statistics from playbook list."""
    active = [p for p in playbooks if p["status"] == "active"]
    total_used = sum(p["times_used"] for p in playbooks)
    avg_success = (
        round(sum(p["success_rate"] for p in playbooks) / len(playbooks), 1)
        if playbooks
        else 0.0
    )
    return {
        "total": len(playbooks),
        "active": len(active),
        "executed_this_month": total_used,
        "avg_success_rate": avg_success,
    }


def _get_all_tactics(playbooks: list[dict[str, Any]]) -> list[str]:
    """Extract sorted unique tactic list."""
    tactics: set[str] = set()
    for p in playbooks:
        tactics.update(p.get("tactics", []))
    return sorted(tactics)


def _filter_playbooks(
    playbooks: list[dict[str, Any]],
    severity: str | None = None,
    tactic: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """Apply filters to playbook list."""
    result = playbooks
    if severity:
        result = [p for p in result if p["severity"] == severity]
    if tactic:
        result = [p for p in result if tactic in p.get("tactics", [])]
    if status:
        result = [p for p in result if p["status"] == status]
    if search:
        q = search.lower()
        result = [
            p for p in result
            if q in p["name"].lower() or q in p.get("description", "").lower()
        ]
    return result


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request) -> HTMLResponse:
    """Render the playbook browser page."""
    playbooks = DEMO_PLAYBOOKS
    stats = _compute_stats(playbooks)
    all_tactics = _get_all_tactics(playbooks)

    return templates.TemplateResponse(
        request,
        "playbooks/index.html",
        {
            "playbooks": playbooks,
            "stats": stats,
            "all_tactics": all_tactics,
        },
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------


@router.get("/api/playbooks/list")
async def api_playbooks_list(
    severity: str | None = None,
    tactic: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> dict[str, Any]:
    """List playbooks with optional filtering."""
    filtered = _filter_playbooks(DEMO_PLAYBOOKS, severity, tactic, status, search)
    return {
        "playbooks": filtered,
        "count": len(filtered),
        "stats": _compute_stats(filtered),
    }


@router.get("/api/playbooks/{playbook_id}")
async def api_playbook_detail(playbook_id: str) -> dict[str, Any]:
    """Get a single playbook with full step details."""
    for pb in DEMO_PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            return pb
    return {"error": "Playbook not found", "playbook_id": playbook_id}
