from blackwall_llm_shield import AuditTrail, build_admin_dashboard_model


audit = AuditTrail(secret="vish")
audit.record({"type": "llm_request_blocked", "severity": "high"})
audit.record({"type": "canary_leak", "severity": "critical"})

dashboard = build_admin_dashboard_model(
    audit.events,
    [
        {"severity": "critical", "reason": "Canary token leaked", "resolved": False},
        {"severity": "high", "reason": "Prompt injection threshold exceeded", "resolved": False},
    ],
)

print(dashboard)
