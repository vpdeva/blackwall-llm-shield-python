# Changelog

## Unreleased

- Updated the default OWASP LLM coverage report and checked-in badge to reflect full built-in framework coverage across the OWASP LLM Top 10 2025 categories.

## 0.6.3

- Replaced the README coverage badge with a checked-in badge generated from the OWASP coverage report output and linked it to the implementation.
- Added a social preview SVG, a contributor-friendly good-first-issues section, and a comparison page covering Blackwall versus OpenAI moderation.

## 0.6.2

- Restructured the README hero section with badges, install commands, and a fast copy-paste guard example.

## 0.6.1

- Expanded PyPI keywords and classifiers to improve discovery across AI security, middleware, HTTP server, and enterprise library categories

## 0.6.0

- Added threat-intel sync hooks, anomaly detection, telemetry replay, signed inspection attestation, and a streaming output firewall
- Hardened the Python sidecar with API-key auth and added a `/guard/stream` endpoint for stream-aware output checks
- Added policy-config validation flow through the scorecard CLI and kept the new runtime slice aligned with JS

## 0.5.1

- Added persisted corpus hardening for adversarial mutations and strengthened the lightweight edge-oriented masking path
- Added explicit coverage paths for training data poisoning, improper output reliance, excessive agency, and overreliance in OWASP reporting
- Fixed tracker lifecycle so shared conversation history stays attached to the shield instance instead of falling back to per-request creation

## 0.5.0

- Added automatic multi-turn threat tracking by default, realistic OWASP coverage reporting, and automatic provenance stamping on guarded request/output paths
- Added richer plugin hooks for output scanning, retrieval inspection, and telemetry enrichment plus an end-to-end `protect_zero_trust_model_call()` helper
- Expanded adversarial mutation strategies, improved unicode de-obfuscation, and widened regression coverage for the new governance paths

## 0.4.0

- Added a reversible `unvault()` API, `ConversationThreatTracker`, plugin registration via `shield.use(plugin)`, and a lightweight edge-friendly shield entry point
- Added OWASP LLM coverage reporting, adversarial mutation helpers, prompt provenance tracking, and stronger grounding output metadata
- Expanded regression coverage for the new platform primitives and kept the Python public surface aligned with JS

## 0.2.1

- Added `CrossModelConsensusWrapper` for out-of-the-box cross-model safety verification
- Extended VaR breakers with tool-schema monetary value fields
- Added schema-derived digital twins from `ToolPermissionFirewall`
- Added `PolicyLearningLoop` for approval-history-based policy suggestions
- Added JWT-style passport tokens in `AgentIdentityRegistry`

## 0.3.0

- Added richer signed agent passports with capability manifests, lineage, trust scores, and PQC-ready crypto profile metadata
- Added `QuorumApprovalEngine`, `SovereignRoutingEngine`, simulation-mode digital twins with differential privacy noise, and explainable transparency reports
- Wired quorum approvals into tool gating and added trust-score degradation when agents repeatedly fall out of consensus

## 0.2.4

- Added wiki-ready example guides and linked them from the main README
- Updated repository hygiene with broader `.gitignore` coverage for local editor and build artifacts

## 0.2.3

- Clarified the standalone install story for Python so the core package remains lightweight while integrations and semantic tooling stay opt-in
- Aligned package versioning with the JS install-path cleanup release

## 0.2.2

- Added a globally applicable governance pack with data classification gates, provider routing policies, approval inbox models, upload quarantine workflows, retrieval trust scoring, outbound communication guards, compliance event bundles, and operational drift detection
- Expanded regulated-environment presets for government, banking, document intake, citizen services, and internal operations routes
- Added regression coverage for the new governance primitives and aligned enterprise rollout docs with the 0.2.x contract line

## 0.2.0

- Added `ValueAtRiskCircuitBreaker` for high-value tool/action thresholds with session revocation and MFA-style escalation flags
- Added `ShadowConsensusAuditor` integration in tool gating for logic-conflict review on high-impact actions
- Added `DigitalTwinOrchestrator` for mock tool sandboxes and pre-production twin testing
- Added `suggest_policy_override()` for self-healing policy tuning suggestions after approved false positives
- Added signed agent passports in `AgentIdentityRegistry`

## 0.1.9

- Added enterprise telemetry enrichment with SSO/user attribution on emitted events and audit records
- Added Power BI-friendly record builders and exporter hooks for telemetry pipelines
- Expanded operational summaries to break down findings by user and identity provider

## 0.1.8

- Expanded enterprise rollout guidance for controlled pilots, internal shield wrappers, and false-positive tuning
- Added clearer provider-wrapper and Gemini adoption guidance in the main docs
- Improved telemetry and benchmarking docs to focus on route-level operator reporting and release-noise review

## 0.1.7

- Added workflow-specific presets for planner, document-review, RAG-search, and tool-calling routes
- Added `protect_json_model_call()` plus JSON parsing helpers for strict structured-output pipelines
- Improved Gemini adapter handling for system instructions and multimodal message parts
- Expanded operator telemetry summaries with feature grouping, noisiest routes, and weekly block estimates

## 0.1.6

- Added production-ready telemetry summaries grouped by route, tenant, model, policy outcome, and top rules
- Expanded provider and rollout docs for better operator trust
- Improved benchmark guidance with clearer shadow-mode reporting questions

## 0.1.5

- Added route-level operational telemetry summaries for easier rollout visibility
- Added stronger rollout presets for RAG-safe and agent-tool workflows
- Expanded enterprise-oriented rollout docs around provider coverage, observability, and control-plane usage

## 0.1.4

- Added richer multimodal message-part normalization and masking
- Added provider adapters and stable wrapper guidance as first-class release docs
- Added migration notes, benchmark notes, and rollout guidance for false-positive tuning
- Expanded route-level and domain-level policy documentation for RAG and agent workflows

## 0.1.0

- Initial public release
- Sensitive-data masking
- Prompt-injection detection
- Output firewall
- Tool permission firewall
- Retrieval sanitizer
- Audit trail
- Policy packs
- Canary tokens
- Dashboard helpers
- Red-team eval harness
