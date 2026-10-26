# Migrating to 0.7.0

- **Signing secrets.** `AgentIdentityRegistry()` and `AuditTrail()` no longer fall back to a shared constant. Pass `secret=` or set `BLACKWALL_PASSPORT_SECRET` and `BLACKWALL_AUDIT_SECRET`. Without one you get a random per-process secret and a `RuntimeWarning`: signatures made by one process won't verify in another. Signatures created by 0.6.x under the old default constant will no longer verify; re-issue them.
- **Sidecar.** Set `BLACKWALL_API_KEY` (32+ characters) before starting it. It now listens on `127.0.0.1`; pass `--host 0.0.0.0` explicitly if it must be reachable from other hosts, and it will refuse to do that without a key. For local development without a key, pass `--allow-no-auth`.
- **Identifier labels.** TFN and Medicare findings now require a valid checksum, so test fixtures with made-up numbers may stop producing `tfn` or `medicare` findings. Use checksum-valid examples such as TFN `123 456 782` and Medicare `2123 45670 1`.

# Migrating to 0.1.9

## Stable Contracts

The following APIs are intended to be the long-term integration surface for the 0.2.x line:

- `guard_model_request()`
- `review_model_response()`
- `protect_model_call()`
- `protect_with_adapter()`
- `ToolPermissionFirewall`
- `RetrievalSanitizer`

These contracts are also exposed in `CORE_INTERFACES` so applications can log or assert the expected interface version.

## What Changed in 0.1.4

- Added richer multimodal/message-part handling for mixed text, image, and file content
- Added provider adapters for OpenAI, Anthropic, Gemini, and OpenRouter
- Added presets and route-level policy overrides
- Added custom prompt detector hooks for domain tuning
- Expanded rollout guidance, benchmarks, and regression notes

## What Changed in 0.1.9

- Added identity-aware telemetry enrichment for SSO-backed applications
- Added Power BI-friendly export helpers and telemetry exporter hooks
- Expanded summaries to support user-level and identity-provider reporting

## What Changed in 0.1.8

- Added explicit guidance for controlled-pilot rollout and internal wrapper adoption
- Added documented workflow presets for planner, document-review, RAG-search, and tool-calling routes
- Added stronger docs for route-level telemetry review, false-positive tuning, and release-noise checks

## Migration Notes

- If you previously passed message content as arrays of parts, 0.1.4 now preserves those parts in `content_parts` while still producing the text view in `content`.
- If you were wrapping providers manually, prefer `protect_with_adapter()` plus the adapter factories in `blackwall_llm_shield.providers`.
- If you want conservative rollout, switch to `preset="shadow_first"` before enabling hard blocking on every route.
- If you already have an internal model-security abstraction, prefer wrapping Blackwall behind that layer and migrating route by route.

## Compatibility

- Existing string-based `messages[].content` flows remain supported.
- Existing `guard_model_request()` and `OutputFirewall` usage remain backward-compatible.
