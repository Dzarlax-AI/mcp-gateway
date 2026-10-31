# Classified read batches and admin workspace

The opt-in `GATEWAY_READ_BATCH_POLICY_MODE=classified` uses the effective operation type of each enabled tool on every enabled server. It requires `GATEWAY_TOOL_SEARCH_ENABLED=true` and `GATEWAY_READ_BATCH_ENABLED=true`. Do not provide `GATEWAY_READ_BATCH_ALLOWLIST` in this mode. Existing `file` and `registry` modes keep their previous policies and administration as compatibility paths.

The classified mode also enables the compact graphite admin workspace at `/admin/servers` and `/admin/servers/<id>`, with the configured external prefix. No automatic production switch, registry import, or SQL migration takes place.

## Classification

- `readOnlyHint: true` means automatic read eligibility. Operators explicitly trust the connected server's declaration; the gateway does not prove its implementation is side-effect free.
- Missing or false hints are unclassified. The pinned Go SDK represents `readOnlyHint` as a plain boolean and cannot distinguish those two cases.
- An explicit manual `write` override denies batch regardless of annotations.
- An explicit manual `read` override permits batch only while its saved approval binding matches. Input/output schema, name, read-only declaration, exact endpoint, credential source/value and HTTPS allowlist are bound; editorial descriptions and titles are excluded.
- Changed manual-read bindings become unclassified and require review. They never silently fall back to the automatic hint. Restoring automatic mode is an explicit operator action.

Optional tool fields `operation_kind` (`read` or `write`, absent means automatic) and `operation_contract_hash` (required only for `read`) persist through the existing versioned JSON/CAS store. Registry document version stays 2; SQL schema stays 2. New tools are still disabled. Classification does not add ACL entries or bypass argument grants.

Before every dispatch, including after initialize, current client identity, ACL, switches, argument validation, connection and operation classification are rechecked. The existing item/worker/deadline/output budgets and no-retry behavior remain. Classified mode follows the upstream InputSchema, including its declared additional-property semantics; legacy profile restrictions remain in legacy mode.

## Workspace and selected tools

The left navigation searches server names, descriptions and endpoints. A selected server has searchable tool groups: Read operations, Write operations and Unclassified. Labels show both type and source, such as `Read · automatic` or `Read · manual`.

Group selection applies to matching rows. Changing search or status filters clears selection. Bulk Enable/Disable submit exact unique tool names (1–500) and save with one CAS. Homogeneous group selections include their expected type and are revalidated before saving. Bulk Enable may make one bounded catalog check; Disable never contacts the upstream. Failures commit nothing, except an explicitly unknown acknowledgement can follow an already committed transaction and requires read-back rather than retry.

The workspace reads an isolated metadata snapshot from the same cache as MCP. Display reads do not extend its TTL or trigger checks across all servers. Stale display metadata is labelled; it never authorizes dispatch. Classification may be submitted against a last-known definition, but manual-read saving verifies the fresh current definition before recording approval.

## Recovery and downgrade

There is no startup migration. The old binary rejects the new optional tool fields once overrides have been saved. Image-only rollback after that point is unsafe.

For an explicitly authorized downgrade, use the new binary's existing private export/CAS import workflow to remove only `operation_kind` and `operation_contract_hash`, preserve all other current server/tool/principal settings and encrypted credentials, and restore the desired legacy policy mode. Review the exact export and expected revision before importing. Do not restore an old whole database over newer state, and do not auto-retry an unknown write.

Production rollout must separately back up the current registry, ciphertext, deployment inputs and environment, then select the classified mode explicitly. No real tool invocation is needed to classify a tool.
