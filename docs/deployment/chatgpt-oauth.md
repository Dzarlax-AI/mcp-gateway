# Cloudflare Access Managed OAuth for the MCP gateway

This is an optional, separate origin profile for an MCP-specific Cloudflare
Access Managed OAuth application. It adds the internal `/mcp/oauth` route;
the existing external path includes the established `/gateway` prefix and
uses the same service and hostname. Native API-key authentication on
`/gateway/mcp` remains independent. No OAuth discovery metadata is served by
the gateway: Cloudflare's edge owns discovery and challenge handling.

## Runtime settings

The feature defaults off. When enabled, all values below are required and
validated at startup:

| Variable | Meaning |
| --- | --- |
| `GATEWAY_MCP_ACCESS_ENABLED` | Set to `true` to enable the route. |
| `GATEWAY_MCP_ACCESS_ISSUER` | Exact HTTPS Cloudflare Access team issuer, with no path or trailing slash. |
| `GATEWAY_MCP_ACCESS_AUD` | Audience for the MCP-specific Access application. |
| `GATEWAY_MCP_ACCESS_USER_MAP` | Strict JSON object mapping exact assertion email addresses to existing gateway principal IDs. |
| `GATEWAY_PUBLIC_ORIGIN` | Existing canonical HTTPS origin; required when OAuth is enabled. |

Example values must be supplied through the private runtime environment, for
example `{"alice@example.net":"principal-a"}`. Never put user identities,
issuer values, or application IDs in a tracked example. A mapped principal
must already exist. Its current presence and grants are checked on each
request and at tool admission; batch checks again immediately before dispatch.
Removing a principal denies its mapped identity on subsequent admissions.
Already admitted ordinary operations may finish. Changing a grant takes effect
on the next operation.

The route requires a valid `Cf-Access-Jwt-Assertion` signed with RS256. The
verifier obtains keys only from the fixed HTTPS path
`<issuer>/cdn-cgi/access/certs`; it does not fetch URLs from a token, follow
redirects, or contact the issuer at startup. It validates issuer, MCP audience
membership (including multi-audience assertions), required `exp` and `iat`,
optional `nbf`, `type=app`, subject, and exact email mapping. JWKS requests use
a bounded timeout and response size, cache keys for five minutes, and limit
refreshes for unknown key IDs. An unavailable JWKS denies requests that need a
key fetch or refresh; a still-cached key can remain usable until its cache
lifetime ends. Native API-key requests do not depend on JWKS.

The route accepts POST only, rejects any supplied Origin and all query
parameters, and requires the canonical Host. A forwarded Authorization value
is optional; when present it must have Cloudflare's opaque `Bearer oauth:…`
shape. It is transport data only and is never looked up as a gateway key.
`X-API-Key`, duplicate assertions, combined assertions and native Bearer values
are denied. The signed assertion is mandatory in every case. The gateway
reserves encoded, case-variant, trailing-slash, and subtree path variants so
they cannot fall through to native authentication. When disabled, the reserved
OAuth path returns 404.

## Edge and client setup

Prepare the separate MCP-specific Cloudflare Access application with only the
intended users and identity provider. Enable Managed OAuth using a client
registration method that supports PKCE S256. Configure the actual callback URI
shown by the ChatGPT connection setup UI exactly; do not guess it, reuse an old
callback, or allow a callback wildcard. Choose token and grant lifetimes for
the intended client. A short access token can aid acceptance, but does not
prove the configured grant's maximum usable duration.

Cloudflare's edge must protect the exact external OAuth path and own any
authorization challenge/discovery behavior. Keep the native key route
available under its existing policy. The reviewed example
[Compose overlay](../../examples/deployment/docker-compose.mcp-oauth.yml) adds
the exact Traefik path router and existing rate, in-flight, body-size, and strip-prefix
middlewares. It takes the hostname and Access values from a private
environment. Adapt the service, entrypoint, certificate resolver and middleware
names to your reviewed base deployment; the example does not create them.
Keep the rendered configuration private because interpolation includes identity
mappings. Review the rendered Compose configuration and current router ownership
before any future deployment. The example is not a complete base deployment and
does not establish the state of any running service.

## Local verification and acceptance limits

The local suite uses synthetic RSA keys and assertions, a local JWKS test
source, and the actual gateway SDK handler. It covers signature, issuer,
audience, time, claim type, identity isolation, path/method/origin/header
rejections, current principal and grant checks, and successful ordinary and
batch calls to the synthetic local upstream fixture. Passing them does not
demonstrate Cloudflare edge routing, real provider discovery, ChatGPT
registration, a live account, expiry behavior, or production deployment.

Before a separately authorized rollout, render and review the overlay, confirm
the exact Cloudflare application/audience and callback in their configuration
screens, and verify the gateway's existing native API-key path. After rollout,
check service health, an unauthenticated edge challenge/discovery path, direct
origin denial, one actual ChatGPT read-only MCP call, and native-key access.
Observe a real post-expiry call before claiming expiry behavior. Keep the
existing native route and deployment artifacts for rollback; disable the new
profile and remove the exact new edge/router path under the deployment's
separate approval process. No runtime change or deployment is performed by
these instructions.

Provider and client behavior references: [Cloudflare Access Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/), [Cloudflare assertion validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), and [OpenAI client authentication](https://developers.openai.com/plugins/build/auth). Read the current provider/client setup UI before configuring a live application because callback and registration details are deployment-specific.

## Private operator material

Keep actual hosts, issuer/audience values, identity mappings, callback values,
client keys and rendered Compose output in an operator-owned secret store or
private files outside the publication inputs. The versioned example contains
variable references only. Never add a runtime `.env`, production registry,
database dump, private recovery bundle or deployment receipt to Git.
The export allowlist includes this guide and its example, while excluding
`deploy/mcp-gateway/`, `docs/local/`, local verification and approval plans.
These exclusions do not remove files already present in Git history.

## Agent permissions

Registry document v2 requires explicit per-principal policy and exact tool ACL. New keys start restricted with no access. OAuth and native credentials resolve to the same policy evaluator. Existing installations require a reviewed explicit migration; see the [ACL runbook](agent-acl.md). Local audit is opt-in and has explicit degraded status.
