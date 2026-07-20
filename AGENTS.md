# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`github.com/robertjndw/go-lti-tool` — a Go SDK for LTI 1.3 (Learning Tools Interoperability). It targets tool implementations (not platforms): the OIDC launch flow, the final LTI Advantage services (AGS 2.0, NRPS 2.0, Deep Linking 2.0), Dynamic Registration, Submission Review, the LTI 1.1 migration claim, and selected opt-in candidate/draft extensions. LTI is a family of final, candidate, and draft specifications — this library does not implement "the full LTI spec"; see `CONFORMANCE.md` for the maintained per-spec stance.

## Commands

```bash
go build ./...          # build all packages
go test ./...           # run all tests
go test ./launch/...     # run tests for a single package
go test -run TestName ./... # run a single test by name
go test -cover ./... # current package-level coverage
go vet ./...            # static analysis
```

## Package layout

| Directory | Purpose |
|---|---|
| `.` (root) | Main entry point: `Tool` / `NewTool`; re-exports core types (`Datastore`, `NonceStore`, `Launch`, `Registration`, `Deployment`, claims) as aliases from `internal/lticore` |
| `login/` | OIDC login-initiation handler (`login.Handler`) |
| `launch/` | JWT validation and launch handler (`launch.Handler`) |
| `jwks/` | JWKS endpoint handler (serves tool's public keys) |
| `advantage/ags/` | Assignment & Grade Services client |
| `advantage/nrps/` | Names & Role Provisioning Services client |
| `advantage/deeplink/` | Deep Linking response builder |
| `internal/lticore/` | Core domain types and interfaces; not importable directly by consumers |
| `internal/connector/` | OAuth2 `client_credentials` bearer-token client; caches tokens per scope set |
| `internal/ltitest/` | Shared test helpers: RSA key gen, JWKS server, claim factories, datastores |
| `dynreg/` | LTI Dynamic Registration handler (`dynreg.Handler`, `dynreg.Register`); also exposed as `Tool.HandleDynamicRegistration(profile ToolProfile)` |
| `examples/` | Runnable examples (basic-launch, complete, deep-linking, grades, moodle) |

## Architecture

The SDK mirrors the structure of the reference PHP implementation ([1EdTech/lti-1-3-php-library](https://github.com/1EdTech/lti-1-3-php-library)), translated to idiomatic Go. Key design principles:

- **`Tool` is the primary entry point**: `lti.NewTool(opts ...ToolOption)` wires together a datastore, nonce store, launch data store, cookie handler, and JWKS key set and returns ready-to-use `http.Handler` values (`HandleLogin()`, `HandleLaunch(next)`, `HandleJWKS()`). Sub-packages (`login`, `launch`, `jwks`) remain available for callers that need lower-level control.
- **Functional options**: Override any component with `WithDataStore`, `WithNonceStore`, `WithLaunchDataStore`, `WithCookieHandler`, `WithKeySet`, `WithAllowedRedirectHosts`. Defaults are in-memory; swap in persistent backends via these options. `WithTrustedAudiences(auds ...string)` is a convenience wrapper for `launch.Config.TrustedAudiences`. `WithLaunchConfig(fn func(*launch.Config))` and `WithLoginConfig(fn func(*login.Config))` are general escape hatches for knobs without a dedicated option (`Leeway`, `MaxTokenAge`, `JWKSCacheTTL`, `Validators`, `JWKSFetchOptions`, ...); `fn` runs after the Tool's own wiring, so set stores via their dedicated `With*` options rather than through `fn`.
- **Storage is caller-provided**: Define a `Datastore` interface (or equivalent) that callers implement to persist registrations and deployments. The SDK never dictates a storage backend. Datastores may additionally implement `RegistrationFinder` (`FindRegistration(ctx, issuer, clientID)`) to support issuers hosting multiple registrations (e.g. cloud Canvas); `MemoryStore` does.
- **No global state**: All configuration is passed explicitly; no `init()` side effects.
- **JWKS is first-class**: Key management (generation, rotation, serving a JWKS endpoint) is a distinct concern, not buried in launch logic.
- **Type aliases**: `lti.X` types (e.g. `lti.Registration`) are transparent aliases for `internal/lticore.X`, so they interoperate with sub-packages without import cycles.

### Core domain concepts

| Concept | Description |
|---|---|
| **Platform** | The LMS (e.g., Canvas, Moodle). Issues signed JWTs, hosts the OIDC authorization endpoint and token endpoint. |
| **Tool** | This SDK's consumer. Receives launches, calls platform services. |
| **Registration** | One tool registered on one platform: holds `client_id`, `issuer`, platform auth URL, platform JWKS URL, platform token URL, and the tool's private key. |
| **Deployment** | A specific instance of a registered tool within a platform context. Identified by `deployment_id`. One registration can have multiple deployments. |
| **LTI Link** | A placed resource on the platform. Each has a stable `resource_link_id`. |

### Launch flow (OIDC + JWT)

```
Platform              Tool
  |                     |
  |-- OIDC login init ->|  GET /oidc/login  (iss, login_hint, target_link_uri)
  |<-- redirect --------|  to platform auth endpoint with state + nonce
  |-- POST id_token --->|  POST /lti/launch
  |                     |  1. validate state cookie
  |                     |  2. fetch platform JWKS, verify JWT signature
  |                     |  3. validate standard OIDC claims (iss, aud, exp, nonce)
  |                     |  4. validate LTI-specific claims (message_type, version, deployment_id)
  |                     |  5. dispatch to resource launch or deep link handler
```

The `id_token` is a signed JWT. **Never trust unsigned parameters from the login initiation request** (especially `target_link_uri`); always use the signed value from the validated JWT.

The platform may POST an OIDC/OAuth error response instead of an id_token (OIDC Core §3.1.2.6, e.g. `login_required`); `launch.ValidateLaunch` surfaces this as a typed `*lti.PlatformError` (`errors.As`) before falling through to the generic missing-id_token error.

`launch.DataPrivacyMessageValidator` handles `LtiDataPrivacyLaunchRequest` (Data Privacy Launch, a Draft spec Canvas sends today) but is deliberately not in `DefaultValidators()` — append it explicitly to opt in. Its message-type string and `for_user` requirement are this plan's best-effort assumption; the primary spec document is 1EdTech member-gated and was not independently verified.

`lti.VerifyLTI11ConsumerKeySign(claims, clientID, oauthConsumerSecret)` verifies the `lti1p1.oauth_consumer_key_sign` migration signature: `base64(hmac_sha256("oauth_consumer_key&deployment_id&iss&client_id&exp&nonce", secret))` (migration guide §6.2.2). `clientID` must be the registration's client_id and is checked against the token's `aud` first, removing multi-audience ambiguity. Sentinels `ErrLTI11ClaimMissing`/`ErrLTI11SignInvalid`.

Launch validation details:
- Platform JWKS responses are cached per URL (default TTL 1 hour, `launch.Config.JWKSCacheTTL`); an unknown `kid` or a signature failure against a cached set triggers one forced refresh, so key rotation is picked up immediately. A JWT without a `kid` header is tried against every platform key.
- Clock skew leeway (`Leeway`, default 60s) and a max token age check on `iat` (`MaxTokenAge`, default 10 minutes, negative disables) are applied.
- OIDC `azp` is validated: it must equal the client_id when present and is required when `aud` has multiple values. Audiences other than the client_id are rejected unless listed in `launch.Config.TrustedAudiences` (1EdTech Security Framework).
- `LtiSubmissionReviewRequest` requires `for_user` and the AGS claim's `lineitem`; `resource_link` is not required (standalone line items).
- Tolerant claim decoding (compatibility mode, see `CONFORMANCE.md`): `custom` values sent as numbers/booleans are coerced to strings, and null/array/object values are dropped rather than erroring (`lti.CustomParameters`); `launch_presentation` `height`/`width` accept a numeric string in addition to a number, decoding to 0 if unparsable.

### JWT claim namespaces

All LTI-specific claims live under the `https://purl.imsglobal.org/spec/lti/claim/` prefix. Key claims:

| Claim (suffix) | Required | Notes |
|---|---|---|
| `message_type` | yes | `LtiResourceLinkRequest` or `LtiDeepLinkingRequest` |
| `version` | yes | Must be `"1.3.0"` |
| `deployment_id` | yes | Must match a known deployment |
| `target_link_uri` | yes | Validated endpoint URL |
| `resource_link` | yes (resource launch) | Object with `id` |
| `roles` | yes | Array of role URIs (may be empty) |
| `context` | no | Course/section info |
| `custom` | no | Key-value string map |
| `lis` | no | Student information system identifiers |
| `for_user` | yes (submission review) | The user whose submission is reviewed; object with `user_id` |
| `role_scope_mentor` | no | User IDs a Mentor-role user may access |
| `lti1p1` | no | LTI 1.1 migration identifiers: `user_id`, `oauth_consumer_key`, `oauth_consumer_key_sign`, `context_id`, `tool_consumer_instance_guid`, `resource_link_id` |

Standard OpenID Connect claims (`sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `given_name`, `email`, etc.) follow normal OIDC validation rules.

### LTI Advantage services

Services require an OAuth 2.0 bearer token obtained from the platform's token endpoint. The tool authenticates using a client assertion JWT where both `iss` and `sub` are the tool's `client_id`.

| Service | Spec short name | Purpose |
|---|---|---|
| Assignment & Grade Services | AGS v2.0 | Read/write grade line items and scores |
| Names & Role Provisioning | NRPS v2.0 | Fetch course roster with roles |
| Deep Linking | DL v2.0 | Tool returns content selections to platform |

Each service URL is discovered from the launch JWT claims, not hardcoded.

Service client notes:
- AGS `Score.ScoreGiven`/`ScoreMaximum` (and `Result` score fields) are `*float64` so a score of 0 survives serialization; build them with `ags.Float64(v)`. `SubmitScore` validates required fields and the "scoreGiven implies scoreMaximum" spec rule, and accepts any 2xx response (the spec's example responds 204).
- `ags.GetLineitems` and `nrps.GetMemberships` accept optional query structs (`LineitemQuery`, `MembersQuery`) mapping to the specs' filter parameters; `FindOrCreateLineitem` scopes matching to the launching resource link.
- `nrps.GetMemberships` returns context and a `DifferencesURL` for incremental roster sync (`GetMembershipsFrom`).
- The deep link `Builder` validates selections against `accept_types`/`accept_multiple` before signing and supports the optional `msg`/`log`/`errormsg`/`errorlog` claims via exported fields. It also requires a non-empty deployment ID, validates document-target parity (`window`/`iframe`/`embed` vs `accept_presentation_document_targets`, and which content item types the DL 2.0 schema defines each target for), matches `file` items' `mediaType` against `accept_media_types` (exact or `type/*` wildcard), and enforces type-specific required fields (`url` for `link`/`file`/`image`, `html` for `html` items, `embed.html`, `link` iframe `src`).
- `deeplink.LineItemProperty.GradesReleased` is `*bool` (build with `deeplink.Bool(v)`) so an explicit `false` survives serialization; nil means "platform default".
- `deeplink.Resource` covers the full DL 2.0 content item schema: `HTML` (html items), `Embed` (an object `{html}`, link items only), `MediaType`/top-level `Width`/`Height` (file/image items), `Available`/`Submission` time windows and `IframeTarget.Src` (ltiResourceLink/link items). `Resource.Presentation` is deprecated in favor of `Iframe`/`Window`/`Embed`. `lti.DeepLinkingSettings.AcceptLineItem` (`*bool`) gates whether a resource may carry a `LineItem` — only an explicit `false` rejects it.

### Key management

- RSA-256 with 2048-bit keys (minimum).
- `jwks.FromRegistration(reg).Handler()` serves the tool's JWKS endpoint so platforms can verify service call assertions.
- Key rotation: JWKS may contain multiple keys; signing always uses the key identified by the `KID` field on `Registration`.

### Dynamic Registration

`Tool.HandleDynamicRegistration(profile ToolProfile)` implements LTI DR v1.0: the platform opens the registration URL in an iframe, the handler fetches the platform's OpenID configuration, POSTs a client registration request, persists the resulting `Registration` via a `RegistrationWriter`, and returns HTML that sends `org.imsglobal.lti.close` via `postMessage`.

- The `Datastore` passed to `WithDataStore` must also implement `RegistrationWriter` (i.e. expose `AddRegistration` and `AddDeployment`).
- `ToolProfile.JWKSBaseURL` overrides `Domain` for the advertised JWKS URI — useful when the platform is on a different network (e.g. Moodle in Docker using `host.docker.internal`).
- Set `AllowInsecureOpenIDConfigURL: true` only for local development; production must use HTTPS.
- Registration is rejected unless the platform's `token_endpoint_auth_methods_supported` includes `private_key_jwt` (an omitted list means `client_secret_basic` per OIDC Discovery); requested scopes are intersected with `scopes_supported` when advertised, and requested `Messages` are intersected with `messages_supported` when the platform advertises any.
- Discovery compatibility: `response_types_supported`, `id_token_signing_alg_values_supported`, and `token_endpoint_auth_signing_alg_values_supported` are checked for compatibility (`id_token`/`RS256`) whenever the platform advertises them, regardless of mode (`ErrIncompatibleDiscovery`). `DynRegConfig.StrictDiscovery` (default false) additionally requires the OIDC-discovery-REQUIRED fields to be present (`ErrIncompleteDiscovery`) — several real LMS discovery documents omit them, so the default tolerates omission.
- `dynreg.Register(ctx, cfg, openidConfigURL, token)` is the lower-level function for non-HTTP callers. `RegistrationResult` also exposes `RegistrationClientURI`/`RegistrationAccessToken` when the platform supports RFC 7592; use them with `dynreg.ReadRegistration`/`dynreg.UpdateRegistration`. `ClientRegistrationRequest`/`Response` and the RFC 7592 `ClientRegistrationUpdate` payload share their client-metadata fields via one embedded struct so the three shapes cannot drift; build an update from a `ReadRegistration` result, mutate, then send — partial updates are not defined by the RFC.

## Retrieving launch context

- `lti.LaunchFromContext(ctx)` — extracts `*Launch` from the request context set by `HandleLaunch`
- `tool.GetLaunch(ctx, launchID)` — retrieves a previously cached launch by ID (useful after deep-link flows where the launch context must be restored in a subsequent request)

## Testing

Use helpers from `internal/ltitest` rather than constructing JWTs or datastores by hand:
- `ltitest.NewKey(t)` — generates an RSA key pair
- `ltitest.NewJWKSServer(t, kid, key)` — serves a JWKS over HTTP (auto-closed via `t.Cleanup`)
- `ltitest.DefaultClaims(reg, nonce)` / `ltitest.DeepLinkClaims(...)` — minimal valid claim maps
- `ltitest.SignJWT(t, key, kid, claims)` — signs and returns a token string
- `ltitest.SimpleDatastore` / `ltitest.StrictDatastore` — in-memory datastore implementations

Gotchas hit repeatedly this session:
- `internal/connector` tests (and `advantage/ags`/`advantage/nrps` tests that build a
  `Connector`) universally use plain-HTTP loopback `httptest` servers, including in
  "should succeed" cases. Any TLS-enforcement check on the token/service endpoints
  must exempt loopback hosts (127.0.0.1/::1/localhost) or it cascades into ~30
  unrelated failures.
- A JSON property that's "required but may be an empty array" (e.g.
  `accept_presentation_document_targets`, DL `content_items`, NRPS `members`/`roles`,
  dynreg `messages`) needs a nil-vs-non-nil-slice check, not `omitempty` —
  `omitempty` treats a non-nil empty slice as absent too, and a nil slice marshals to
  JSON `null`, not `[]`.

## Conformance matrix

`CONFORMANCE.md` is the maintained index of which normative tool-side spec
requirements are implemented, planned, a deliberate compatibility exception,
platform-only, or out of scope. **Any change to spec-relevant behavior must
update the matrix in the same change** — a change is not complete while
`CONFORMANCE.md` contradicts the code.

This test suite grows iteratively — expect to be asked to verify newly-added
tests against spec before implementing, not just make them pass. WebFetch of
imsglobal.org spec pages is unreliable on repeat fetches of the same URL (has
returned contradictory answers across 3 fetches of one page); trust an answer
quoting a specific section number over a paraphrase, and re-fetch once before
trusting a surprising claim. When a new test turns out to be wrong, or
conflicts with the rest of the suite in a way no implementation can resolve
(e.g. it needs a signal the code can't observe), record the reasoning under
"Known test/spec disagreements" in `CONFORMANCE.md` and remove the test rather
than leave it permanently red.

## Reference resources

- **Core spec**: https://www.imsglobal.org/spec/lti/v1p3
- **Implementation guide**: https://www.imsglobal.org/spec/lti/v1p3/impl/
- **AGS spec**: https://www.imsglobal.org/spec/lti-ags/v2p0
- **NRPS spec**: https://www.imsglobal.org/spec/lti-nrps/v2p0
- **Deep Linking spec**: https://www.imsglobal.org/spec/lti-dl/v2p0
- **Reference PHP implementation**: https://github.com/1EdTech/lti-1-3-php-library
