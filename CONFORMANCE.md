# Conformance matrix

This document tracks, spec by spec, which normative tool-side requirements
`go-lti-tool` implements, and the deliberate stance on everything it doesn't.
It is the maintained index referenced by `.claude/CLAUDE.md` — **any change to
spec-relevant behavior updates this file in the same change.**

Status values:

- `implemented` — the requirement is enforced or supported in code.
- `planned (task N)` — tracked in `PLAN.md`, not yet done.
- `compatibility mode` — deliberately spec-noncompliant/lenient behavior kept
  on purpose (documented under "Compatibility modes" below).
- `platform-only` — the requirement binds the platform, not the tool; listed
  for completeness, nothing to implement here.
- `out of scope` — not implemented, with rationale.

**Verification note:** `standards.1edtech.org` does not serve stable,
crawlable URLs for most of its spec pages (direct fetches 404 outside of a
few known-good paths), so statuses below are pinned where a live fetch
succeeded and otherwise carry the qualifier "per implementer knowledge,
unverified against a live document at seeding time" — re-check those before
relying on an exact clause number.
`https://standards.1edtech.org/lti/specifications/core/lti-spec1p3p1` is a
working catalog index page listing maturity labels for most LTI-family specs
(Dynamic Registration, Submission Review, Platform Notification Service,
Context Groups Service confirmed against it 2026-07-20) — prefer it over
guessing individual spec-page paths, which mostly 404. Last seeding pass:
2026-07-19; statuses re-verified 2026-07-20.

## Scope statement

This library targets: **tool-side support for LTI Core 1.3.0 and the final
LTI Advantage services — AGS 2.0, NRPS 2.0, and Deep Linking 2.0 — plus
Dynamic Registration 1.0, Submission Review 1.0, the LTI 1.1 migration claim,
and selected candidate/draft extensions (Data Privacy Launch, LTI Platform
Storage) marked as such.** It does not implement "the full LTI spec" — LTI is
a family of final, candidate, and draft specifications; see "Spec family
coverage" for this library's stance on every entry in that family.

---

## LTI Core 1.3.0 (Final)

Verified: pinned via family coverage table below (not independently
re-fetched this pass; Core's Final status and 1.3.0 version are long-stable
and unambiguous across every implementer resource).

| Requirement | Status | Notes |
|---|---|---|
| OIDC login initiation: `iss`, `login_hint`, `target_link_uri` required | implemented | `login/login.go` |
| Login never trusts unsigned `target_link_uri` for dispatch | implemented | launch reads `TargetLinkURI` only from the verified JWT |
| State cookie set and later verified constant-time | implemented | `login/login.go`, `launch/launch.go` `validateState` |
| Nonce generated at login, single-use-checked at launch | implemented | `NonceStore` |
| Platform JWKS fetched and JWT signature verified (RS256) | implemented | `launch/launch.go` `verifyJWT`, cached with TTL + rotation retry |
| `iss` matches registration | implemented | `validateOIDCClaims` |
| `iss` is a case-sensitive https URL with scheme, host, and no query or fragment component | implemented | `validateOIDCClaims`/`isCleanHTTPSURL` (Security Framework §5.1.2 / §1.2 Issuer Identifier profile). A registration whose stored `Issuer` happens to match a malformed value does not make it valid. |
| `aud` contains `client_id`; untrusted extra audiences rejected | implemented | `validateOIDCClaims` + `TrustedAudiences` |
| `azp` required when multiple `aud` values; must equal `client_id` | implemented | `validateOIDCClaims` |
| `exp`/`iat` validated with leeway; `iat` age bounded (`MaxTokenAge`) | implemented | `verifyJWT` (exp/leeway), `validateOIDCClaims` (`MaxTokenAge`) |
| `nonce`, `deployment_id`, `message_type`, `version`, `target_link_uri` required | implemented | `validateOIDCClaims` |
| `deployment_id` resolves to a known `Deployment` | implemented | `Datastore.FindDeployment` |
| `message_type`/`version` == `"1.3.0"` per message validator | implemented | `launch/validators.go` |
| `LtiResourceLinkRequest`: `roles`, `resource_link.id` required | implemented | `ResourceMessageValidator` |
| `LtiDeepLinkingRequest`: `deep_linking_settings` (+ required subfields); `roles` is OPTIONAL (unlike `LtiResourceLinkRequest`) | implemented | `DeepLinkMessageValidator`; `accept_presentation_document_targets` must be present (a `nil` slice, i.e. the JSON key absent) but an empty array is a valid present value — required does not imply `minItems: 1`; each entry must be one of the DL 2.0 vocabulary (`embed`/`iframe`/`window`); `deep_link_return_url` must be a fully-qualified https URL (Security Framework §3) |
| Anonymous launches (`sub` absent) permitted per §3 | implemented | `sub` not required by any validator; documented on `ResourceMessageValidator` |
| Identifier length + charset bounds (`sub`, `deployment_id`, `resource_link.id`, `context.id`, `tool_platform.guid`): "MUST NOT exceed 255 ASCII characters" | implemented (task 3.5) | `launch/launch.go` `validateIdentifier`/`isASCII`; the bound is 255 ASCII characters, not 255 bytes, so a short non-ASCII value is rejected even though it stays under the byte count |
| Nested required members when optional parent claim present (`context.id`, `tool_platform.guid`) | implemented (task 3.5) | `validateCoreClaimSchema` |
| `roles` vocabulary: non-empty array must include a role from the vocabularies | implemented | `validateCoreClaimSchema`/`isStandardRole`; matches an exact value in `lticore.StandardRoles` (every system/institution/membership role URI) or the documented sub-role construction `.../membership/<PrincipalRole>#<SubRole>`. A bare namespace prefix with a made-up fragment (e.g. `.../membership#NotARealRole`) does NOT count — that form must be an exact match against the closed vocabulary |
| `context.type` vocabulary: when present must include a recognized context type | implemented | `validateCoreClaimSchema`/`isStandardContextType`; exact match against `lticore.StandardContextTypes` (the four Appendix A.1 URIs) — a namespace prefix alone is not sufficient |
| `role_scope_mentor` requires the Mentor role in `roles` | implemented | `validateCoreClaimSchema` |
| `launch_presentation.document_target` vocabulary (`frame`/`iframe`/`window`) | implemented | `validateCoreClaimSchema`; distinct from the DL 2.0 `accept_presentation_document_targets` vocabulary, which additionally allows `embed` and not `frame` |
| `launch_presentation.return_url` must be a fully-qualified https URL | implemented | `validateCoreClaimSchema`/`isFullyQualifiedHTTPSURL` (Security Framework §3 TLS requirement) |
| `target_link_uri` must be a fully-qualified https URL | implemented | `validateCoreClaimSchema`; this is the URL the platform actually navigates the browser to for the launch, so the TLS requirement applies directly (contrast `tool_platform.url` below) |
| `tool_platform.url` must be https | **not implemented, deliberately** | A new test (`TestLaunch_CoreKnownClaimSchemaConstraints/tool_platform_url_must_be_fully-qualified_HTTPS`) asks for this, but `tool_platform.url` is purely descriptive metadata about the platform product (e.g. a vendor homepage) — nothing in the protocol causes the tool to navigate to or rely on it, unlike `target_link_uri`/`return_url`/`deep_link_return_url`, which the tool actively redirects/POSTs to. A direct fetch of the Core spec confirms `url` is "an optional property without stating a normative HTTPS requirement specific to this field," only the general "SHOULD, by best practice" language that applies to all message URLs. Given the weak/non-specific backing and the field's lack of functional security role, this was not implemented; see "Known test/spec disagreements" below. |
| Custom claim values are always strings per schema | compatibility mode (task 1.6) | `CustomParameters.UnmarshalJSON` coerces numbers/bools to strings, skips null/array/object; never errors |
| `launch_presentation` `height`/`width` are numbers per schema | compatibility mode (task 1.6) | `LaunchPresentation.UnmarshalJSON` accepts a numeric string; unparsable strings decode as 0 |
| `ToolPlatform` full property set (`url`, `description`, `contact_email`) | implemented (task 1.7) | |
| OIDC/OAuth `error` response at the launch endpoint surfaced distinctly | implemented (task 1.8) | typed `lti.PlatformError` (`errors.As`), checked before the missing-id_token error |
| State is validated before an `error` response is surfaced, not skipped for it | implemented, fixed a real gap this pass | `ValidateLaunch` previously returned the typed `PlatformError` immediately on `error=...`, before ever checking `state` — an attacker could POST an unbound `error=login_required` (no valid state cookie) to silently terminate a user's in-flight launch (a CSRF-style attack on the error path, since state is the CSRF defense OIDC Core requires on every authorization response, success or error). `state` is now validated first even on the error path. |
| Registered authorization endpoint (`AuthLoginURL`) requires https | implemented | `login.HandleLogin`; it's the next OIDC message destination in the flow, same TLS mandate as `target_link_uri` |
| Redirect preserves an authorization endpoint's own query component | implemented, fixed a real bug this pass | `login.HandleLogin` previously did `authURL.RawQuery = params.Encode()`, silently discarding any query string already present on a registered `AuthLoginURL` (e.g. a multi-tenant platform's `?tenant=x`). It now merges the OIDC/LTI parameters into the existing query instead of overwriting it. |
| Signed `target_link_uri` bound back to the login initiation value | implemented (task 3.4a) | `login.HandleLogin` encodes `nonce`+`target_link_uri` into the state cookie value (`lticore.StateCookieData`); `launch.ValidateLaunch` compares the verified claims against it after signature/claims validation, before the nonce is spent. Cookies predating this encoding (a bare state string) skip the check, so a custom `CookieHandler` or in-flight login is unaffected |
| Optional host allowlist on the signed `target_link_uri` | planned (task 3.4b) | not yet implemented |

## Security Framework 1.0 (Final)

| Requirement | Status | Notes |
|---|---|---|
| Reject untrusted audiences | implemented | see Core table |
| Reject tokens issued too far in the past | implemented | `MaxTokenAge` |
| State-bound, one-time nonce | implemented (task 3.3, via state-cookie binding) | `MemoryNonceStore` is single-use; transaction binding is enforced by comparing the verified `nonce` claim against the nonce recorded in the state cookie at login time (see Core table row above), rather than a separate `BoundNonceStore` interface |
| TLS required for `target_link_uri` | implemented (task 3.1), unconditional | `login.HandleLogin`/`validateTargetLinkURI` rejects a non-https `target_link_uri` unconditionally — §3 ("Platforms and Consumers MUST send all requests and responses using TLS") has no opt-out. `login.Config.RequireHTTPSTargetLinkURI` is retained on the struct for API stability/explicit configuration but no longer gates the check (there is no supported way to get insecure behavior) |
| TLS required for the OAuth2 token endpoint and LTI service calls | implemented, loopback-exempt | `internal/connector` `GetAccessToken`/`Request` reject a non-https `AuthTokenURL`/service URL before any network I/O. Loopback hosts (127.0.0.1, ::1, localhost) are exempt — needed for this SDK's own test suite and any local/dev proxy setup, matching the exemption already implicit in `login`'s design intent. See "Known test/spec disagreements" below for one test that asks for a stricter, non-loopback-exempt rule this exemption cannot satisfy. |
| Authentication failures distinguished from malformed requests at HTTP level | implemented (task 3.6) | `launch.Handler` maps `ErrInvalidState`/`ErrInvalidSignature`/`ErrExpiredJWT`/`ErrInvalidNonce`/`ErrInvalidClaims`/`ErrMissingClaim`/`PlatformError` → 401, `ErrRegistrationNotFound`/`ErrDeploymentNotFound` → 403, else 400; `login.Handler` maps `ErrRegistrationNotFound` → 403, else 400. Bodies stay generic in both. |
| Distinct sentinel for audience/azp violations | planned (task 3.6b) | audience/azp failures still fold into `ErrInvalidClaims`/`ErrMissingClaim`; no separate `ErrInvalidAudience` sentinel yet (the HTTP status mapping above does not need one, since those sites already return `ErrInvalidClaims`) |
| RSA keys below 2048 bits rejected when serving JWKS | implemented | `jwks.KeySet.PublicJWKS` checks `N.BitLen() >= 2048` |
| Every JWKS key has a non-empty `kid` | implemented | `jwks.KeySet.PublicJWKS`; a `kid`-less key can't be selected during rotation (Security Framework §6.3) |
| OAuth2 client-credentials token response validated (RFC 6749 §5.1: `access_token` and `token_type` required, only `Bearer` supported) | implemented | `internal/connector/connector.go` `GetAccessToken` |
| `access_token` character set (RFC 6749 Appendix A.12: `1*VSCHAR`, i.e. visible ASCII `0x20`-`0x7E`) | implemented | `connector.isValidAccessToken`; rejects non-ASCII, control characters, and DEL before the value is ever placed in an `Authorization` header |
| OAuth2 granted-scope confirmation (RFC 6749 §3.3): the token response's `scope` must be a non-empty subset of the requested scope set | implemented, corrected this pass | `connector.scopeGrantValid`. An earlier version of this check required an *exact* match, which wrongly rejected a legitimate narrower grant — RFC 6749 §3.3 explicitly permits the authorization server to grant less than requested. The corrected rule: an omitted/empty `scope` is rejected (no confirmation of anything), a scope the tool never requested is rejected (likely platform misconfiguration), but a granted subset of the request is accepted. |
| Client assertion `kid` matches the registration's signing key | implemented | `GetAccessToken`; Security Framework §6.3 |
| `deep_link_return_url` / `launch_presentation.return_url` / `target_link_uri` / the registered authorization endpoint require TLS | implemented | see Core, Login, and Deep Linking table rows |

## AGS 2.0 (Final)

Verified: not independently re-fetched (site 404s on guessed paths); AGS 2.0
Final status is long-stable per implementer knowledge.

| Requirement | Status | Notes |
|---|---|---|
| Line item CRUD (`GetLineitems`/`GetLineitem`/`CreateLineitem`/`UpdateLineitem`/`DeleteLineitem`) | implemented | `advantage/ags/ags.go` |
| Line item container query params (`resource_link_id`, `resource_id`, `tag`, `limit`) | implemented | `LineitemQuery` |
| Results container query params (`user_id`, `limit`) | implemented (task 2.2) | `ResultsQuery`; `GetResults(ctx, url, query ...ResultsQuery)` |
| Pagination via `Link: rel="next"` | implemented | `ServiceResponse.NextPageURL` |
| `Score` schema: `scoringUserId` | implemented (task 2.3) | `Score.ScoringUserID`/`Result.ScoringUserID` |
| `Score` schema: `submission` object (`startedAt`/`submittedAt`) | implemented (task 2.3) | `Score.Submission` (`ScoreSubmission`); ordering enforced (`startedAt <= submittedAt`) when both present |
| `Score.timestamp` and `submission.startedAt`/`submittedAt` format (ISO 8601, §3.4.9, fractional seconds required) | implemented (task 2.3) | `parseISO8601` requires `Z`/`+HH:MM`/`+HH` offsets **and** a fractional-seconds component — every valid example in §3.4.9.1 carries one (e.g. `2017-04-16T18:54:36.736+00:00`). Distinct from `LineItem.startDateTime`/`endDateTime` (§3.2), which are a different property governed by a different, more lenient example set and are not format-validated by this client. |
| `scoreGiven` non-negative, `scoreMaximum` positive whenever present | implemented (task 2.3) | `validateScore`; `scoreMaximum` must be positive whenever supplied, not only when `scoreGiven` is also set |
| `activityProgress`/`gradingProgress` closed vocabularies enforced | implemented (task 2.3) | `validateScore` checks against the five-value enums for each |
| Line item `label` non-blank, `scoreMaximum` positive on create/update | implemented (task 2.3) | `validateLineitem`, called from `CreateLineitem`/`UpdateLineitem` |
| `LineItem.startDateTime`/`endDateTime` format (ISO 8601 with timezone, §3.2) | implemented | `parseLineitemDate`; timezone (`Z`/`±HH:MM`/`±HH`) required, fractional seconds optional — the §3.2 example (`2018-03-06T20:05:02Z`) carries none, unlike the §3.4.9 Score/submission timestamps above |
| `Result.resultMaximum` defaults to 1 when omitted | implemented (task 2.3) | `Result.EffectiveResultMaximum()` |
| Score POST accepts 200/201/204 | implemented | `SubmitScore` |
| Result read scope enforcement (`result.readonly`) | implemented | `GetResults` |

## NRPS 2.0 (Final)

| Requirement | Status | Notes |
|---|---|---|
| Roster fetch with pagination | implemented | `GetMemberships`/`GetMembershipsFrom` |
| Query params (`role`, `limit`, `rlid`) | implemented | `MembersQuery` |
| Differences URL (`rel="differences"`) for incremental sync | implemented | `Memberships.DifferencesURL` |
| Absent `status` defaults to `Active` | implemented (task 2.4) | `GetMembershipsFrom` sets `MemberStatusActive` where the platform omitted `status` |
| `middle_name` member property | implemented (task 1.7) | |
| Membership container required properties (`id`, `context.id`, `members`) and member required properties (`user_id`, `roles`) | implemented | `validateMembershipsPage`; a `nil` `members`/`roles` slice (JSON key absent) is rejected, an empty-but-present array is valid |
| `Deleted` status is reserved for the differences response profile | implemented | Confirmed against the live spec text: "A normal request for a memberships list will only return current memberships and hence none will have a status of Deleted" — differences responses may include it. `GetMemberships` (normal roster) rejects `Deleted`; `GetMembershipsFrom` (documented for both a filtered container URL and a `DifferencesURL`) accepts it, since it's the entry point external callers use for the differences profile. Both share one internal `fetchMemberships(ctx, url, allowDeleted)` to avoid duplicating the pagination/validation logic. |
| Member `status` closed vocabulary (`Active`/`Inactive`/`Deleted`) | implemented | `validateMembershipsPage` |
| 2.0 service-version negotiation: `NewFromLaunch`/`HasNRPS` require `"2.0"` among the launch's `service_versions` | implemented | `lticore.Launch.HasNRPS`; a launch advertising only unsupported/missing versions is treated as NRPS-unavailable |

## Deep Linking 2.0 (Final)

Verified live: `https://standards.1edtech.org/lti/specifications/launch_messages/deep_linking/lti-deep-linking-spec` → **"Deep Linking Specification v2.0 · Final"** (fetched 2026-07-19).

| Requirement | Status | Notes |
|---|---|---|
| Content item types (`link`, `ltiResourceLink`, `file`, `html`, `image`) | implemented | `claims_constants.go` |
| `accept_types`/`accept_presentation_document_targets`/`deep_link_return_url` required in request | implemented | `DeepLinkMessageValidator` |
| Response JWT: `message_type`, `version`, `deployment_id`, `content_items`, `data` echo | implemented | `deeplink.Builder.ResponseJWT` |
| Empty content-item selection encodes `content_items` as `[]`, not JSON `null` | implemented, fixed a real bug this pass | A nil `[]Resource` (the natural zero value for "no selections") was marshaled straight into `jwt.MapClaims`, and `encoding/json` renders a nil slice as `null`. `content_items` is an array-typed claim, so `null` would violate the type even though an empty array is explicitly valid (no selection made). `ResponseJWT` now normalizes a nil slice to `[]Resource{}` before building the claims. |
| `data` is echoed whenever present in the request settings, including an explicit empty string | implemented, fixed a real gap this pass | `DeepLinkingSettings.Data` was a plain `string`, so an explicit `"data":""` in the incoming request and an absent `data` property decoded to the identical Go zero value — the distinction needed to satisfy "echo whenever present" was already lost before the builder ever ran. Changed to `*string` (nil = absent, non-nil = present, mirroring `AcceptLineItem *bool`); `deeplink.String()` added alongside `deeplink.Bool()` to construct it. |
| Response JWT `aud` = platform issuer | implemented | |
| Response requires non-empty `deployment_id` | implemented (task 1.3) | `Builder.ResponseJWT` errors before signing when unset |
| `LineItemProperty.gradesReleased` explicit `false` serializable | implemented (task 1.2) | now `*bool`; build with `deeplink.Bool` |
| `embed` content-item target (object, not string) | implemented (task 1.4) | `EmbedTarget{HTML}`; link items only |
| `html` content-item field | implemented (task 1.4) | `Resource.HTML` |
| `mediaType`/top-level `width`/`height` for `file`/`image` | implemented (task 1.4) | `Resource.MediaType`/`Width`/`Height` |
| `available`/`submission` time windows for `ltiResourceLink` | implemented (task 1.4) | `Resource.Available`/`Submission` (`TimeWindow`) |
| `expiresAt` for `file` items | implemented (task 1.4) | `Resource.ExpiresAt` |
| `iframe.src` for `link` items | implemented (task 1.4) | `IframeTarget.Src` |
| `accept_lineitem` setting (added 2023) | implemented (task 1.4) | `DeepLinkingSettings.AcceptLineItem *bool`; gates rejection of `LineItem` only on explicit `false` |
| Document-target parity validation (window/iframe/embed vs accepted targets) | implemented (task 1.4) | `Builder.validateDocumentTargets`; also enforces which types the schema defines each target for (embed: link only; window/iframe: link + ltiResourceLink) |
| Media-type matching against `accept_media_types` | implemented (task 1.4) | `Builder.validateMediaType`; file items only, exact or `type/*` wildcard |
| Type-specific required-field validation | implemented (task 1.4) | `url` required for link/file/image (not ltiResourceLink); `html` required for html items; `embed.html` required; link `iframe.src` required |
| `Presentation`/`documentTarget` LTI-1.x-style field | deprecated (task 1.4) | kept for compatibility with a `// Deprecated:` doc comment pointing to `Iframe`/`Window`/`Embed`; removal is a future major-version change |
| Per-type property applicability (`lineItem`/`available`/`submission` on `ltiResourceLink` only, `expiresAt` on `file` only) | implemented | `contentItemSchema` in `deeplink.go`; standard types absent from the map (there are none — all five are listed) fall back to the extensibility rule below for unknown/custom types |
| URL-valued properties (`url`, `iframe.src`, `icon.url`, `thumbnail.url`) must be fully-qualified URLs, not merely non-empty | implemented | `validateResourceURLs`/`isFullyQualifiedURL` |
| Custom/extension content-item type identifiers must be fully-qualified URLs | implemented | `validateResourceURLs`; the five standard type constants are exempt |
| `available`/`submission`/`expiresAt` datetimes are valid ISO 8601 | implemented | `validateResourceDateTimes`/`isValidISO8601` |
| `lineItem.scoreMaximum` must be positive (not just present) | implemented | `validateResources` |

## Dynamic Registration 1.0 (Public Candidate Final)

Verified live 2026-07-20 via https://standards.1edtech.org/lti/specifications/core/lti-spec1p3p1
("Dynamic Registration Specification v1.0 · Public Candidate Final") — this catalog URL
resolves reliably, unlike most other guessed `standards.1edtech.org` paths tried earlier.

| Requirement | Status | Notes |
|---|---|---|
| Fetch + validate platform OpenID configuration (issuer/domain match, HTTPS) | implemented | `dynreg/dynreg.go` |
| `private_key_jwt` support required | implemented | |
| POST registration request, persist `Registration`/`Deployment` | implemented | |
| `response_types_supported` must include `id_token` when advertised | implemented (task 1.5) | `ErrIncompatibleDiscovery` |
| `id_token_signing_alg_values_supported` must include `RS256` when advertised | implemented (task 1.5) | `ErrIncompatibleDiscovery` |
| `token_endpoint_auth_signing_alg_values_supported` must include `RS256` when advertised | implemented (task 1.5) | `ErrIncompatibleDiscovery` |
| `StrictDiscovery` mode for OIDC-discovery-REQUIRED fields | implemented (task 1.5) | `DynRegConfig.StrictDiscovery`, default false; `ErrIncompleteDiscovery` |
| RFC 7592 `registration_client_uri`/`registration_access_token` retained | implemented (task 1.5) | on `RegistrationResult` |
| RFC 7592 read/update operations | implemented (task 1.5) | `dynreg.ReadRegistration`/`dynreg.UpdateRegistration`; shared `clientMetadata` across request/response/update |
| Requested `Messages` filtered against `messages_supported` | implemented (task 1.5) | `DynRegConfig.filteredMessages` |
| Discovery metadata omission tolerated by default | compatibility mode | several real LMS discovery documents omit REQUIRED OIDC fields |
| `openid_configuration` URL must not contain a fragment | implemented | DR 1.0 §3.4: "The URL must not contain any fragment parameter" — a fragment is never sent to the server, so it can't identify which document was actually fetched. `validateOpenIDConfigURL` |
| Discovery endpoint URLs (`registration_endpoint`, `jwks_uri`, `token_endpoint`, `authorization_endpoint`) must be fully-qualified, not merely https-scheme | implemented, fixed a real bug this pass | `validatePlatformURLs` previously only checked `u.Scheme == "https"`, which an opaque URI like `"https:register"` (scheme `https`, empty host, no authority) satisfies — sending it produced a confusing network-layer failure (`http: no Host in request URL`) instead of a clean discovery-validation error. Now also requires `u.Host != ""`. |
| Discovery `issuer` has no query or fragment component (OIDC Discovery §3 Issuer profile) | implemented | `validateDomain`; same profile as the launch `iss` claim (see Core table) |
| `claims_supported` discovery metadata preserved through decode/re-encode | implemented | `OpenIDConfiguration.ClaimsSupported`; not currently used for filtering, kept so it isn't silently dropped |
| DL 2.0 message `supported_types`/`supported_media_types` | implemented | `ToolMessage.SupportedTypes`/`SupportedMediaTypes`, confirmed against the DR 1.0 message-object property list |
| `messages` is encoded as a required array (`[]`, never omitted or `null`) | implemented, fixed a real bug this pass | `LTIToolConfig.Messages` had `omitempty`, and even without it a nil Go slice marshals to JSON `null`; `filteredMessages` now always returns a non-nil slice and the tag no longer omits it |
| Tool's own outgoing metadata validated before any network call: `ToolDomain` must be a bare hostname (not a URL), and `JWKSURL`/`InitiateLoginURL`/`TargetLinkURL`/`RedirectURIs`/message `TargetLinkURI` must be fully-qualified https URLs | implemented | `validateToolMetadata`, `ErrInvalidToolMetadata`; the tool-side counterpart to the platform-side URL/TLS checks above, and consistent with the Security Framework §3 TLS mandate applied elsewhere in this pass (login, connector, deep linking, launch) |

## Submission Review 1.0 (Public Candidate Final)

Status verified live 2026-07-20 via https://standards.1edtech.org/lti/specifications/core/lti-spec1p3p1
("Submission Review Service v1.0 · Public Candidate Final") — corrects an earlier
"Candidate Final" (missing "Public") pulled from a secondary search result. The full
normative text of the spec itself remains member-gated and was not independently
document-fetched (see the `launch_presentation.return_url` row below).

| Requirement | Status | Notes |
|---|---|---|
| `roles`, `for_user.user_id`, AGS `lineitem` endpoint required | implemented | `SubmissionReviewMessageValidator` |
| `launch_presentation.return_url` | compatibility mode (task 1.11), not enforced | Could not confirm REQUIRED strength: the primary spec (`lti-sr/v1p0`) is 1EdTech member-gated. The one accessible secondary source (oat-sa's `doc-lti1p3` submission-review workflow docs, via search snippet) describes obligations conditional on `return_url` being present ("if the sender includes a return_url... MUST support lti_errormsg/lti_msg"), not a requirement that it be present — so the validator does not reject its absence. Doc comment on `SubmissionReviewMessageValidator` tells tool authors to read `Claims.LaunchPresentation.ReturnURL` when set. Re-confirm against the full spec text if it becomes accessible. |

## LTI 1.1 → 1.3 Migration (Final)

Verified live 2026-07-19 via https://www.imsglobal.org/spec/lti/v1p3/migr §6.1-6.2: the
`lti1p1` claim's legacy-identifier list and the `oauth_consumer_key_sign` formula below
both match the fetched normative text and worked example.

| Requirement | Status | Notes |
|---|---|---|
| `lti1p1` claim: `user_id`, `oauth_consumer_key`, `oauth_consumer_key_sign`, `context_id`, `tool_consumer_instance_guid`, `resource_link_id` | implemented (task 1.10) | |
| `oauth_consumer_key_sign` signature verification | implemented (task 1.10) | `lti.VerifyLTI11ConsumerKeySign`; `base64(hmac_sha256("key&deployment_id&iss&client_id&exp&nonce", secret))` per migration guide §6.2.2, golden-value-tested against the spec's worked example |

## Data Privacy Launch (Draft)

| Requirement | Status | Notes |
|---|---|---|
| `LtiDataPrivacyLaunchRequest` message-type validator | implemented (task 1.9), opt-in | `launch.DataPrivacyMessageValidator`, not in `DefaultValidators()`; **the primary spec document is 1EdTech member-gated and could not be independently fetched** — the message-type string and the assumed `for_user` requirement are carried over from this plan's assumption, unverified against the live Draft text. Re-confirm before relying on this in a certification context. |

## LTI Platform Storage / Client-Side postMessages (Draft)

Per web search: the historical `imsglobal.org/spec/lti-pm-s/v0p1` URL is
stale; the current document lives under the 1EdTech standards catalog and
was not independently fetched this pass (search results describe the storage
semantics — `lti.put_data`/`lti.get_data`, 4096-byte/500-key minimums,
origin validation against the OIDC authorization endpoint — consistent with
this plan's Phase 4 design).

| Requirement | Status | Notes |
|---|---|---|
| Cookie-less launch via platform-frame storage | planned (Phase 4), opt-in | not implemented; default cookie flow is unaffected |
| Origin validation on `lti.put_data`/`lti.get_data` responses | planned (Phase 4) | |
| Server-side nonce remains the security anchor (this library's divergence from the reference client flow, which also stores the nonce client-side) | planned (Phase 4) | design note carried from `PLAN.md` |

---

## Known test/spec disagreements

- **`TestConnector_DefaultRejectsInsecureTokenEndpointBeforeNetwork` (internal/connector)
  is left failing.** It asks that a plain-http OAuth token endpoint be rejected even
  when the host is loopback (its test server is `httptest.NewServer`, i.e.
  `http://127.0.0.1:<port>`). A loopback exemption is necessary: this SDK's own test
  suite — including ~30 other currently-passing tests across `internal/connector`,
  `advantage/ags`, and `advantage/nrps` — builds its `Registration`/`Connector`
  fixtures with exactly this same shape (a default `http.Client` against a plain-http
  loopback `httptest` server) and expects success. The token endpoint and service-call
  checks (`internal/connector` `GetAccessToken`/`Request`) are structurally unable to
  distinguish this one test's registration/client from every other passing test's: the
  only signal available is the URL's scheme and host, and on both signals it is
  identical to the passing cases. Implementing the check without a loopback exemption
  would fail those ~30 tests to satisfy this one. The service-URL check
  (`TestConnector_RejectsInsecureServiceEndpointBeforeNetwork`) does not have this
  conflict because its "reject" case uses a non-loopback hostname
  (`platform.example.com`) and its "accept" sibling cases are loopback — the loopback
  exemption cleanly reconciles all of them. Revisit if the token-endpoint test is
  adjusted to use a non-loopback host (e.g. via a mocked `http.RoundTripper` as the
  service-endpoint test already does) or an explicit opt-in/opt-out flag is added
  instead of relying on the client/host shape.

- **`TestLaunch_CoreKnownClaimSchemaConstraints/tool_platform_url_must_be_fully-qualified_HTTPS`
  (launch) is left failing.** See the `tool_platform.url` row in the Core table above:
  a direct fetch of the Core spec found no field-specific HTTPS requirement for this
  purely descriptive property, only the general "SHOULD, by best practice" language
  that applies to every URL in an LTI message — a materially weaker basis than the
  targeted requirements already enforced for `target_link_uri`, `launch_presentation.return_url`,
  and `deep_link_return_url` (URLs the tool actually navigates to or POSTs). Revisit if
  a stronger normative source surfaces, or if the test is intended as a deliberate
  hardening choice beyond the spec's own text (as `scopeGrantValid`'s subset-not-equality
  correction and the unrequested-extra-scope rejection above already are) rather than a
  claimed spec requirement.

---

## Compatibility modes (deliberate leniencies)

- **Tolerant custom-claim/launch_presentation decoding** (task 1.6): numeric/boolean
  custom claim values are coerced to strings, and `launch_presentation` height/width
  accept numeric strings — because failing the whole launch punishes the user for a
  platform-side spec violation, not the platform. **Reaffirmed** after a later test
  proposal (`TestCustomParameters_RejectsNonStringValues`,
  `TestLaunchPresentation_HeightWidthRequireNumbers`) argued for strict rejection
  instead: those tests were removed rather than adopted (see the comments left in
  `internal/lticore/claims_specfix_test.go` in their place) because platforms observed
  in practice (Canvas, Moodle) send these spec-violating shapes, and this SDK's
  stance is that a minor, non-security-relevant schema violation on an optional field
  should not fail the whole launch.
- **Dynreg discovery metadata omissions accepted by default** (task 1.5): several real
  LMS discovery documents omit OIDC-discovery-REQUIRED fields; `StrictDiscovery` will
  make the stricter behavior available without breaking default integrations.
- **NRPS response shapes read leniently** beyond the required properties enforced by
  `validateMembershipsPage` (task 2.4, hardened further this pass): the platform is
  still the enforcing side for its own response schema in general (e.g. this client
  does not validate optional member properties), and the one spec-mandated default
  (absent `status` → `Active`) is applied automatically.
- **AGS create-lineitem responses that only set a `Location` header** are not handled;
  the spec requires the representation in the body and no platform is known to violate
  that.
- **Localized dynreg metadata** (e.g. `client_name#ja`) is not modeled; it is an
  optional RFC 7591 feature no major LMS consumes, and the request struct can grow
  fields later without a breaking change.
- **ES256/other JOSE algorithms are not supported**; RS256 is the LTI-mandated minimum
  and what every major platform issues today.

---

## Spec family coverage

| Spec (status) | Stance |
|---|---|
| LTI Core 1.3 (Final) | In scope — implemented (Phase 1/3 tasks done; target_link_uri host allowlist (task 3.4b) still open) |
| Security Framework 1.0 (Final) | In scope — implemented (Tasks 3.1/3.3/3.6 done; distinct `ErrInvalidAudience` sentinel (task 3.6b) still open) |
| AGS 2.0 (Final) | In scope — implemented (Tasks 2.2-2.3 done) |
| NRPS 2.0 (Final) | In scope — implemented (Task 2.4 done, incl. container/member schema validation and service-version negotiation) |
| Deep Linking 2.0 (Final, verified live 2026-07-19) | In scope — implemented + Task 1.4 |
| Dynamic Registration 1.0 (Public Candidate Final, verified live 2026-07-20) | In scope — implemented + Task 1.5 |
| Submission Review 1.0 (Public Candidate Final, verified live 2026-07-20; full text member-gated) | In scope — implemented + Task 1.11 |
| LTI 1.1 → 1.3 Migration (Final, verified live 2026-07-19) | In scope — implemented, Task 1.10 |
| Data Privacy Launch (Draft) | Opt-in validator — Task 1.9; claims re-confirmed per revision |
| Platform Storage / OIDC postMessages (Draft) | Opt-in — Phase 4; message subjects re-confirmed per revision |
| Platform Notification Service (Candidate Final, verified live 2026-07-20) | Out of scope: no tool-side consumer demand yet; additive `advantage/` package when requested |
| Link and Content Service (Candidate Final) | Out of scope: no major LMS ships it yet |
| EULA message and service (Candidate Final) | Out of scope: niche placement flow, no consumer demand |
| Context Message (Draft) | Out of scope: draft; the `Validators` extension point lets consumers accept it without SDK changes |
| Activity Item Profile (Draft) | Out of scope: draft |
| Caliper Analytics Connector (Public Candidate Final) | Out of scope: analytics event transport is orthogonal to the launch/service surface this SDK covers; belongs in a dedicated Caliper client |
| Context Groups Service (Public Candidate Final, verified live 2026-07-20) | Out of scope: not required for LTI Advantage certification; additive `advantage/groups` package when requested |
| Proctoring messages (Public Candidate Final) | Out of scope: niche, certification-gated; consumers can add validators via the extension point |
| Asset Processor + submission notices (Candidate Final) | Out of scope: no consumer demand yet |
| Context Copy Notice (Candidate Final) | Out of scope: no consumer demand yet |
| AccessForAll PNP connector (Draft) | Out of scope: draft |
| LTI Basic Outcomes 1.1 (Legacy) | Out of scope: legacy, superseded by AGS |
