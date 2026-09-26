# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Pin token algorithm to HS256 and reject header algorithm claims structurally

**What I chose:** Strictly require `header.alg === 'HS256'` and `header.typ === 'JWT'` after safely decoding the header, rejecting any other algorithm or header shape with `401 UNAUTHENTICATED` before verifying the HMAC-SHA256 signature in constant time.
**Why:** `scripts/check-jwt.js:95-102` explicitly tests algorithm confusion attacks (`alg: none` with empty signature, `alg: none` with trailing dot, `HS512` substitution, `RS256` substitution, and missing/invalid `alg`/`typ`). Trusting the token's header to dictate how the signature is verified allows algorithm confusion attacks (e.g. `none` algorithm bypass, or treating an HMAC secret as an RSA public key).
**What I rejected:** Allowing a configurable algorithm whitelist or dynamically selecting a verification function based on `header.alg`. In a symmetric HMAC token architecture, accepting asymmetric algorithms like `RS256` creates an asymmetric-to-symmetric key confusion attack vector where an attacker signs a forged token using the server's public key as the HMAC secret.
**What would change my mind:** A requirement to support asymmetric tokens from an external third-party Identity Provider (OIDC/OAuth2) with key rotation via JWKS endpoints.

---

### Explicit deny outranks allow unconditionally regardless of specificity (no carve-outs)

**What I chose:** In `server/permissions.js`, collect all grants matching the query's scope and evaluate denies first. If any applicable grant specifies `effect: 'deny'`, the permission resolves to `deny` with `reason: 'explicit_deny'`, ignoring any `allow` grants or role baselines.
**Why:** In `scripts/check-permissions.js:81-86`, grant `g_carve` grants an explicit device-scoped `allow device:terminal` on `dev_lab_win_01` for `usr_sam`, who possesses an org-wide `deny device:terminal`. The test explicitly asserts that the outcome remains `deny` (`device-scoped ALLOW does NOT carve out org-wide DENY`).
**What I rejected:** Hierarchical precedence or "narrowest scope wins" (e.g. device-scoped grant overrides org-scoped grant). Implementing narrower-scope precedence fails `check-permissions.js:85` and violates invariant D1 ("an explicit deny always wins regardless of scope or specificity").
**What would change my mind:** A requirement for multi-device delegation where org administrators need to blacklist a tool globally while whitelisting designated sandbox devices.

---

### Batched device permission resolution without caching

**What I chose:** In `resolveDevices()`, resolve permissions for an entire list of devices by loading catalogue, membership, and baseline once and fetching all applicable grants in a single database query, performing per-row matching in memory.
**Why:** Eliminates the N+1 query problem without introducing an in-memory cache or TTL. With SQLite's sub-millisecond query execution, loading grants once per request takes under 1ms. An in-memory cache keyed by `userId` alone would leak permissions across organizations for multi-org users (`AUTH-DATA-MODEL.md §4`), while any cache with a TTL would serve stale permissions after a revocation, violating D7.
**What I rejected:** Adding an in-memory LRU cache or Redis cache with short TTL. A cache introduces cache invalidation complexity across multi-process deployments and risks serving revoked authority.
**What would change my mind:** Profiling showing database read contention with tens of thousands of active devices per organization, at which point an in-memory cache strictly keyed by `(userId, orgId)` and invalidated by `memberships.perm_version` would be justified.

---

### Re-inviting a removed member updates the existing membership row rather than inserting

**What I chose:** In `routes/invites.js`, when an invite is accepted, check if a membership record already exists for `(org_id, user_id)`. If present (whether in `invited` or `removed` status), perform an `UPDATE memberships SET status='active', role=?, joined_at=? WHERE id=?` and bump `perm_version`, instead of an `INSERT`.
**Why:** The SQLite schema enforces `UNIQUE(org_id, user_id)` on `memberships`, while user rows are never deleted (`users` has no `deleted_at`). Removing a user merely sets `memberships.status = 'removed'`. Attempting a naive `INSERT` when a previously removed user accepts a new invite crashes with `SQLITE_CONSTRAINT: UNIQUE constraint failed: memberships.org_id, memberships.user_id` (HTTP 500).
**What I rejected:** Soft-deleting memberships with a `deleted_at` column, or hard-deleting membership rows on member removal. The schema is fixed and deliberate: keeping the membership row preserves historic audit foreign-key integrity and prevents phantom state transitions.
**What would change my mind:** If the schema were revised to include a surrogate history table and allowed physical deletion of `memberships`, or changed the unique constraint to a partial index `WHERE status != 'removed'`.

---

## Where this repo argues with itself

### 1. Suspension cannot both bump `perm_version` and answer `403` with an empty set
- **Statement A (`AUTH-DATA-MODEL.md §1`)**: *"pv is the membership's permission version... It goes up whenever something authorization-relevant changes: a role change, a grant created or revoked, a suspension, a removal... A token whose pv no longer matches gets 401 TOKEN_STALE."*
- **Statement B (`AUTH-DATA-MODEL.md §10` & `PERMISSIONS.md §7`)**: *"A suspended membership's token still verifies, but resolves to an empty set, so every permission question is refused with 403 suspended."*
- **The Conflict**: If suspension increments `perm_version`, any request presenting the caller's live token will fail the `perm_version === claims.pv` freshness check in `context.js` and immediately return `401 TOKEN_STALE`. The request is aborted before reaching the resolution engine, meaning `403 FORBIDDEN` with `reason: "suspended"` is never returned to the caller.
- **My Decision**: I preserved the database `perm_version` bump (which is correct and ensures that when the user is reinstated, old pre-suspension tokens remain permanently stale). In `server/context.js`, I check `if (membership.status !== 'suspended') assertFresh(claims, membership);`. This intentionally bypasses the staleness check for suspended memberships, allowing the request to proceed to route handlers where `assertCan` executes, the empty permission set is evaluated, and the server returns `403 FORBIDDEN` (`reason: "suspended"`).

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
