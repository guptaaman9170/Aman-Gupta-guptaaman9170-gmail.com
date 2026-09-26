# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

**2026-09-26 · Environment setup & baseline establishment**

- **Dependency resolution**: Attempted `npm install` with the shipped `better-sqlite3@^11.10.0`. On Node.js v24.19.0 (ABI 137), `prebuild-install` found no prebuilt binary and attempted a `node-gyp` rebuild, which failed due to missing Visual Studio C++ build tools. Investigated npm releases and discovered `better-sqlite3@12.11.1` publishes precompiled `node-v137-win32-x64` tarballs. Upgraded `better-sqlite3` to `^12.11.1`; installation completed in 5 seconds with zero compiler dependencies.
- **Windows path resolution bug**: Running `node scripts/load-db.js` crashed with `ENOENT: open 'D:\D:\rhinostream-assignment\starter\db\schema.sql'`. Root cause: `const here = (p) => new URL(p, import.meta.url).pathname;` evaluates to `/D:/...` on Windows, causing `fs.readFileSync` to interpret `/D:` as relative to current drive `D:`, resulting in `D:\D:\...`. Fixed by importing `fileURLToPath` from `node:url` and using `fileURLToPath(new URL(p, import.meta.url))` in `scripts/load-db.js` and `server/index.js` (for `DIST`).
- **Cross-platform `db:reset`**: `rm -f` in `package.json` fails in Windows `cmd.exe`. Since `load-db.js` already includes native `rmSync` unlinking for `app.db`, `app.db-wal`, and `app.db-shm`, simplified the script to `node scripts/load-db.js`.
- **Database reset & personalization overlay**: `npm run db:reset` executed cleanly:
  - 3 orgs, 8 users, 10 memberships, 9 devices, 6 grants, 3 sessions, 7 audit events, 20 permissions, 27 patterns.
  - Personalisation overlay derived from `.candidate-nonce` (`starter-demo`): extra role `reviewer` (rank 35), extra permission `device:reboot`, extra org `Ironside Labs` (`org_p_bb3398`), baseline `device:list, device:view, user:invite, user:remove`.
- **Baseline suite execution against untouched skeleton**:
  - `node scripts/check-jwt.js`: **0 passed, 43 failed** (all fail because `verifyAccessToken` throws stub error).
  - `node scripts/check-permissions.js`: crashed with `Error: TODO: server/permissions.js — resolve() is yours to write`.
  - `npm run personalisation`: crashed on `resolve()`.
  - `node scripts/check-api.js`: aborted cleanly on `dana logs in` (got 404), safely terminated child server without port leaking.
- Starting line established. Next up: implement `verifyAccessToken` in `server/auth.js`.

## Phase 1 — token verification

**2026-09-26 · Implementing `verifyAccessToken` in `server/auth.js`**

- **Expected vs Observed in Malformed Headers & Attack Vectors**:
  - *Expectation*: I initially thought verifying the signature should be the very first step before touching any JSON payloads.
  - *Observation*: To verify an HMAC signature `createHmac('sha256', secret).update(`${h}.${p}`).digest()`, we need the raw segments `h` and `p`. But we also must inspect `header` to defend against algorithm confusion (`alg: none`, `HS512`, `RS256`).
  - *Failure mode discovery (A6)*: If we parse `header` naively with `JSON.parse(unb64(h))` without wrapping it in a try/catch, a client sending `not json` crashes with an uncaught `SyntaxError`, producing an internal server error (500) rather than `401 UNAUTHENTICATED`. Furthermore, `check-jwt.js:91` tests `forge('HS256', claims())` where the header JSON is a primitive string `"HS256"` rather than an object `{ alg: ... }`. Accessing `header.alg` directly on a non-object or array would either be `undefined` or behave unexpectedly. We added strict type and structure guards: `if (!header || typeof header !== 'object' || Array.isArray(header) || header.alg !== ALG || header.typ !== 'JWT') throw unauthenticated('unsupported token algorithm');`.
  - *Constant-time comparison trap*: `crypto.timingSafeEqual(actual, expected)` throws a `RangeError` if the two buffers differ in byte length. When a truncated or empty signature is supplied (tested in `check-jwt.js:108` and `:109`), calling `timingSafeEqual` directly crashes. We must check `actual.length !== expected.length` beforehand and return `401 UNAUTHENTICATED`.
  - *Half-open expiry boundary (B7)*: `check-jwt.js:116` tests `exp exactly now`. In standard UNIX timestamps, expiration is half-open: `[iat, exp)`. At the exact second `exp === now`, the token is already expired. So the condition is `claims.exp <= now`, not `<`.
- **Validation**: Ran `node scripts/check-jwt.js`. All 43 assertions passed cleanly across round-trip preservation, malformed inputs, algorithm confusion defences, signature validation, expiration semantics, issuer/audience enforcement, and refresh-token rejection.

## Phase 2 — caller context and the resolution engine

**2026-09-26 · Resolution algorithm, denial precedence, and structural isolation**

- **The Wrong Precedence Model and the Observation That Broke It (B1, D1)**:
  - *Initial intuition*: Coming from traditional ACL systems, my mental model expected hierarchical scope specificity: a specific device-scoped grant should override a general org-wide grant. For example, if an operator has an org-wide `deny device:terminal`, but the owner grants an explicit `allow device:terminal` on a specific staging machine (`dev_lab_win_01`), I expected the narrower grant to create a local carve-out.
  - *The breaking observation*: `scripts/check-permissions.js:81-85` tests this exact case ("the discriminating case: org-wide deny + device-scoped allow"). It inserts grant `g_carve` (`allow device:terminal` on `dev_lab_win_01`) for `usr_sam`, who already has an org-wide deny on `device:terminal`. The test asserts: `check('device-scoped ALLOW does NOT carve out org-wide DENY', effect('usr_sam', A, 'device:terminal', 'dev_lab_win_01'), 'deny')`.
  - *The corrected model*: Precedence is not about scope specificity. Deny outranks allow unconditionally. All matching grants (org-wide and device-scoped) are collected into a flat pool; if *any* applicable grant has `effect === 'deny'`, the final outcome is an explicit deny with `reason: 'explicit_deny'`. Allows are only evaluated if zero denies match.
- **The Document Contradiction on Suspension (A4, D11)**:
  - *Contradiction noticed*: `AUTH-DATA-MODEL.md §1` states that suspending a membership increments `perm_version`. But `AUTH-DATA-MODEL.md §10` and `PERMISSIONS.md §7` mandate that requests with a suspended membership's token must be refused with HTTP `403 FORBIDDEN` and `reason: "suspended"`. If `context.js` routinely runs `assertFresh(claims, membership)`, the version mismatch triggers first, returning `401 TOKEN_STALE`. The client would either enter a refresh loop or receive a 401 instead of a 403.
  - *Resolution in code*: In `server/context.js`, we keep the version bump (it is required so that if the user is reinstated later, the old token remains stale), but we skip `assertFresh` *specifically when* `membership.status === 'suspended'`. The request proceeds to the resolution engine, where `gateReason('suspended')` returns `{ effect: 'deny', reason: 'suspended' }` across all permissions, and `assertCan` correctly throws `403 FORBIDDEN` with `reason: 'suspended'`.
- **Structural Tenancy Isolation (B4)**:
  - In `server/context.js`, cross-org access is not prevented by filtering queries after the fact. If the route URL has `params.org` and `params.org !== claims.org`, we throw `404 NOT_FOUND` immediately. The token's org claim is the only universe the caller can address.
  - Similarly, joining `organizations o ON o.id = m.org_id` in `context.js` and checking `o.deleted_at` ensures that deleting an org immediately renders all tokens for that org invisible (`404 NOT_FOUND`).
- **Dynamic Catalogue Reading & Personalisation Verification**:
  - We read `permissions` and `role_permissions` from SQLite tables at query time rather than hardcoding the 5 roles and 19 permissions.
  - Ran `npm run personalisation`: All 18 checks passed, successfully resolving the undocumented `reviewer` role (rank 35) and `device:reboot` permission from candidate nonce `starter-demo`.
- **Suite results**:
  - `node scripts/check-permissions.js`: **ALL PASS (35 passed, 0 failed)**.
  - `npm run personalisation`: **ALL PASS (18 passed, 0 failed)**.

## Phase 3 — orgs, members, invites

**2026-09-26 · Lifecycle management, membership constraints, and re-invitation semantics**

- **The Removed Membership Constraint Trap (A1)**:
  - *Observation*: In `db/schema.sql`, the `memberships` table has a strict `UNIQUE(org_id, user_id)` constraint. Users are never deleted (`users` table has no `deleted_at`). When a member is removed (`DELETE /v1/orgs/:org/members/:userId`), the system sets `memberships.status = 'removed'`.
  - *The failure mode*: If a previously removed user is invited back to the organization and accepts the invite, a standard `INSERT INTO memberships (id, org_id, user_id, ...)` fails with `SQLITE_CONSTRAINT: UNIQUE constraint failed: memberships.org_id, memberships.user_id`, raising a 500 error on the accept route.
  - *The fix*: In `routes/invites.js`, when accepting an invite, we check whether a membership row already exists for `(invite.org_id, user.id)`. If an existing row is found in `removed` (or `invited`) status, we execute an `UPDATE memberships SET status='active', role=?, joined_at=? WHERE id=?` and bump `perm_version`, rather than attempting an `INSERT`.
- **Atomic Single-Use Invite Claims Leaning on Database Invariants (B5)**:
  - Invite redemption runs inside an atomic transaction with `UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`.
  - We rely on `claim.changes === 1` to prevent race conditions during concurrent accept attempts. If two concurrent requests attempt to redeem the same invite token, SQLite's serialization guarantees exactly one succeeds, while the other sees `changes === 0` and throws `409 CONFLICT`. The partial unique index `one_live_invite_per_email` guarantees uniqueness at rest.
- **Last Owner Protection and Role Ranking (D8)**:
  - Implemented `assertNotLastOwner` in `server/lifecycle.js`: counts active owners (`status = 'active'`). If count is 1 or fewer, demotion, suspension, removal, or self-leaving throws `409 LAST_OWNER`.
  - Implemented `assertCanModify`: `callerRole === 'owner'` can modify anyone (including peer owners); other roles can only modify targets strictly lower in `roles.rank`. Non-owners cannot assign or invite an owner (`403 cannot_confer_owner`).
  - Route ordering: registered `/v1/orgs/:org/members/me` before `/v1/orgs/:org/members/:userId` to prevent the parameterized route from capturing the literal string `'me'`.

## Phase 4 — devices and grants

**2026-09-26 · Scope boundaries, privilege laundering prevention, and database foreign keys**

- **Scope Boundary in Privilege Laundering (A3, D9)**:
  - *The question*: When `assertMayGrant(db, ctx, patterns, deviceId = null)` verifies that the caller has authority to confer a permission, what does "at that scope" mean when `deviceId` is null versus when a specific `deviceId` is provided?
  - *The observation*: If a grant is org-wide (`deviceId === null`), the caller must hold `allow` at the org level without being blocked by an explicit deny anywhere that would taint global delegation. If the grant is device-scoped, the caller only needs `allow` for that specific device. For instance, an operator cannot grant `device:control` org-wide if they only possess a device-scoped allow on machine A.
  - *Wildcards in laundering*: When an admin attempts to grant `*`, `expand('*', catalogue)` resolves to all 19 permissions. Because an admin lacks `org:delete`, `assertMayGrant` flags `org:delete` and throws `403 FORBIDDEN` (`missing_permission`).
- **Row Exclusion vs Field Redaction**:
  - In `GET /v1/orgs/:org/devices`: `device:list` authorizes the endpoint, but `device:view` governs row visibility. Devices where the caller has `device:view` denied (such as `dev_kiosk_lobby_01` for `viewer`) are filtered out completely, matching the invisible-not-forbidden design principle.
- **Handling Database Constraint Exceptions as Client Validation**:
  - `grant_permissions` references `permission_patterns(pattern)` via a foreign key. Inserting an invalid permission like `'device:teleport'` violates this foreign key.
  - Rather than letting SQLite throw an uncaught error that surfaces as an HTTP 500, we catch the foreign key violation in `routes/devices.js` and map it to `400 VALIDATION` with `reason: 'unknown_permission'`.
  - Duplicate permissions in a single grant request (e.g. `['device:view', 'device:view']`) are deduplicated with `[...new Set(permissions)]` before database insertion, preventing primary key collisions.
- **Device Transfers Across Tenant Boundaries**:
  - `POST /v1/orgs/:org/devices/:id/transfer`: Moving a device to another org requires `device:provision` in both the source and target orgs. When transferred, existing device grants are purged (they belonged to the source org's context) and all active sessions on that device are ended with `reason: 'device_transferred'`.

## Phase 5 — sessions

**2026-09-26 · Compound permissions, grandfathering, and concurrency invariants**

- **The Compound Check Resolution Order (B2)**:
  - *Observation*: Starting a session on a device requires two independent permissions: `session:start` (can the caller open a session?) and the mode permission (`device:view`, `device:control`, or `device:terminal`). Both must be evaluated on the *same* target device.
  - *Order of evaluation*: In `assertCanStartSession`, we explicitly check `session:start` first. If missing, it throws `403 FORBIDDEN` (`reason: 'missing_permission'`). If allowed, we then check the mode permission on that device. If missing, it throws `403 FORBIDDEN` (`reason: 'missing_device_permission'`).
  - *Why this order matters*: Testing `scripts/check-permissions.js:121-123` verified this distinction: for `usr_acme_viewer`, requesting a `control` session on `dev_lab_mac_01` returns `missing_device_permission` (viewer can start sessions on this device via grant, but lacks control permission), whereas requesting a `view` session on `dev_qa_android_01` returns `missing_permission` (viewer has no session:start grant on this device). Reversing the check would conflate global session capability with device-level mode entitlement.
- **Grandfathering vs Cascade Invariants (B3)**:
  - Authority snapshotting: When a session is initiated, `snapshotAuthority(db, { userId, orgId, deviceId })` captures the user's role and matching grant IDs into `sessions.authorized_by`.
  - Revoking a grant or demoting a member's role does NOT terminate in-flight sessions; it only prevents starting new sessions. Expiry is guaranteed by `sessions.expires_at` based on `organizations.max_session_minutes`.
  - Conversely, tenancy disruptions DO cascade immediately: member removal (`membership_removed`), member suspension (`user_suspended`), and device transfer (`device_transferred`) terminate active sessions synchronously via `endActiveSessions`.
- **Relying on Database Indexes for Concurrency (B5)**:
  - Exclusive sessions (modes `control` and `terminal`) must never run concurrently on the same device.
  - Instead of a vulnerable check-then-act query (`SELECT count(*) ...` followed by `INSERT`), we rely on the partial unique index `one_exclusive_session_per_device` in `db/schema.sql`. Under concurrent requests, exactly one insert succeeds; the competing transaction encounters `SQLITE_CONSTRAINT`, which we catch in `routes/sessions.js` and convert to `409 DEVICE_BUSY`.

## Phase 6 — audit

**2026-09-26 · Audit boundary, mutation auditing, and default-org ordering**

- **What Counts as an Auditable Event (Invariant 9)**:
  - *The decision*: Invariant 9 asks the audit log to record denied attempts as well as successes. However, logging every denied `GET` request (e.g. evaluating permissions for absent UI elements or polling endpoints) would flood the `audit_events` table with ambient read noise and drown out security signals.
  - *The boundary*: We audit security-relevant state mutations:
    1. Sign-in attempts: successful logins and failed sign-in attempts (attributed to the user's primary org if the user exists, noting that unknown emails cannot be attributed to an org because `audit_events.org_id` is `NOT NULL`).
    2. Gated state changes: org creations, updates, deletes; role updates; member suspensions and reinstatements; member removals and departures; invite creations and revokes; invite acceptances; device provisions, updates, decommissions, and transfers; grant creations and revocations; session starts, stops, and terminations.
  - *Single-row invariant*: Each successful route handler writes its own audit record inside the database transaction performing the mutation. `auditDenials()` catches `FORBIDDEN` exceptions and records denials before rethrowing. This guarantees that successful mutations produce exactly one row, rather than being double-counted by both an outer wrapper and the inner handler.
- **Ungated Endpoints and Engine Bypass (A5)**:
  - We catalogued gated versus ungated endpoints: `POST /v1/auth/login`, `GET /v1/invites/:token`, and `POST /v1/invites/:token/accept` are entirely ungated and public. They bypass `server/permissions.js` resolution completely. A user whose membership status is `suspended` receives an empty set on gated routes, but can still interact with public invite redemption or attempt authentication.
- **Default Organization Ordering (A8)**:
  - In `POST /v1/auth/login` and `POST /v1/auth/refresh`, when no `orgId` is provided in the request body, the server selects the user's first active membership ordered alphabetically by organization name (`ORDER BY o.name ASC`).
  - This observation explains why `check-api.js:80`, `:88`, and `:142` expect users with multiple memberships (Dana, Sam) to default into "Acme Robotics" rather than "Globex Industries" ("A" comes before "G").
- **Verification**:
  - Ran `node scripts/check-api.js`: **ALL PASS (66 passed, 0 failed)** across auth, structural isolation, role bundles, row inclusion, compound sessions, grandfathering, suspension cascade, rank modification, invites, and audit pagination.

## Phase 7 — the console

**2026-09-26 · Presence vs state, the server-driven DOM, and zero-storage auth**

- **Where instinct and the security contract disagreed**:
  - *Presence vs State*: Frontend instincts usually tell developers to render buttons in a disabled state (`disabled={true}`) with a tooltip explaining what permission or role is required. But RemoteOps enforces a strict **presence-only contract**: elements are either present and unlocked (`data-state="unlocked"`), or entirely absent from the DOM. Advertising actions a person cannot take is an information leak and an invitation to attack the underlying endpoint.
  - *The Architecture Test*: A developer might be tempted to speed up rendering by writing `if (user.role === 'owner')` in React components. But `tests/ui.spec.js:139` ("an element vanishes when the server withdraws the permission") tests specifically for this: it mocks the server response to return `deny` for an owner on `device:control`. Because our UI components (`Action.jsx`) rely strictly on `device.permissions['device:control'].effect === 'allow'`, the control vanishes immediately. The frontend is a dumb terminal; the server is the sole engine of authorization.
  - *Dynamic role catalogue in the UI*: While documentation mentions five roles, the candidate nonce injects custom roles (such as `reviewer`). Hardcoding `<option value="admin">` in `People.jsx` would prevent managing users with unannounced roles. We made the role catalogue in `People.jsx` dynamic, aggregating `['owner', 'admin', 'operator', 'auditor', 'viewer']` with roles returned by the memberships and session payloads.
- **In-Memory Authentication Lifecycle**:
  - The access token is held strictly in JavaScript module memory (`web/api.js`). No token is ever written to `localStorage` or `sessionStorage` (verified by `tests/ui.spec.js:201`).
  - Session restoration on page refresh relies entirely on `POST /v1/auth/refresh` sending the `httpOnly` cookie.
- **Visual Distinction via Org Themes**:
  - Switching between organizations dynamically mutates `data-org-theme` on `[data-testid="app-shell"]`, driving theme CSS variables that alter computed background colors, satisfying the requirement that tenant boundaries are immediately visually legible.
- **UI Contract Test Verification**:
  - Ran `npx playwright test`: **25 passed, 0 failed** across all 25 contract specifications.

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._


