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

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
