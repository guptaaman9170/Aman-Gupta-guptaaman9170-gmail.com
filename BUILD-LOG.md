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

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

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
