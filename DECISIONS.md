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

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.
