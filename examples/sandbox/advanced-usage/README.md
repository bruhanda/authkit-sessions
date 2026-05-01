# `@authkit/sessions` — advanced-usage sandbox

Production-shaped scenario with every opt-in feature switched on at
once.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/advanced-usage)

## Run locally

```bash
npm install
npm start
```

## Features exercised

| Feature | What the script asserts |
| --- | --- |
| Concurrent session limits (`max=3`, `lru`) | Creating a fourth device evicts the LRU; `listByUser` returns 3. |
| `rotate()` after privilege change | The id and CSRF token both change while the data survives. |
| CSRF (double-submit cookie) | `verifyCsrf(token)` is `true`; a forged token returns `false`. |
| Device fingerprint mismatch (`onMismatch: 'rotate'`) | Same cookie + different UA → session preserved, flagged for rotation. |
| Active devices UI (`listByUser`) | Prints id / UA / lastSeen for each live device. |
| `revokeByUser` | "Log out everywhere" — returns the number of sessions removed. |
| Concurrency `deny-new` | Second create for the same user throws `CONCURRENCY_DENIED`. |
| Audit hook | `composeAuditHook` fans events out to stdout + an in-memory tally. |

The `[audit] {...}` JSON lines on stdout are the discriminated-union
events the manager emits — that's the integration point for OTel /
Sentry / your own metrics.
