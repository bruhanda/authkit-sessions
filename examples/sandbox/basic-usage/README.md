# `@authkit/sessions` — basic-usage sandbox

Minimal walk-through of the four read/write paths: `create`, `get`,
`update`, `signOut`. Uses the in-memory store, so it runs anywhere with
no infrastructure.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/basic-usage)

## Run locally

```bash
npm install
npm start
```

## What the script does

1. **Create** a typed session for `userId: 'user_42'` and inspect the
   generated `Set-Cookie`.
2. **Read** the session back from a follow-up request — the typed payload
   propagates with no casts.
3. **Update** the payload via a pure mutator.
4. **Mutate without a session** — confirms `SessionError('NOT_FOUND')`.
5. **Sign out** and confirm the next read returns `null`.

The output is a numbered five-step trace; all session ids are truncated
so the log stays readable.
