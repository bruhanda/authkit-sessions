# `@authkit/sessions` — Hono adapter sandbox

A four-route Hono app (`/sign-in`, `/me`, `/csrf`, `/action`,
`/sign-out`) driven directly through `app.fetch(req)` — no port binding
needed, because Hono speaks Web Standards natively.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/with-hono)

## Run locally

```bash
npm install
npm start
```

## What gets demonstrated

- `honoSessions(manager)` middleware exposes `c.var.sessions` and
  `c.var.session` — both fully typed.
- CSRF runs automatically on `POST` / `PUT` / `PATCH` / `DELETE` once a
  session exists; the script asserts the 403-without-token, 200-with
  flow.
- The same `SessionManager` object would run unchanged on Cloudflare
  Workers, Bun, Deno, or Vercel Edge — Hono's `app.fetch(req)` is the
  contract.

Output is a sequence of `METHOD /path: status body` lines, one per call
the driver makes against the in-memory app.
