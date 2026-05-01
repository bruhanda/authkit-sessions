# `@authkit/sessions` — Express compatibility sandbox

Same flow as the Hono sandbox, but driven through a real `http.Server`
on a random port because Express expects Node's `req`/`res` objects.
The middleware bridges between Express and Web Standards so the *same*
`SessionManager` instance runs identically on the edge and in Express.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/with-express)

## Run locally

```bash
npm install
npm start
```

## What gets demonstrated

- `expressSessions(manager)` middleware sets `req.session` /
  `req.sessions` on every request after the body parser.
- The exported `ExpressSessionRequest<T>` interface gives you
  module-augmentation typing without `any` casts — the example wires it
  up with a global `declare`.
- CSRF enforcement on protected methods works exactly as on the edge
  (the same `csrf()` feature handle is reused).
- The driver hits `/sign-in`, `/me`, `/csrf`, `/action` (without and
  with `x-csrf-token`), and `/sign-out` to walk the full happy path.

Output is the same `METHOD /path: status body` shape as the Hono
sandbox so the two adapters are easy to compare side-by-side.
