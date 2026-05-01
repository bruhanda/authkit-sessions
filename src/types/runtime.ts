/**
 * Minimal duck-typed view of `Request` — enough for cookie reads and CSRF
 * verification, no body / streaming surface. Lets the engine accept inputs
 * from frameworks that wrap `Request` in their own type without forcing a
 * dependency on a specific runtime's `Request` constructor.
 *
 * In practice every supported runtime ships a real `Request`; this type
 * exists for tests and edge-case framework integrations.
 */
export interface MinimalRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Headers;
}
