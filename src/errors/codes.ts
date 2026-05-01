/**
 * Closed enumeration of stable error codes thrown or surfaced by the
 * library. Each code maps to a single failure mode; consumers branch on
 * `error.code` rather than parsing the message.
 *
 * `SECRET_TOO_SHORT` exists because we require ≥256 bits of entropy in the
 * supplied secret — HKDF itself works on any input length, but anything
 * below the entropy floor is a security weakness.
 */
export const SESSION_ERROR_CODES = [
  'INVALID_COOKIE',
  'INVALID_SIGNATURE',
  'EXPIRED',
  'NOT_FOUND',
  'CONFLICT',
  'CONCURRENCY_DENIED',
  'CSRF_INVALID',
  'CSRF_MISSING',
  'STORE_UNAVAILABLE',
  'SECRET_TOO_SHORT',
  'CONFIG_INVALID',
  'PAYLOAD_TOO_LARGE',
  'FINGERPRINT_MISMATCH',
] as const;

export type SessionErrorCode = (typeof SESSION_ERROR_CODES)[number];
