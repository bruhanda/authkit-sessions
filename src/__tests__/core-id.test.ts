import { describe, expect, it } from 'vitest';
import { generateCsrfToken, generateSessionId, SESSION_ID_LENGTH } from '../core/id.js';

describe('generateSessionId', () => {
  it('should produce a 43-character base64url string', () => {
    const id = generateSessionId();
    expect(id.length).toBe(SESSION_ID_LENGTH);
    expect(id.length).toBe(43);
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should produce a fresh id each invocation', () => {
    expect(generateSessionId()).not.toBe(generateSessionId());
  });
});

describe('generateCsrfToken', () => {
  it('should produce a 43-character base64url string', () => {
    const token = generateCsrfToken();
    expect(token.length).toBe(43);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should produce a fresh token each invocation', () => {
    expect(generateCsrfToken()).not.toBe(generateCsrfToken());
  });
});

describe('SESSION_ID_LENGTH constant', () => {
  it('should be exported as 43 (base64url of 32 bytes)', () => {
    expect(SESSION_ID_LENGTH).toBe(43);
  });
});
