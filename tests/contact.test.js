import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { onRequestPost } from '../functions/api/contact.js';

describe('Cloudflare Pages Function: /api/contact', () => {
  const originalFetch = globalThis.fetch;
  const validSecret = 'test_secret_key_12345';
  const validEnv = { TURNSTILE_SECRET_KEY: validSecret };

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function createRequest(body, options = {}) {
    const headers = new Headers({
      'Content-Type': options.contentType || 'application/json',
      'Host': options.host || 'nanok.consulting',
      ...(options.origin ? { 'Origin': options.origin } : {}),
      ...(options.contentLength ? { 'Content-Length': String(options.contentLength) } : {})
    });

    const bodyString = typeof body === 'string' ? body : JSON.stringify(body);

    return new Request('https://nanok.consulting/api/contact', {
      method: 'POST',
      headers,
      body: bodyString
    });
  }

  test('rejects unsupported media type with 415', async () => {
    const req = new Request('https://nanok.consulting/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', 'Host': 'nanok.consulting' },
      body: 'invalid format'
    });

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 415);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Unsupported Media Type/i);
  });

  test('rejects cross-origin requests from mismatching host with 403', async () => {
    const req = createRequest(
      { name: 'Alice', email: 'alice@example.com', message: 'Hello' },
      { origin: 'https://malicious-site.com', host: 'nanok.consulting' }
    );

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 403);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Cross-origin request forbidden/i);
  });

  test('rejects payload exceeding size limit with 413', async () => {
    const req = createRequest(
      { name: 'Alice', email: 'alice@example.com', message: 'Hello' },
      { contentLength: 70 * 1024 } // 70 KB > 64 KB limit
    );

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 413);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Payload exceeds size limit/i);
  });

  test('silently captures and ignores spam honeypot with 200', async () => {
    const req = createRequest({
      name: 'Bot Spammer',
      email: 'bot@spam.com',
      message: 'Spam text',
      honeypot: 'i-am-a-bot'
    });

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.note, 'Ignored spam');
  });

  test('rejects missing required fields with 400', async () => {
    const req = createRequest({ name: '', email: 'test@example.com', message: '' });
    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Name, email, and message are required/i);
  });

  test('rejects invalid email address with 400', async () => {
    const req = createRequest({ name: 'Alice', email: 'not-an-email', message: 'Hi' });
    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /valid work email/i);
  });

  test('rejects fields exceeding permitted length limits with 400', async () => {
    const longName = 'A'.repeat(101); // max is 100
    const req = createRequest({ name: longName, email: 'alice@example.com', message: 'Hi' });
    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Field length exceeds permitted limits/i);
  });

  test('fails closed with 500 when TURNSTILE_SECRET_KEY is missing from env', async () => {
    const req = createRequest({
      name: 'Alice',
      email: 'alice@example.com',
      message: 'Hi',
      'cf-turnstile-response': 'sample_token'
    });

    const res = await onRequestPost({ request: req, env: {} }); // empty env
    assert.equal(res.status, 500);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Server configuration error/i);
  });

  test('rejects missing Turnstile token with 400', async () => {
    const req = createRequest({
      name: 'Alice',
      email: 'alice@example.com',
      message: 'Hi'
    });

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Security verification required/i);
  });

  test('rejects failed Turnstile siteverify outcome with 403', async () => {
    globalThis.fetch = async (url) => {
      if (String(url).includes('challenges.cloudflare.com')) {
        return new Response(JSON.stringify({
          success: false,
          'error-codes': ['invalid-input-response']
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return originalFetch(url);
    };

    const req = createRequest({
      name: 'Alice',
      email: 'alice@example.com',
      message: 'Hi',
      'cf-turnstile-response': 'rejected_token'
    });

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 403);
    const data = await res.json();
    assert.equal(data.success, false);
    assert.match(data.error, /Security verification failed/i);
  });

  test('accepts valid submission and verifies Turnstile token successfully with 200', async () => {
    globalThis.fetch = async (url, options) => {
      if (String(url).includes('challenges.cloudflare.com')) {
        return new Response(JSON.stringify({
          success: true,
          hostname: 'nanok.consulting',
          challenge_ts: new Date().toISOString()
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return originalFetch(url, options);
    };

    const req = createRequest({
      name: 'Alex Morgan',
      email: 'alex@company.com',
      organization: 'Acme Corp',
      service: 'Distributed Systems Architecture',
      message: 'We are decoupling a monolithic application and looking for architectural advisory.',
      'cf-turnstile-response': 'valid_verified_token'
    });

    const res = await onRequestPost({ request: req, env: validEnv });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.match(data.message, /Thank you for reaching out/i);
  });
});
