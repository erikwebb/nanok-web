import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

describe('Static Security & Regression Audit', () => {
  const indexHtml = fs.readFileSync(path.join(rootDir, 'index.html'), 'utf8');
  const headersConfig = fs.readFileSync(path.join(rootDir, '_headers'), 'utf8');

  test('ensures no raw email address or mailto links exist in index.html', () => {
    // Prohibit mailto: links
    assert.doesNotMatch(indexHtml, /mailto:/i, 'index.html must not contain mailto links');

    // Prohibit nanok.consulting email addresses
    assert.doesNotMatch(
      indexHtml,
      /[a-zA-Z0-9._%+-]+@nanok\.consulting/i,
      'index.html must not contain raw @nanok.consulting email addresses'
    );
  });

  test('ensures all internal navigation anchor links resolve to valid element IDs', () => {
    const anchorMatches = [...indexHtml.matchAll(/href="#([a-zA-Z0-9_-]+)"/g)].map(m => m[1]);
    assert.ok(anchorMatches.length > 0, 'index.html should have internal anchor links');

    for (const targetId of anchorMatches) {
      const hasId = indexHtml.includes(`id="${targetId}"`);
      assert.ok(hasId, `Anchor link #${targetId} must have matching id="${targetId}" element`);
    }
  });

  test('ensures critical security headers are configured in _headers', () => {
    const requiredHeaders = [
      'X-Content-Type-Options: nosniff',
      'X-Frame-Options: DENY',
      'Referrer-Policy: strict-origin-when-cross-origin',
      'Strict-Transport-Security:',
      'Content-Security-Policy:',
      'Cross-Origin-Opener-Policy: same-origin',
      'Permissions-Policy:'
    ];

    for (const header of requiredHeaders) {
      assert.ok(
        headersConfig.includes(header),
        `_headers must contain required security header: ${header}`
      );
    }
  });

  test('ensures Content-Security-Policy permits required external sources', () => {
    assert.match(headersConfig, /https:\/\/challenges\.cloudflare\.com/, 'CSP must allow Cloudflare Turnstile');
    assert.match(headersConfig, /https:\/\/cdn\.tailwindcss\.com/, 'CSP must allow Tailwind CDN');
    assert.match(headersConfig, /https:\/\/fonts\.googleapis\.com/, 'CSP must allow Google Fonts CSS');
    assert.match(headersConfig, /https:\/\/fonts\.gstatic\.com/, 'CSP must allow Google Fonts font files');
  });

  test('ensures Open Graph and essential metadata tags exist in index.html', () => {
    assert.match(indexHtml, /<meta name="viewport"/, 'Viewport meta tag required');
    assert.match(indexHtml, /<link rel="canonical"/, 'Canonical link tag required');
    assert.match(indexHtml, /<meta name="description"/, 'Meta description tag required');
    assert.match(indexHtml, /<meta property="og:title"/, 'OpenGraph title required');
    assert.match(indexHtml, /<meta property="og:description"/, 'OpenGraph description required');
    assert.match(indexHtml, /<meta property="og:image"/, 'OpenGraph image required');
    assert.match(indexHtml, /<link rel="icon"/, 'Favicon link tag required');
  });

  test('ensures Turnstile widget is embedded with production sitekey', () => {
    assert.match(
      indexHtml,
      /cf-turnstile.*data-sitekey="0x4AAAAAAF36-ycpUqHxfogk"/,
      'Production Turnstile widget with sitekey must be present'
    );
  });
});
