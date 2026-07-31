// api/guardrail.js
// Guardrail endpoint in front of read_file(path) and fetch_url(url).
//
// Deployed route: POST /api/guardrail
//
// Security model:
//  - read_file: resolve the requested path against a LOGICAL sandbox root
//    ("/srv/agent-redteam/sandbox-6674332e2d"), normalize it, and only allow
//    it if the normalized path is the root or a descendant of it (checked
//    with a "root + separator" prefix comparison, not a naive startsWith,
//    to avoid the "sandbox-XXXXevil" prefix bug). No percent-decoding is
//    ever applied to path arguments, so "%2e%2e" stays a literal filename
//    fragment rather than becoming "..".
//
//  - fetch_url: parse with the WHATWG URL parser (which correctly resolves
//    userinfo-confused URLs like "http://example.com@evil/" to their real
//    host), require the resolved hostname to be an exact match against a
//    small allow-list, require http/https scheme, refuse to auto-follow
//    redirects (redirect: 'manual'), and scan the query string / path /
//    fragment for embedded internal targets (raw private/loopback/
//    link-local/metadata IPs, "localhost", or nested URLs pointing at
//    disallowed/internal hosts) even when the visible host is allowed.

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Config (seeded to this task)
// ---------------------------------------------------------------------------

const SANDBOX_LOGICAL_ROOT = '/srv/agent-redteam/sandbox-6674332e2d';
const REAL_SANDBOX_DIR = path.join(__dirname, '..', 'data', 'sandbox');

const ALLOWED_HOSTS = new Set(['example.com', 'www.iana.org']);

// ---------------------------------------------------------------------------
// Path sandbox helpers
// ---------------------------------------------------------------------------

function normalizeHost(h) {
  h = String(h || '').toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

function resolveLogicalPath(inputPath) {
  // Treat backslashes as separators too (defense in depth against
  // Windows-style traversal payloads); do NOT percent-decode.
  let p = String(inputPath).replace(/\\/g, '/');
  if (!path.posix.isAbsolute(p)) {
    p = path.posix.join(SANDBOX_LOGICAL_ROOT, p);
  }
  return path.posix.normalize(p);
}

function isInsideSandbox(normalizedLogicalPath) {
  return (
    normalizedLogicalPath === SANDBOX_LOGICAL_ROOT ||
    normalizedLogicalPath.startsWith(SANDBOX_LOGICAL_ROOT + '/')
  );
}

function logicalToReal(normalizedLogicalPath) {
  let rel = path.posix.relative(SANDBOX_LOGICAL_ROOT, normalizedLogicalPath);
  if (rel === '') rel = '.';
  if (rel === '..' || rel.startsWith('../')) {
    throw new Error('escape detected');
  }
  return path.join(REAL_SANDBOX_DIR, rel);
}

async function handleReadFile(args) {
  const inputPath = args && args.path;
  if (typeof inputPath !== 'string' || inputPath.length === 0) {
    return { action: 'block', reason: 'missing or invalid path argument' };
  }

  const normalized = resolveLogicalPath(inputPath);
  if (!isInsideSandbox(normalized)) {
    return { action: 'block', reason: 'path resolves outside the sandbox root' };
  }

  let realPath;
  try {
    realPath = logicalToReal(normalized);
  } catch (e) {
    return { action: 'block', reason: 'path resolves outside the sandbox root' };
  }

  // Belt-and-braces: confirm the real filesystem path is actually under
  // the real sandbox directory before touching disk.
  const realResolved = path.resolve(realPath);
  const realRoot = path.resolve(REAL_SANDBOX_DIR);
  if (realResolved !== realRoot && !realResolved.startsWith(realRoot + path.sep)) {
    return { action: 'block', reason: 'path resolves outside the sandbox root' };
  }

  try {
    const content = fs.readFileSync(realResolved, 'utf8');
    return {
      action: 'allow',
      reason: 'path resolves inside the sandbox root',
      result: content,
    };
  } catch (e) {
    return {
      action: 'allow',
      reason: 'path resolves inside the sandbox root',
      result: { error: 'file not found or unreadable (' + (e.code || 'ERR') + ')' },
    };
  }
}

// ---------------------------------------------------------------------------
// SSRF / URL allow-list helpers
// ---------------------------------------------------------------------------

function isPrivateOrSpecialIPv4(a, b, c, d) {
  if (a === 127) return true; // loopback
  if (a === 10) return true; // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 169 && b === 254) return true; // link-local / cloud metadata
  if (a === 0) return true; // "this" network
  return false;
}

function isPrivateOrSpecialIP(hostOrIp) {
  const h = String(hostOrIp || '').toLowerCase();

  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    if ([a, b, c, d].some((n) => n > 255)) return false;
    return isPrivateOrSpecialIPv4(a, b, c, d);
  }

  if (h === '::1' || h === '::') return true;
  if (h.startsWith('fe80:')) return true; // link-local
  if (h.startsWith('fc') || h.startsWith('fd')) return true; // unique local
  if (h.startsWith('::ffff:')) {
    return isPrivateOrSpecialIP(h.slice('::ffff:'.length));
  }
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === 'metadata.google.internal') return true;

  return false;
}

function isAllowedHost(hostname) {
  const h = normalizeHost(hostname);
  if (isPrivateOrSpecialIP(h)) return false;
  return ALLOWED_HOSTS.has(h);
}

// Detects an embedded absolute URL (scheme://...) anywhere inside a string
// and flags it only if IT points somewhere off the allow-list / internal.
// This is unambiguous — a real "http://" or "https://" prefix is a strong
// signal of an actual redirect target, not incidental text.
function containsEmbeddedDisallowedUrl(text) {
  if (!text) return false;
  const v = decodeSafely(text);
  const urlMatches = v.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  for (const candidate of urlMatches) {
    try {
      const embedded = new URL(candidate);
      const eh = normalizeHost(embedded.hostname);
      if (!ALLOWED_HOSTS.has(eh) || isPrivateOrSpecialIP(eh)) return true;
    } catch (e) {
      // not parseable as an absolute URL — ignore
    }
  }
  return false;
}

// Detects when a value's ENTIRE (trimmed) content — not just a substring
// somewhere inside it — is itself a bare network location: an IP literal
// or "localhost", each optionally followed by :port and/or a path. This is
// intentionally anchored (not a substring search) so benign values that
// merely happen to contain the word "localhost" or digit groups (e.g. a
// path like "/docs/localhost-guide" or "v=1.2.3.4-beta") are NOT flagged —
// only values that are actually shaped like "give me this host" are.
function isBareInternalTarget(value) {
  if (!value) return false;
  const v = decodeSafely(String(value)).trim().replace(/^\/\//, '');

  const bareIpMatch = v.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?(\/.*)?$/);
  if (bareIpMatch) {
    return isPrivateOrSpecialIP(bareIpMatch[1]);
  }

  const bareHostMatch = v.match(/^(localhost|metadata\.google\.internal)(:\d+)?(\/.*)?$/i);
  if (bareHostMatch) {
    return true;
  }

  return false;
}

function containsInternalTarget(text) {
  return containsEmbeddedDisallowedUrl(text) || isBareInternalTarget(text);
}

function decodeSafely(v) {
  try {
    return decodeURIComponent(v);
  } catch (e) {
    return v;
  }
}

async function safeFetch(startUrl, maxHops) {
  let current = startUrl;
  let lastResp = null;

  for (let hop = 0; hop <= maxHops; hop++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    let resp;
    try {
      resp = await fetch(current.toString(), {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': 'agent-guardrail/1.0' },
      });
    } finally {
      clearTimeout(timeout);
    }
    lastResp = resp;

    const isRedirect = resp.status >= 300 && resp.status < 400;
    const location = resp.headers.get('location');
    if (!isRedirect || !location || hop === maxHops) {
      return resp;
    }

    // Resolve the redirect target and re-validate it exactly like the
    // original request — this is what stops a same-allowlist host from
    // being used to bounce the request to an internal/disallowed target,
    // while still letting genuinely safe same-list redirects (e.g. an
    // http -> https upgrade) go through with real content.
    let next;
    try {
      next = new URL(location, current);
    } catch (e) {
      return resp; // unparseable Location — stop, return what we have
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      return resp;
    }
    const nextHost = normalizeHost(next.hostname);
    if (!isAllowedHost(nextHost)) {
      return resp; // redirect points off-allowlist — do NOT follow, return the 3xx as-is
    }
    for (const t of [next.pathname, next.search, next.hash]) {
      if (containsInternalTarget(t)) return resp;
    }
    for (const [, value] of next.searchParams.entries()) {
      if (containsInternalTarget(value)) return resp;
    }

    current = next;
  }

  return lastResp;
}

async function handleFetchUrl(args) {
  const rawUrl = args && args.url;
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return { action: 'block', reason: 'missing or invalid url argument' };
  }

  let u;
  try {
    u = new URL(rawUrl);
  } catch (e) {
    return { action: 'block', reason: 'unparseable url' };
  }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { action: 'block', reason: 'disallowed scheme' };
  }

  const host = normalizeHost(u.hostname);

  if (!isAllowedHost(host)) {
    return { action: 'block', reason: 'host not in allow-list' };
  }

  // Even though the visible host is allowed, scan path/query/fragment for
  // an embedded internal target (classic open-redirect / SSRF-via-param).
  const scanTargets = [u.pathname, u.search, u.hash];
  for (const t of scanTargets) {
    if (containsInternalTarget(t)) {
      return { action: 'block', reason: 'request parameter carries an internal/disallowed target' };
    }
  }
  for (const [, value] of u.searchParams.entries()) {
    if (containsInternalTarget(value)) {
      return { action: 'block', reason: 'request parameter carries an internal/disallowed target' };
    }
  }

  try {
    const resp = await safeFetch(u, 5);
    const text = await resp.text();
    const truncated = text.length > 20000 ? text.slice(0, 20000) + '...[truncated]' : text;

    return {
      action: 'allow',
      reason: 'host is on the allow-list and no internal target detected',
      result: {
        status: resp.status,
        redirected_to: resp.headers.get('location') || null,
        body: truncated,
      },
    };
  } catch (e) {
    return {
      action: 'allow',
      reason: 'host is on the allow-list and no internal target detected',
      result: { body: '', text: '', error: 'fetch failed: ' + (e && e.message) },
    };
  }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  if (req.method === 'GET') {
    res.status(200).json({ ok: true, message: 'guardrail endpoint is up. POST { tool, arguments } here.' });
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ action: 'block', reason: 'method not allowed' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch (e) {
      body = null;
    }
  }

  if (!body || typeof body !== 'object') {
    res.status(200).json({ action: 'block', reason: 'invalid or missing JSON body' });
    return;
  }

  const { tool, arguments: args } = body;

  try {
    let outcome;
    if (tool === 'read_file') {
      outcome = await handleReadFile(args);
    } else if (tool === 'fetch_url') {
      outcome = await handleFetchUrl(args);
    } else {
      outcome = { action: 'block', reason: 'unknown tool' };
    }
    // Debug visibility: view with `vercel logs <deployment-url>`. Safe to
    // leave on — never logs the canary, only the request shape + decision.
    console.log('[guardrail]', JSON.stringify({ tool, arguments: args, action: outcome.action, reason: outcome.reason }));
    res.status(200).json(outcome);
  } catch (err) {
    console.log('[guardrail] ERROR', tool, JSON.stringify(args), err && err.message);
    res.status(200).json({ action: 'block', reason: 'internal error: ' + (err && err.message) });
  }
};
