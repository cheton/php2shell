import http from 'node:http';
import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const USER_AGENT = 'PHP2Shell-Exposure-Checker';
const DEADLINE_MS = 10_000;
const MAX_REDIRECTS = 3;
const MAX_HEADER_SIZE = 16 * 1024;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_EVIDENCE = 8;
const MAX_WARNINGS = 12;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);

const GENERIC_WARNINGS = [
  'PHP signals are indicators only; this scan does not verify exploitability or prove that the site is safe.',
  'Vendor or distribution backports can change the effective patch status; verify with your PHP vendor or OS distribution.',
];

export class ScanError extends Error {
  constructor(message, statusCode = 502, options = {}) {
    super(message, options && typeof options === 'object' ? options : undefined);
    this.name = 'ScanError';
    this.statusCode = statusCode;
  }
}

function stripBrackets(hostname) {
  if (typeof hostname !== 'string') return '';
  return hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
}

function isLocalHostname(hostname) {
  const lower = hostname.toLowerCase().replace(/\.$/, '');
  return lower === 'localhost' || lower.endsWith('.localhost');
}

function parseIPv4(address) {
  if (typeof address !== 'string') return null;
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part[0] === '0') return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }
  return octets;
}

function parseIPv6(address) {
  if (typeof address !== 'string') return null;
  let value = address.trim();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  if (value === '' || value.includes('%')) return null;

  const lastColon = value.lastIndexOf(':');
  if (lastColon === -1) return null;
  const tail = value.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = parseIPv4(tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] === '' ? [] : halves[0].split(':');
  const right = halves.length === 2 ? (halves[1] === '' ? [] : halves[1].split(':')) : [];
  let groups;
  if (halves.length === 1) {
    if (left.length !== 8) return null;
    groups = left;
  } else {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...new Array(missing).fill('0'), ...right];
  }
  if (groups.length !== 8) return null;

  const numbers = [];
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    numbers.push(Number.parseInt(group, 16));
  }
  return numbers;
}

function isPublicIPv4([a, b, c]) {
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192) {
    if (b === 0 && (c === 0 || c === 2)) return false;
    if (b === 31 && c === 196) return false;
    if (b === 52 && c === 193) return false;
    if (b === 88 && c === 99) return false;
    if (b === 168) return false;
    if (b === 175 && c === 48) return false;
  }
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return a < 224;
}

function isPublicIPv6([a, b, c, d, e, f, g, h]) {
  if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0 && f === 0 && g === 0 && h <= 1) return false;
  // Conservative: reject every IPv4-mapped IPv6 address, including mapped
  // public IPv4, rather than normalising it into an IPv4 check.
  if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0 && f === 0xffff) return false;
  if (a === 0 && b === 0 && c === 0 && d === 0 && e === 0 && f === 0) return false;
  if (a === 0x0064 && b === 0xff9b) return false;
  if (a === 0x0100 && b === 0 && c === 0 && d === 0) return false;
  if (a === 0x2001 && b <= 0x01ff) return false;
  if (a === 0x2001 && b === 0x0db8) return false;
  if (a === 0x2002 || a === 0x3ffe) return false;
  if (a === 0x3fff && b <= 0x0fff) return false;
  if (a === 0x2620 && b === 0x004f && c === 0x8000) return false;
  if ((a & 0xfe00) === 0xfc00) return false;
  if ((a & 0xffc0) === 0xfe80) return false;
  if ((a & 0xff00) === 0xff00) return false;
  return (a & 0xe000) === 0x2000;
}

export function isPublicAddress(address) {
  if (typeof address !== 'string') return false;
  const value = stripBrackets(address.trim());
  if (value === '') return false;
  const v4 = parseIPv4(value);
  if (v4) return isPublicIPv4(v4);
  const v6 = parseIPv6(value);
  return v6 ? isPublicIPv6(v6) : false;
}

function cleanVersion(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed.length > 64) return null;
  return /^\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9.+~_-]*)$/.test(trimmed) ? trimmed : null;
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9.+~_-]*)$/.exec(version);
  if (!match) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = match[3] === undefined ? null : Number(match[3]);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)) return null;
  if (patch !== null && !Number.isSafeInteger(patch)) return null;
  return { major, minor, patch, suffix: match[4] };
}

function isPrerelease(suffix) {
  return Boolean(suffix) && /(?:^|[-+~.])(?:alpha|beta|rc|dev|snapshot|preview|pre|nightly|git|svn)[0-9]*/i.test(suffix);
}

function isVendorSuffix(suffix) {
  if (!suffix || !/^[-+~]/.test(suffix)) return false;
  return /(?:ubuntu|deb|el\d+|fc\d+|mga\d+|remi|ius|sury|webtatic|amzn\d*|rhel|centos|fedora|mageia|opensuse|suse|alpine|r\d+)/i.test(suffix);
}

function versionBase(version) {
  const parsed = parseVersion(version);
  return parsed
    ? `${parsed.major}.${parsed.minor}.${parsed.patch === null ? 'x' : parsed.patch}`
    : version.toLowerCase();
}

export function classifyPhpVersion(version) {
  const cleaned = cleanVersion(version);
  const parsed = cleaned ? parseVersion(cleaned) : null;
  if (!parsed) return { status: 'unknown', reason: 'unrecognized', warnings: [] };

  const { major, minor, patch, suffix } = parsed;
  const warnings = [];
  if (patch === null) {
    warnings.push(`PHP ${major}.${minor} does not disclose a patch level; exposure cannot be determined.`);
    return { status: 'unknown', reason: 'missing-patch', warnings };
  }
  if (isPrerelease(suffix)) {
    warnings.push('The reported PHP version is a pre-release; exposure cannot be determined.');
    return { status: 'unknown', reason: 'prerelease', warnings };
  }
  if (suffix !== '') {
    if (!isVendorSuffix(suffix)) {
      warnings.push('The reported PHP version has an unrecognized suffix; exposure cannot be determined.');
      return { status: 'unknown', reason: 'unrecognized-suffix', warnings };
    }
    warnings.push('The reported PHP version includes a vendor or distribution suffix; verify its backport status with your vendor.');
  }

  if (major === 8 && minor >= 2 && minor <= 5) {
    const threshold = minor === 2 ? 35 : minor === 3 ? 36 : minor === 4 ? 27 : 12;
    const status = patch >= threshold ? 'patched' : 'affected';
    return { status, reason: status, warnings };
  }
  if (major === 7 || (major === 8 && minor <= 1) || (major === 5 && minor >= 4 && minor <= 6)) {
    warnings.push('PHP 5.4–8.1 is affected by the upstream advisory but is end-of-life; verify distribution backports.');
    return { status: 'affected', reason: 'legacy', warnings };
  }
  warnings.push(`PHP ${major}.${minor} is outside the branches covered by the advisory; exposure cannot be determined.`);
  return { status: 'unknown', reason: 'unknown-branch', warnings };
}

function extractVersions(value) {
  if (typeof value !== 'string') return [];
  const pattern = /\bPHP[ \t]*(?:[\/-][ \t]*)?v?(\d+\.\d+[0-9A-Za-z.+~_-]*)/gi;
  const versions = [];
  for (const match of value.matchAll(pattern)) {
    const cleaned = cleanVersion(match[1]);
    if (cleaned) versions.push(cleaned);
  }
  return versions;
}

function collectHeaders(rawHeaders) {
  const headers = new Map();
  const values = Array.isArray(rawHeaders) ? rawHeaders : [];
  for (let i = 0; i + 1 < values.length; i += 2) {
    const name = String(values[i]).toLowerCase();
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(String(values[i + 1]));
  }
  return headers;
}

function getHeader(rawHeaders, name) {
  if (!Array.isArray(rawHeaders)) return null;
  const wanted = name.toLowerCase();
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (String(rawHeaders[i]).toLowerCase() === wanted) return String(rawHeaders[i + 1]);
  }
  return null;
}

function bound(items, maxItems, maxLength = 240) {
  const output = [];
  const seen = new Set();
  for (const item of items) {
    if (typeof item !== 'string') continue;
    const text = item.replace(/\s+/g, ' ').trim().slice(0, maxLength);
    if (text === '' || seen.has(text)) continue;
    seen.add(text);
    output.push(text);
    if (output.length >= maxItems) break;
  }
  return output;
}

export function inspectPhpHeaders(rawHeaders) {
  const headers = collectHeaders(rawHeaders);
  const evidence = [];
  const warnings = [...GENERIC_WARNINGS];
  const found = [];
  let phpDetected = false;
  let cookieDetected = false;

  for (const name of ['x-powered-by', 'server']) {
    const label = name === 'server' ? 'Server' : 'X-Powered-By';
    for (const value of headers.get(name) ?? []) {
      const versions = extractVersions(value);
      if (versions.length === 0) {
        if (/\bPHP\b/i.test(value)) {
          phpDetected = true;
          evidence.push(`${label} indicated PHP without a version.`);
        }
        continue;
      }
      phpDetected = true;
      for (const version of versions) {
        found.push({ source: label, version });
        evidence.push(`${label} reported PHP ${version}.`);
      }
    }
  }

  for (const value of headers.get('set-cookie') ?? []) {
    const first = value.split(';', 1)[0].trim();
    const equals = first.indexOf('=');
    if (equals > 0 && first.slice(0, equals).trim().toLowerCase() === 'phpsessid') {
      cookieDetected = true;
      break;
    }
  }
  if (cookieDetected) {
    phpDetected = true;
    evidence.push('A PHPSESSID cookie was set.');
  }

  const unique = [];
  const seen = new Set();
  for (const item of found) {
    const key = item.version.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
  }
  const versions = unique.map((item) => item.version);

  if (!phpDetected) {
    return {
      phpDetected: false,
      version: null,
      versions: [],
      status: 'not-detected',
      evidence: bound(['No PHP indicators were found in the response headers.'], MAX_EVIDENCE, 200),
      warnings: bound([...warnings, 'No PHP header signal was found; exposure is undetermined.'], MAX_WARNINGS),
    };
  }
  if (unique.length === 0) {
    return {
      phpDetected: true,
      version: null,
      versions: [],
      status: 'unknown',
      evidence: bound(evidence, MAX_EVIDENCE, 200),
      warnings: bound([...warnings, 'PHP was detected, but no version was disclosed; exposure is undetermined.'], MAX_WARNINGS),
    };
  }

  const bases = new Set(unique.map((item) => versionBase(item.version)));
  const classifications = unique.map((item) => classifyPhpVersion(item.version));
  const statuses = new Set(classifications.map((item) => item.status));
  for (const classification of classifications) warnings.push(...classification.warnings);

  if (bases.size > 1 || statuses.size > 1) {
    const reported = unique.slice(0, 3).map((item) => item.version).join(', ');
    return {
      phpDetected: true,
      version: null,
      versions,
      status: 'unknown',
      evidence: bound(evidence, MAX_EVIDENCE, 200),
      warnings: bound([
        ...warnings,
        `Conflicting PHP version signals were reported: ${reported}.`,
        'Exposure cannot be determined from conflicting version signals.',
      ], MAX_WARNINGS),
    };
  }

  return {
    phpDetected: true,
    version: unique[0].version,
    versions,
    status: classifications[0].status,
    evidence: bound(evidence, MAX_EVIDENCE, 200),
    warnings: bound(warnings, MAX_WARNINGS),
  };
}

function findPhpRefs(html) {
  if (typeof html !== 'string' || html === '') return 0;
  const pattern = /(?:^|[\s<])(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  let count = 0;
  for (const match of html.matchAll(pattern)) {
    const raw = (match[1] ?? match[2] ?? match[3] ?? '').trim();
    if (raw === '' || raw.startsWith('#')) continue;
    if (/^(?:javascript|mailto|tel|data):/i.test(raw)) continue;
    let url;
    try {
      url = new URL(raw, 'http://placeholder.invalid/');
    } catch {
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
    if (/\.php(?:$|[\/;])/i.test(url.pathname)) count += 1;
  }
  return count;
}

async function defaultResolve(hostname) {
  const results = await dnsLookup(hostname, { all: true, verbatim: true });
  return results.map(({ address, family }) => ({ address, family }));
}

function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) {
    return Promise.reject(signal.reason instanceof Error ? signal.reason : new ScanError('The scan was aborted.', 502));
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      signal.removeEventListener('abort', onAbort);
      reject(signal.reason instanceof Error ? signal.reason : new ScanError('The scan was aborted.', 502));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

function assertTarget(target, statusCode) {
  if (!(target instanceof URL)) throw new ScanError('A valid URL object is required.', 400);
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new ScanError('Only http and https URLs are supported.', statusCode);
  }
  if (target.username !== '' || target.password !== '') {
    throw new ScanError('URLs containing credentials are not supported.', statusCode);
  }
  if (target.hostname === '') throw new ScanError('The URL must include a hostname.', statusCode);
  if (target.port !== '') throw new ScanError('Only standard HTTP and HTTPS ports are supported.', statusCode);
  const bare = stripBrackets(target.hostname);
  if (bare === '' || bare === '.' || bare === '..') {
    throw new ScanError('The URL must include a valid hostname.', statusCode);
  }
  if (isLocalHostname(bare)) throw new ScanError('Local hostnames are not allowed.', statusCode);
  if (isIP(bare) !== 0 && !isPublicAddress(bare)) {
    throw new ScanError('The target address is not a public address.', statusCode);
  }
}

async function resolvePublic(hostname, { resolve, signal, statusCode }) {
  const bare = stripBrackets(hostname);
  const literal = isIP(bare);
  if (literal !== 0) {
    if (!isPublicAddress(bare)) throw new ScanError('The target address is not a public address.', statusCode);
    return { address: bare, family: literal };
  }
  if (isLocalHostname(bare)) throw new ScanError('Local hostnames are not allowed.', statusCode);

  const results = await abortable(Promise.resolve(resolve(bare, { signal })), signal);
  if (!Array.isArray(results) || results.length === 0) {
    throw new ScanError('The hostname did not resolve to an address.', 502);
  }
  const addresses = [];
  const seen = new Set();
  for (const entry of results) {
    const address = typeof entry === 'string'
      ? entry
      : entry && typeof entry.address === 'string'
        ? entry.address
        : null;
    if (!address || !isPublicAddress(address)) {
      throw new ScanError('The hostname resolves to a non-public address.', statusCode);
    }
    const clean = stripBrackets(address);
    const family = isIP(clean);
    if (family === 0) throw new ScanError('The hostname returned an invalid address.', statusCode);
    const key = `${clean}|${family}`;
    if (!seen.has(key)) {
      seen.add(key);
      addresses.push({ address: clean, family });
    }
  }
  return addresses[0];
}

function hostHeader(hostname, port) {
  const bare = stripBrackets(hostname);
  const host = isIP(bare) === 6 ? `[${bare}]` : bare;
  return port === '' ? host : `${host}:${port}`;
}

/**
 * One real GET. Returns status and headers; optionally captures a bounded
 * text/html body for .php URL-reference inspection. The body is never returned
 * raw to callers outside this module. `address` is assumed validated/pinned by
 * the caller; production callers reach this only through `scanWebsite`.
 */
export async function requestHeaders({
  target,
  address,
  family,
  signal,
  captureBody = false,
  maxHeaderSize = MAX_HEADER_SIZE,
  maxBodyBytes = MAX_BODY_BYTES,
} = {}) {
  if (!(target instanceof URL)) throw new ScanError('A valid URL object is required.', 400);
  if (typeof address !== 'string' || address === '') throw new ScanError('A pinned address is required.', 502);

  const bare = stripBrackets(target.hostname);
  const port = target.port === '' ? (target.protocol === 'https:' ? 443 : 80) : Number(target.port);
  const transport = target.protocol === 'https:' ? https : http;
  const options = {
    protocol: target.protocol,
    hostname: bare,
    port,
    path: `${target.pathname === '' ? '/' : target.pathname}${target.search}`,
    method: 'GET',
    headers: {
      'User-Agent': USER_AGENT,
      Accept: '*/*',
      'Accept-Encoding': 'identity',
      Connection: 'close',
      Host: hostHeader(target.hostname, target.port),
    },
    lookup: (host, lookupOptions, callback) => {
      if (lookupOptions && lookupOptions.all) callback(null, [{ address, family }]);
      else callback(null, address, family);
    },
    servername: target.protocol === 'https:' && isIP(bare) === 0 ? bare : undefined,
    rejectUnauthorized: true,
    maxHeaderSize,
    agent: false,
  };
  if (signal) options.signal = signal;

  return await new Promise((resolve, reject) => {
    let settled = false;
    let responded = false;
    let result = null;
    const finish = (extra = {}) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, ...extra });
    };
    const req = transport.request(options, (res) => {
      responded = true;
      res.on('error', () => {});
      const statusCode = res.statusCode;
      const rawHeaders = Array.isArray(res.rawHeaders) ? res.rawHeaders.slice() : [];
      const type = getHeader(rawHeaders, 'content-type') ?? '';
      const encoding = getHeader(rawHeaders, 'content-encoding') ?? '';
      const location = getHeader(rawHeaders, 'location');
      result = {
        statusCode,
        rawHeaders,
        body: null,
        bodyTruncated: false,
        bodyError: false,
        bodyInspected: false,
        bodySkippedReason: null,
      };

      if (!captureBody) {
        res.destroy();
        finish({ bodySkippedReason: 'not-requested' });
        return;
      }
      if (REDIRECTS.has(statusCode) && location !== null && location !== '') {
        res.destroy();
        finish({ bodySkippedReason: 'redirect' });
        return;
      }
      if (!/^\s*text\/html\b/i.test(type)) {
        res.destroy();
        finish({ bodySkippedReason: 'not-html' });
        return;
      }
      if (encoding !== '' && !/^\s*identity\s*$/i.test(encoding)) {
        res.destroy();
        finish({ bodySkippedReason: 'encoding' });
        return;
      }

      const chunks = [];
      let size = 0;
      const finishBody = (truncated, error = false) => {
        finish({
          body: Buffer.concat(chunks).toString('utf8'),
          bodyTruncated: truncated,
          bodyError: error,
          bodyInspected: true,
        });
      };
      res.on('error', () => {
        if (!settled) finishBody(false, true);
      });
      res.on('data', (chunk) => {
        if (settled) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const remaining = maxBodyBytes - size;
        if (buf.length > remaining) {
          if (remaining > 0) chunks.push(buf.subarray(0, remaining));
          size = maxBodyBytes;
          res.destroy();
          finishBody(true);
          return;
        }
        chunks.push(buf);
        size += buf.length;
      });
      res.on('end', () => {
        if (!settled) finishBody(false);
      });
      res.on('aborted', () => {
        if (!settled) finishBody(true, true);
      });
    });
    req.on('error', (error) => {
      if (settled) return;
      if (responded && result) {
        finish({ bodyError: true });
        return;
      }
      settled = true;
      reject(error);
    });
    req.end();
  });
}

function asScanError(error, hostname) {
  if (error instanceof ScanError) return error;
  const host = typeof hostname === 'string' && hostname !== '' ? stripBrackets(hostname) : 'the host';
  const code = error && typeof error === 'object' ? error.code : undefined;
  const options = error instanceof Error ? { cause: error } : {};

  if (error && (error.name === 'AbortError' || code === 'ABORT_ERR')) {
    return new ScanError('The scan was aborted.', 502, options);
  }
  if (code === 'HPE_HEADER_OVERFLOW') return new ScanError('The response headers were too large.', 502, options);
  if (['ENOTFOUND', 'EAI_AGAIN', 'EAI_NONAME', 'EAI_FAIL'].includes(code)) {
    return new ScanError(`Could not resolve ${host}.`, 502, options);
  }
  if (code === 'ECONNREFUSED') return new ScanError(`The connection to ${host} was refused.`, 502, options);
  if (code === 'ECONNRESET') return new ScanError(`The connection to ${host} was reset.`, 502, options);
  if (code === 'ETIMEDOUT') return new ScanError(`The connection to ${host} timed out.`, 502, options);
  if (['EHOSTUNREACH', 'ENETUNREACH', 'ENETDOWN'].includes(code)) {
    return new ScanError(`The host ${host} is unreachable.`, 502, options);
  }
  if (code === 'EACCES') return new ScanError(`The connection to ${host} was blocked.`, 502, options);
  if (typeof code === 'string' && (
    code.startsWith('CERT_')
    || code.startsWith('ERR_TLS_CERT_')
    || code.startsWith('UNABLE_TO_')
    || code === 'DEPTH_ZERO_SELF_SIGNED_CERT'
    || code === 'SELF_SIGNED_CERT_IN_CHAIN'
  )) {
    return new ScanError(`TLS certificate verification failed for ${host}.`, 502, options);
  }
  if (typeof code === 'string' && (code.startsWith('ERR_TLS_') || code.startsWith('ERR_SSL_') || code === 'EPROTO')) {
    return new ScanError(`The TLS connection to ${host} failed.`, 502, options);
  }
  if (['ERR_INVALID_HTTP_RESPONSE', 'HPE_INVALID_HEADER_TOKEN', 'HPE_INVALID_STATUS', 'HPE_INVALID_CONSTANT'].includes(code)) {
    return new ScanError(`The host ${host} returned an invalid HTTP response.`, 502, options);
  }
  if (code === 'ERR_INVALID_URL') return new ScanError('The URL is invalid.', 400, options);
  return new ScanError('The scan could not be completed.', 502, options);
}

function safeFinalUrl(target) {
  const safe = new URL(target.href);
  safe.username = '';
  safe.password = '';
  safe.search = '';
  safe.hash = '';
  return safe.href;
}

function combine(hops, {
  finalPathname,
  originalHostname,
  finalHostname,
  redirectCount,
  sawHostChange,
  sawDowngrade,
  bodyInfo,
}) {
  const evidence = [];
  const warnings = [];
  const versions = [];
  const statuses = [];
  let headerSignal = false;

  hops.forEach((hop, index) => {
    evidence.push(`Hop ${index + 1}: ${hop.hostname} returned HTTP ${hop.statusCode}.`);
    if (hop.inspection.phpDetected) {
      headerSignal = true;
      for (const item of hop.inspection.evidence) {
        if (item === 'No PHP indicators were found in the response headers.') continue;
        evidence.push(`${hop.hostname} (HTTP ${hop.statusCode}): ${item}`);
      }
    }
    versions.push(...hop.inspection.versions);
    warnings.push(...hop.inspection.warnings);
    statuses.push(hop.inspection.status);
    if (hop.statusCode >= 400) {
      warnings.push(`${hop.hostname} returned HTTP ${hop.statusCode}; response headers may not represent the application.`);
    }
  });

  const finalHop = hops[hops.length - 1];
  if (!headerSignal) {
    evidence.push(`${finalHop.hostname} (HTTP ${finalHop.statusCode}): no PHP indicators were found in the response headers.`);
  }

  const pathSignal = typeof finalPathname === 'string' && /\.php$/i.test(finalPathname);
  if (pathSignal) evidence.push('The final URL path ends in .php.');

  const bodyRefs = bodyInfo && bodyInfo.bodyInspected ? findPhpRefs(bodyInfo.body) : 0;
  const bodySignal = bodyRefs > 0;
  if (bodySignal) evidence.push(`HTML href/src/action attributes referenced .php URLs (${bodyRefs} found).`);

  if (!headerSignal && !pathSignal && !bodySignal) {
    const parts = ['response headers', 'final URL path'];
    if (bodyInfo && bodyInfo.bodyInspected) parts.push('inspected HTML body');
    evidence.push(`No PHP indicators were found in the ${parts.join(', ')}.`);
  }

  const confidence = headerSignal || pathSignal ? 'high' : bodySignal ? 'medium' : 'low';

  if (bodyInfo) {
    if (bodyInfo.bodyTruncated) {
      warnings.push('The HTML body was truncated at 64 KiB; .php references after that point were not inspected.');
    }
    if (bodyInfo.bodyError) warnings.push('The HTML body could not be read completely.');
    if (bodyInfo.bodySkippedReason === 'encoding') warnings.push('The HTML body used content encoding and was not inspected.');
    if (!bodyInfo.bodyInspected && !headerSignal && !pathSignal) {
      warnings.push('The final response body was not inspected; only response headers and the final URL path were checked.');
    }
  }
  if (pathSignal && !headerSignal) {
    warnings.push('PHP was inferred from the final URL path only; no version was disclosed.');
  }
  if (pathSignal && finalHostname !== originalHostname) {
    warnings.push(`The final .php path belongs to ${finalHostname}, not the original host; attribute it accordingly.`);
  }
  if (bodySignal && !headerSignal) {
    warnings.push('PHP was inferred from .php URL references in the HTML body; no version was disclosed.');
  }

  const uniqueVersions = [...new Set(versions)];
  let phpVersion = null;
  if (uniqueVersions.length > 0) {
    const bases = new Set(uniqueVersions.map(versionBase));
    if (bases.size === 1) phpVersion = uniqueVersions[0];
    else warnings.push('Different PHP versions were reported across redirect hops; no single version is reported.');
  }

  const meaningful = new Set(statuses.filter((status) => status !== 'not-detected'));
  if (!headerSignal && (pathSignal || bodySignal)) meaningful.add('unknown');
  const hasAffected = meaningful.has('affected');
  const hasPatched = meaningful.has('patched');
  const hasUnknown = meaningful.has('unknown');
  const hasNotDetected = statuses.includes('not-detected');
  let status;

  if (hasAffected && hasPatched) {
    status = 'unknown';
    warnings.push('An affected PHP version was reported at one hop and a patched version at another; exposure cannot be determined from the final response alone.');
  } else if (hasAffected) {
    status = 'affected';
    if (hasUnknown || hasNotDetected) {
      warnings.push('An affected PHP version was reported at one hop; another hop was undetermined or had no PHP signal.');
    }
  } else if (hasPatched && hasUnknown) {
    status = 'unknown';
    warnings.push('A patched PHP version was reported at one hop, but another hop was undetermined; exposure cannot be confirmed.');
  } else if (hasPatched) {
    status = 'patched';
    if (hasNotDetected) warnings.push('A patched PHP version was reported at one hop; another hop had no PHP signal.');
  } else if (hasUnknown) {
    status = 'unknown';
  } else {
    status = 'not-detected';
    warnings.push('No PHP signal was found; exposure is undetermined. Absence of a signal does not mean PHP is absent.');
  }

  if (redirectCount > 0) {
    warnings.push('The site redirected; results include response headers from each redirect hop.');
    if (sawHostChange) {
      warnings.push('The site redirected to a different host; the final response may come from a CDN or proxy and not the original runtime.');
    }
    if (sawDowngrade) warnings.push('The site redirected from HTTPS to HTTP.');
  }

  const isPhp = headerSignal || pathSignal || bodySignal ? 'yes' : 'unknown';
  if (isPhp !== 'yes') {
    status = 'not-detected';
    phpVersion = null;
  }

  return {
    is_php: isPhp,
    confidence,
    php_version: phpVersion,
    status,
    evidence: bound(evidence, MAX_EVIDENCE, 200),
    warnings: bound(warnings, MAX_WARNINGS),
  };
}

/**
 * Scans one public website using one normal GET per hop. Redirects (maximum 3)
 * are followed only after the same URL, port, credential, hostname, DNS and
 * address checks as the original target. Response bodies are read only for a
 * final text/html response, capped at 64 KiB, and never returned raw.
 *
 * `options.resolve` and `options.request` are in-process test seams only. They
 * are never read from HTTP input, environment variables, or client config.
 * Production callers must use `scanWebsite(url)` so real DNS validation and
 * pinned transport remain in force.
 */
export async function scanWebsite(inputUrl, options = {}) {
  if (!(inputUrl instanceof URL)) throw new ScanError('A valid URL object is required.', 400);
  const original = new URL(inputUrl.href);
  const originalHref = original.href;
  const originalHostname = original.hostname;
  const opts = options && typeof options === 'object' ? options : {};
  const resolve = typeof opts.resolve === 'function' ? opts.resolve : defaultResolve;
  const request = typeof opts.request === 'function' ? opts.request : requestHeaders;
  const deadlineMs = Number.isFinite(opts.deadlineMs) && opts.deadlineMs > 0 ? opts.deadlineMs : DEADLINE_MS;
  const maxRedirects = Number.isInteger(opts.maxRedirects) && opts.maxRedirects >= 0 ? opts.maxRedirects : MAX_REDIRECTS;
  const timeoutMessage = deadlineMs === DEADLINE_MS ? 'The scan timed out after 10 seconds.' : 'The scan timed out.';

  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(new ScanError(timeoutMessage, 502));
  }, deadlineMs);
  let currentHostname = originalHostname;

  try {
    assertTarget(original, 400);
    let target = new URL(original.href);
    target.hash = '';
    const visited = new Set();
    const hops = [];
    let redirects = 0;
    let sawHostChange = false;
    let sawDowngrade = false;
    let bodyInfo = null;

    while (true) {
      currentHostname = target.hostname;
      const key = target.href;
      if (visited.has(key)) throw new ScanError('Redirect loop detected.', 502);
      visited.add(key);

      const pinned = await resolvePublic(target.hostname, {
        resolve,
        signal: controller.signal,
        statusCode: redirects === 0 ? 400 : 502,
      });
      const response = await abortable(request({
        target,
        address: pinned.address,
        family: pinned.family,
        signal: controller.signal,
        captureBody: true,
        maxHeaderSize: MAX_HEADER_SIZE,
        maxBodyBytes: MAX_BODY_BYTES,
      }), controller.signal);

      if (!response || !Number.isInteger(response.statusCode) || !Array.isArray(response.rawHeaders)) {
        throw new ScanError('The host returned an invalid HTTP response.', 502);
      }

      const statusCode = response.statusCode;
      const inspection = inspectPhpHeaders(response.rawHeaders);
      hops.push({ hostname: target.hostname, statusCode, inspection });
      bodyInfo = {
        body: typeof response.body === 'string' ? response.body : null,
        bodyTruncated: response.bodyTruncated === true,
        bodyError: response.bodyError === true,
        bodyInspected: response.bodyInspected === true,
        bodySkippedReason: typeof response.bodySkippedReason === 'string' ? response.bodySkippedReason : null,
      };

      const location = getHeader(response.rawHeaders, 'location');
      if (REDIRECTS.has(statusCode) && location !== null && location !== '') {
        if (redirects >= maxRedirects) {
          throw new ScanError(`Too many redirects (maximum ${maxRedirects}).`, 502);
        }
        let next;
        try {
          next = new URL(location, target);
        } catch {
          throw new ScanError('The site returned an invalid redirect location.', 502);
        }
        next.hash = '';
        assertTarget(next, 502);
        if (next.hostname !== originalHostname) sawHostChange = true;
        if (target.protocol === 'https:' && next.protocol === 'http:') sawDowngrade = true;
        redirects += 1;
        target = next;
        continue;
      }

      const combined = combine(hops, {
        finalPathname: target.pathname,
        originalHostname,
        finalHostname: target.hostname,
        redirectCount: redirects,
        sawHostChange,
        sawDowngrade,
        bodyInfo,
      });

      return {
        mock: false,
        url: originalHref,
        hostname: originalHostname,
        finalUrl: safeFinalUrl(target),
        httpStatus: statusCode,
        is_php: combined.is_php,
        confidence: combined.confidence,
        php_version: combined.php_version,
        status: combined.status,
        evidence: combined.evidence,
        warnings: combined.warnings,
      };
    }
  } catch (error) {
    if (timedOut) {
      throw controller.signal.reason instanceof ScanError
        ? controller.signal.reason
        : new ScanError(timeoutMessage, 502);
    }
    throw asScanError(error, currentHostname);
  } finally {
    clearTimeout(timer);
  }
}


