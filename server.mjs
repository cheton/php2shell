import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { ScanError, scanWebsite } from './scanner.mjs';

const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const MAX_BODY_BYTES = 16 * 1024;
const MAX_CONCURRENT_SCANS = 4;

const SCAN_PATH = '/api/scan';

const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.mjs', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.map', 'application/json; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.gif', 'image/gif'],
  ['.webp', 'image/webp'],
  ['.avif', 'image/avif'],
  ['.ico', 'image/x-icon'],
  ['.woff', 'font/woff'],
  ['.woff2', 'font/woff2'],
  ['.ttf', 'font/ttf'],
  ['.webmanifest', 'application/manifest+json'],
]);

class ValidationError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = statusCode;
  }
}

class BodyTooLargeError extends Error {
  constructor(limit) {
    super(`Request body exceeds ${limit} bytes.`);
    this.name = 'BodyTooLargeError';
  }
}

function baseHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  };
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  if (res.destroyed || res.writableEnded) return;
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    ...baseHeaders(),
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function sendMethodNotAllowed(res, allow) {
  sendJson(res, 405, { mock: false, error: 'Method not allowed.' }, { Allow: allow });
}

/**
 * Reads a request body with a hard byte cap. Rejects as soon as the cap is
 * crossed, then drains the remaining bytes so the response can still be sent.
 */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let rejected = false;
    let finished = false;

    req.on('data', (chunk) => {
      if (rejected) return;
      size += chunk.length;
      if (size > limit) {
        rejected = true;
        chunks.length = 0;
        reject(new BodyTooLargeError(limit));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      finished = true;
      if (!rejected) resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', (error) => {
      if (!rejected) {
        rejected = true;
        reject(error);
      }
    });
    req.on('close', () => {
      if (!rejected && !finished) {
        rejected = true;
        reject(new Error('Request aborted before the body was complete.'));
      }
    });
  });
}

function parseJsonBody(text) {
  if (text.trim() === '') {
    throw new ValidationError('Request body must be a JSON object.');
  }
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new ValidationError('Request body must be valid JSON.');
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ValidationError('Request body must be a JSON object.');
  }
  return payload;
}

function validateScanRequest(payload) {
  // Scans always run against the submitted URL. Clients cannot ask the server
  // for a canned outcome.
  if (Object.hasOwn(payload, 'scenario')) {
    throw new ValidationError('The scenario field is not supported.');
  }

  if (payload.authorized !== true) {
    throw new ValidationError(
      'You must confirm you are authorized to scan this host (authorized: true).',
      403,
    );
  }

  const { url } = payload;
  if (typeof url !== 'string' || url.trim() === '') {
    throw new ValidationError('url must be a non-empty absolute http(s) URL.');
  }

  let target;
  try {
    target = new URL(url.trim());
  } catch {
    throw new ValidationError('url must be a non-empty absolute http(s) URL.');
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    throw new ValidationError('Only http and https URLs are supported.');
  }
  if (target.username !== '' || target.password !== '') {
    throw new ValidationError('URLs containing credentials are not supported.');
  }
  if (target.hostname === '') {
    throw new ValidationError('url must include a hostname.');
  }

  return { target };
}

/**
 * Bounded scan concurrency. Requests beyond the cap are refused immediately
 * with 429 rather than queued, so the portal cannot be used as an unbounded
 * open proxy.
 */
function createScanLimiter(max) {
  let active = 0;
  return {
    tryAcquire() {
      if (active >= max) return false;
      active += 1;
      return true;
    },
    release() {
      if (active > 0) active -= 1;
    },
  };
}

async function handleScan(req, res, options) {
  if (req.method !== 'POST') {
    sendMethodNotAllowed(res, 'POST');
    return;
  }

  let payload;
  try {
    payload = parseJsonBody(await readBody(req, MAX_BODY_BYTES));
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      // The reader keeps draining the remaining bytes, so the connection stays
      // usable and the client can still read this response.
      sendJson(res, 413, { mock: false, error: 'Request body is too large.' });
      return;
    }
    if (error instanceof ValidationError) {
      sendJson(res, error.statusCode, { mock: false, error: error.message });
      return;
    }
    sendJson(res, 400, { mock: false, error: 'Could not read request body.' });
    return;
  }

  let target;
  try {
    ({ target } = validateScanRequest(payload));
  } catch (error) {
    if (error instanceof ValidationError) {
      sendJson(res, error.statusCode, { mock: false, error: error.message });
      return;
    }
    throw error;
  }

  if (!options.limiter.tryAcquire()) {
    sendJson(
      res,
      429,
      { mock: false, error: 'The scan service is busy. Please try again shortly.' },
      { 'Retry-After': '5' },
    );
    return;
  }

  let result;
  try {
    result = await options.scan(target);
  } catch (error) {
    if (error instanceof ScanError) {
      const statusCode = Number.isInteger(error.statusCode)
        && error.statusCode >= 400
        && error.statusCode <= 599
        ? error.statusCode
        : 502;
      const message = typeof error.message === 'string' && error.message !== ''
        ? error.message
        : 'The scan could not be completed.';
      sendJson(res, statusCode, { mock: false, error: message });
      return;
    }
    sendJson(res, 502, { mock: false, error: 'The scan could not be completed.' });
    return;
  } finally {
    options.limiter.release();
  }

  if (result === null || typeof result !== 'object') {
    sendJson(res, 502, { mock: false, error: 'The scan returned no result.' });
    return;
  }

  sendJson(res, 200, { ...result, mock: false });
}

function notFound(res) {
  sendJson(res, 404, { error: 'Not found.' });
}

async function serveStatic(req, res, publicDir, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    sendMethodNotAllowed(res, 'GET, HEAD');
    return;
  }

  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    notFound(res);
    return;
  }
  if (decoded.includes('\0')) {
    notFound(res);
    return;
  }

  const relativePath = decoded.replace(/^\/+/, '');
  let target = path.resolve(publicDir, relativePath === '' ? 'index.html' : relativePath);

  let realPublicDir;
  try {
    realPublicDir = await realpath(publicDir);
  } catch {
    notFound(res);
    return;
  }

  const isInside = (base, candidate) => {
    const relative = path.relative(base, candidate);
    return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
  };

  let targetStat;
  try {
    targetStat = await stat(target);
    if (targetStat.isDirectory()) {
      target = path.join(target, 'index.html');
      targetStat = await stat(target);
    }
  } catch {
    notFound(res);
    return;
  }

  if (!targetStat.isFile()) {
    notFound(res);
    return;
  }

  let realTarget;
  try {
    realTarget = await realpath(target);
  } catch {
    notFound(res);
    return;
  }
  if (!isInside(realPublicDir, realTarget)) {
    notFound(res);
    return;
  }

  const contentType = MIME_TYPES.get(path.extname(realTarget).toLowerCase())
    ?? 'application/octet-stream';
  const headers = {
    ...baseHeaders(),
    'Content-Type': contentType,
    'Content-Length': targetStat.size,
    'Cache-Control': 'no-cache',
  };
  res.writeHead(200, headers);

  if (req.method === 'HEAD') {
    res.end();
    return;
  }

  const stream = createReadStream(realTarget);
  stream.on('error', () => {
    res.destroy();
  });
  stream.pipe(res);
}

/**
 * Creates the portal HTTP server. Pass `publicDir` to serve a different
 * directory and `scan` to inject a scanner (integration tests only); nothing
 * is listened to until `.listen()` is called.
 */
export function createServer({ publicDir, scan = scanWebsite } = {}) {
  if (typeof scan !== 'function') {
    throw new TypeError('scan must be a function.');
  }

  const options = {
    publicDir: path.resolve(publicDir ?? process.env.PUBLIC_DIR ?? DEFAULT_PUBLIC_DIR),
    scan,
    limiter: createScanLimiter(MAX_CONCURRENT_SCANS),
  };

  return createHttpServer((req, res) => {
    let pathname;
    try {
      pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
    } catch {
      notFound(res);
      return;
    }

    if (pathname === SCAN_PATH) {
      handleScan(req, res, options).catch(() => {
        if (!res.headersSent) {
          sendJson(res, 500, { mock: false, error: 'Internal server error.' });
        } else {
          res.destroy();
        }
      });
      return;
    }

    serveStatic(req, res, options.publicDir, pathname).catch(() => {
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'Internal server error.' });
      } else {
        res.destroy();
      }
    });
  });
}

const isEntrypoint = process.argv[1] !== undefined
  && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;

if (isEntrypoint) {
  const port = Number.parseInt(process.env.PORT ?? '3000', 10);
  const host = process.env.HOST ?? '0.0.0.0';
  const ignoreTlsErrors = process.env.SCAN_IGNORE_TLS_ERRORS === 'true';
  const server = createServer({ scan: (target) => scanWebsite(target, { ignoreTlsErrors }) });
  if (ignoreTlsErrors) {
    console.warn('[php2shell] WARNING: scan TLS certificate verification is disabled; website identity is not verified.');
  }

  server.on('error', (error) => {
    console.error(`[php2shell] server error: ${error.message}`);
    process.exitCode = 1;
  });

  server.listen(Number.isInteger(port) ? port : 3000, host, () => {
    console.log(`[php2shell] portal listening on http://${host}:${server.address().port}`);
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
