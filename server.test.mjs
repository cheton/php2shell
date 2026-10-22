import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

import { ScanError } from './scanner.mjs';
import { createServer } from './server.mjs';

let origin;
let server;
let tempRoot;
let publicDir;

const SAMPLE_RESULT = {
  url: 'https://example.com/',
  hostname: 'example.com',
  finalUrl: 'https://example.com/',
  httpStatus: 200,
  is_php: 'yes',
  confidence: 'high',
  php_version: '8.4.27',
  status: 'patched',
  evidence: ['server: PHP/8.4.27'],
  warnings: [],
};

async function listen(options) {
  const instance = createServer(options);
  await new Promise((resolve, reject) => {
    instance.once('error', reject);
    instance.listen(0, '127.0.0.1', resolve);
  });
  const { port } = instance.address();
  return { instance, origin: `http://127.0.0.1:${port}` };
}

function close(instance) {
  return new Promise((resolve) => instance.close(resolve));
}

async function postScan(body, { method = 'POST', base = origin } = {}) {
  const response = await fetch(`${base}/api/scan`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // left null so assertions surface the raw text
  }
  return { response, json, text };
}

function rawGet(rawPath) {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: Number(new URL(origin).port),
        method: 'GET',
        path: rawPath,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

async function waitFor(predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for condition');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

before(async () => {
  tempRoot = await mkdtemp(path.join(tmpdir(), 'php2shell-test-'));
  publicDir = path.join(tempRoot, 'public');
  await mkdir(publicDir);
  await writeFile(path.join(publicDir, 'index.html'), '<!doctype html><title>portal</title>');
  await writeFile(path.join(publicDir, 'styles.css'), 'body { color: red; }');
  await writeFile(path.join(publicDir, 'app.js'), 'export const ready = true;');
  await writeFile(path.join(tempRoot, 'secret.txt'), 'outside public directory');

  const started = await listen({ publicDir });
  server = started.instance;
  origin = started.origin;
});

after(async () => {
  await close(server);
  await rm(tempRoot, { recursive: true, force: true });
});

describe('POST /api/scan authorization', () => {
  it('rejects a request where authorized is false', async () => {
    const { response, json } = await postScan({
      url: 'https://example.com/',
      authorized: false,
    });
    assert.equal(response.status, 403);
    assert.equal(json.mock, false);
    assert.match(json.error, /authorized/i);
  });

  it('rejects a request where authorized is missing', async () => {
    const { response, json } = await postScan({ url: 'https://example.com/' });
    assert.equal(response.status, 403);
    assert.equal(json.mock, false);
  });

  it('requires authorized to be exactly true, not a truthy string', async () => {
    const { response, json } = await postScan({ url: 'https://example.com/', authorized: 'true' });
    assert.equal(response.status, 403);
    assert.equal(json.mock, false);
  });
});

describe('POST /api/scan URL validation', () => {
  for (const url of ['ftp://example.com/', 'javascript:alert(1)', 'file:///etc/passwd', 'example.com', '']) {
    it(`rejects ${JSON.stringify(url)}`, async () => {
      const { response, json } = await postScan({ url, authorized: true });
      assert.equal(response.status, 400);
      assert.equal(json.mock, false);
      assert.equal(typeof json.error, 'string');
    });
  }

  it('rejects URLs that embed credentials', async () => {
    const { response, json } = await postScan({
      url: 'https://user:secret@example.com/',
      authorized: true,
    });
    assert.equal(response.status, 400);
    assert.equal(json.mock, false);
    assert.match(json.error, /credentials/i);
  });

  it('rejects malformed JSON, non-object JSON, and empty bodies', async () => {
    for (const body of ['{', '[]', 'null', '', '"text"']) {
      const { response, json } = await postScan(body);
      assert.equal(response.status, 400, `body ${JSON.stringify(body)} should be rejected`);
      assert.equal(json.mock, false);
    }
  });

  it('rejects any client-supplied scenario field', async () => {
    for (const scenario of ['affected', 'error', null, true]) {
      const { response, json } = await postScan({
        url: 'https://example.com/',
        authorized: true,
        scenario,
      });
      assert.equal(response.status, 400, `scenario ${JSON.stringify(scenario)} should be rejected`);
      assert.equal(json.mock, false);
      assert.match(json.error, /scenario/i);
    }
  });

  it('rejects bodies larger than the 16 KiB cap', async () => {
    const { response, json } = await postScan({
      url: 'https://example.com/',
      authorized: true,
      padding: 'x'.repeat(20_000),
    });
    assert.equal(response.status, 413);
    assert.equal(json.mock, false);
  });
});

describe('POST /api/scan with the real scanner', () => {
  it('refuses a loopback target without contacting it', async () => {
    let hits = 0;
    const target = createServer({ publicDir });
    target.on('request', () => {
      hits += 1;
    });
    await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
    const targetOrigin = `http://127.0.0.1:${target.address().port}/`;

    try {
      const { response, json } = await postScan({ url: targetOrigin, authorized: true });
      assert.ok(response.status >= 400 && response.status <= 599, `unexpected status ${response.status}`);
      assert.equal(json.mock, false);
      assert.equal(typeof json.error, 'string');
      assert.ok(json.error.length > 0);
      assert.equal(hits, 0, 'a non-public target must never receive a request');
    } finally {
      await close(target);
    }
  });

  it('refuses private, link-local, and IPv6 loopback targets', async () => {
    for (const url of [
      'http://10.0.0.1/',
      'http://192.168.1.10/',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]/',
      'http://[::ffff:127.0.0.1]/',
    ]) {
      const { response, json } = await postScan({ url, authorized: true });
      assert.ok(response.status >= 400 && response.status <= 599, `${url} returned ${response.status}`);
      assert.equal(json.mock, false, `${url} must not return a scan result`);
      assert.equal(typeof json.error, 'string');
    }
  });
});

describe('scan result handling with an injected scanner', () => {
  it('never invokes the scanner for rejected requests', async () => {
    let calls = 0;
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        calls += 1;
        return { ...SAMPLE_RESULT };
      },
    });

    try {
      const bodies = [
        { url: 'https://example.com/', authorized: false },
        { url: 'https://example.com/', authorized: true, scenario: 'affected' },
        { url: 'ftp://example.com/', authorized: true },
        { url: 'https://user:secret@example.com/', authorized: true },
      ];
      for (const body of bodies) {
        const { response } = await postScan(body, { base: injectedOrigin });
        assert.ok(response.status === 400 || response.status === 403);
      }
      assert.equal(calls, 0);
    } finally {
      await close(instance);
    }
  });

  it('maps a ScanError status code onto the API response', async () => {
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        throw new ScanError('Target refused the request.', 451);
      },
    });

    try {
      const { response, json } = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(response.status, 451);
      assert.deepEqual(json, { mock: false, error: 'Target refused the request.' });
    } finally {
      await close(instance);
    }
  });

  it('falls back to 502 for unexpected scanner failures', async () => {
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        throw new Error('boom');
      },
    });

    try {
      const { response, json } = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(response.status, 502);
      assert.equal(json.mock, false);
      assert.equal(typeof json.error, 'string');
    } finally {
      await close(instance);
    }
  });
});

describe('scan concurrency limits', () => {
  it('allows four concurrent scans and rejects the fifth with 429', async () => {
    let releaseGate;
    const gate = new Promise((resolve) => {
      releaseGate = resolve;
    });
    let calls = 0;
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        calls += 1;
        await gate;
        return { ...SAMPLE_RESULT };
      },
    });

    try {
      const inflight = Array.from({ length: 4 }, () => postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      ));

      await waitFor(() => calls === 4);

      const fifth = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(fifth.response.status, 429);
      assert.equal(fifth.json.mock, false);
      assert.equal(fifth.response.headers.get('retry-after'), '5');
      assert.equal(calls, 4, 'the rejected request must not start a scan');

      releaseGate();
      const settled = await Promise.all(inflight);
      for (const { response } of settled) assert.equal(response.status, 200);

      const afterRelease = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(afterRelease.response.status, 200);
      assert.equal(calls, 5);
    } finally {
      releaseGate();
      await close(instance);
    }
  });

  it('releases concurrency slots when scans fail', async () => {
    let calls = 0;
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        calls += 1;
        throw new ScanError('Upstream timed out.', 504);
      },
    });

    try {
      const settled = await Promise.all(Array.from({ length: 4 }, () => postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      )));
      for (const { response } of settled) assert.equal(response.status, 504);

      const next = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(next.response.status, 504, 'a freed slot must admit the next scan');
      assert.equal(calls, 5);
    } finally {
      await close(instance);
    }
  });

  it('does not consume scan slots for unauthorized requests', async () => {
    let calls = 0;
    const { instance, origin: injectedOrigin } = await listen({
      publicDir,
      scan: async () => {
        calls += 1;
        return { ...SAMPLE_RESULT };
      },
    });

    try {
      const rejected = await Promise.all(Array.from({ length: 6 }, () => postScan(
        { url: 'https://example.com/', authorized: false },
        { base: injectedOrigin },
      )));
      for (const { response } of rejected) assert.equal(response.status, 403);

      const authorized = await postScan(
        { url: 'https://example.com/', authorized: true },
        { base: injectedOrigin },
      );
      assert.equal(authorized.response.status, 200);
      assert.equal(calls, 1);
    } finally {
      await close(instance);
    }
  });
});

describe('static file serving', () => {
  it('serves index.html at the root with an HTML content type', async () => {
    const response = await fetch(`${origin}/`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^text\/html/);
    assert.match(await response.text(), /portal/);
  });

  it('serves CSS and JavaScript with the right MIME types', async () => {
    const css = await fetch(`${origin}/styles.css`);
    assert.equal(css.status, 200);
    assert.match(css.headers.get('content-type'), /^text\/css/);

    const js = await fetch(`${origin}/app.js`);
    assert.equal(js.status, 200);
    assert.match(js.headers.get('content-type'), /^text\/javascript/);
  });

  it('answers HEAD without a body', async () => {
    const response = await fetch(`${origin}/styles.css`, { method: 'HEAD' });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '');
  });

  it('returns 404 for unknown paths', async () => {
    const response = await fetch(`${origin}/missing.txt`);
    assert.equal(response.status, 404);
  });

  it('blocks path traversal outside public/', async () => {
    for (const rawPath of ['/%2e%2e/secret.txt', '/..%2fsecret.txt', '/%2e%2e%2f%2e%2e%2fsecret.txt']) {
      const { status, body } = await rawGet(rawPath);
      assert.equal(status, 404, `${rawPath} must not be served`);
      assert.doesNotMatch(body, /outside public directory/);
    }
  });

  it('rejects unsupported methods on static paths', async () => {
    const response = await fetch(`${origin}/index.html`, { method: 'POST' });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), 'GET, HEAD');
  });
});

describe('API method handling', () => {
  it('rejects GET /api/scan with 405, an Allow header, and mock false', async () => {
    const { response, json } = await postScan(null, { method: 'GET' });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), 'POST');
    assert.equal(json.mock, false);
    assert.equal(typeof json.error, 'string');
  });
});
