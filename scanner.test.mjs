import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  scanWebsite,
  ScanError,
  isPublicAddress,
  classifyPhpVersion,
  inspectPhpHeaders,
  requestHeaders,
} from './scanner.mjs';

function raw(pairs) {
  const out = [];
  for (const [name, value] of pairs) {
    if (Array.isArray(value)) {
      for (const item of value) out.push(name, item);
    } else {
      out.push(name, value);
    }
  }
  return out;
}

function response(statusCode, pairs = [], body = null, extra = {}) {
  return {
    statusCode,
    rawHeaders: raw(pairs),
    body,
    bodyTruncated: false,
    bodyError: false,
    bodyInspected: body !== null,
    bodySkippedReason: null,
    ...extra,
  };
}

const publicResolve = async () => [{ address: '93.184.216.34', family: 4 }];

test('isPublicAddress rejects private, loopback, metadata, reserved and mapped addresses', () => {
  const rejected = [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
    '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.1', '192.168.1.1',
    '192.31.196.1', '192.52.193.1', '192.88.99.1', '192.175.48.1',
    '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:8.8.8.8',
    '64:ff9b::7f00:1', '100::1', '2001::1', '2001:2::1', '2001:10::1',
    '2001:20::1', '2001:30::1', '2001:db8::1', '2002:7f00:1::1', '3ffe::1',
    '3fff::1', '2620:4f:8000::1', 'fc00::1', 'fd00::1', 'fe80::1', 'ff02::1',
    'fe80::1%en0', '0177.0.0.1', '999.1.1.1', 'not-an-ip',
  ];
  for (const address of rejected) {
    assert.equal(isPublicAddress(address), false, address);
  }

  const accepted = [
    '1.1.1.1', '8.8.8.8', '93.184.216.34', '100.63.255.255', '100.128.0.1',
    '172.15.255.255', '172.32.0.1', '192.0.1.1', '192.167.255.255', '192.169.0.1',
    '198.20.0.1', '203.0.114.1', '223.255.255.255',
    '2001:470::1', '2001:4860:4860::8888', '2606:4700:4700::1111',
    '2a00:1450:4001:81b::200e', '2404:6800:4001:80e::200e',
  ];
  for (const address of accepted) {
    assert.equal(isPublicAddress(address), true, address);
  }
});

test('classifyPhpVersion handles all four branch boundaries and legacy 5.4 threshold', () => {
  const cases = [
    ['8.2.34', 'affected'], ['8.2.35', 'patched'],
    ['8.3.35', 'affected'], ['8.3.36', 'patched'],
    ['8.4.26', 'affected'], ['8.4.27', 'patched'],
    ['8.5.11', 'affected'], ['8.5.12', 'patched'],
    ['5.4.0', 'affected'], ['5.6.40', 'affected'], ['5.3.29', 'unknown'],
    ['7.0.0', 'affected'], ['7.4.33', 'affected'],
    ['8.0.30', 'affected'], ['8.1.99', 'affected'],
    ['8.6.0', 'unknown'], ['9.0.0', 'unknown'],
  ];
  for (const [version, status] of cases) {
    assert.equal(classifyPhpVersion(version).status, status, version);
  }
  assert.match(classifyPhpVersion('5.4.0').warnings.join(' '), /backport|end-of-life/i);
  assert.equal(classifyPhpVersion('8.2').status, 'unknown');
});

test('classifyPhpVersion does not treat arbitrary suffixes as patched', () => {
  for (const version of [
    '8.4.27.1', '8.4.27-foo', '8.4.27-1', '8.4.27-pl1',
    '8.4.27-dev', '8.4.27RC1', '8.4.27beta1',
  ]) {
    assert.equal(classifyPhpVersion(version).status, 'unknown', version);
  }
  assert.equal(classifyPhpVersion('8.4.27-1ubuntu2.14').status, 'patched');
  assert.equal(classifyPhpVersion('8.4.26-1ubuntu2.14').status, 'affected');
  assert.equal(classifyPhpVersion('8.4.27+deb12u1').status, 'patched');
  assert.equal(classifyPhpVersion('8.4.27-1.el9').status, 'patched');
  assert.equal(classifyPhpVersion('8.4.27-r0').status, 'patched');
  assert.match(classifyPhpVersion('8.4.27-1ubuntu2.14').warnings.join(' '), /vendor|distribution/i);
});

test('inspectPhpHeaders parses CSV-derived multi-product headers and dedupes', () => {
  const comma = inspectPhpHeaders(raw([['X-Powered-By', 'PHP/8.3.29, ASP.NET']]));
  assert.equal(comma.phpDetected, true);
  assert.equal(comma.version, '8.3.29');
  assert.equal(comma.status, 'affected');

  const duplicate = inspectPhpHeaders(raw([
    ['Server', 'Apache/2.4.66 () PHP/8.2.29'],
    ['X-Powered-By', 'PHP/8.2.29'],
  ]));
  assert.equal(duplicate.phpDetected, true);
  assert.equal(duplicate.version, '8.2.29');
  assert.equal(duplicate.status, 'affected');
  assert.deepEqual(duplicate.versions, ['8.2.29']);

  const legacy = inspectPhpHeaders(raw([['Server', 'Apache/2.4.41 (Ubuntu) PHP/8.1.2']]));
  assert.equal(legacy.status, 'affected');
  assert.match(legacy.warnings.join(' '), /end-of-life|backport/i);
});

test('inspectPhpHeaders reports cookie-only PHP without leaking the value', () => {
  const result = inspectPhpHeaders(raw([
    ['Set-Cookie', 'PHPSESSID=super-secret-value; Path=/; HttpOnly'],
  ]));
  assert.equal(result.phpDetected, true);
  assert.equal(result.version, null);
  assert.equal(result.status, 'unknown');
  const text = JSON.stringify(result);
  assert.equal(text.includes('super-secret-value'), false);
  assert.equal(text.includes('PHPSESSID='), false);
});

test('inspectPhpHeaders keeps malformed multi-part and prerelease headers unknown', () => {
  const malformed = inspectPhpHeaders(raw([['X-Powered-By', 'PHP/8.4.27.1']]));
  assert.equal(malformed.status, 'unknown');
  assert.equal(malformed.version, '8.4.27.1');

  const prerelease = inspectPhpHeaders(raw([['X-Powered-By', 'PHP/8.4.27-dev']]));
  assert.equal(prerelease.status, 'unknown');

  const rc = inspectPhpHeaders(raw([['X-Powered-By', 'PHP/8.4.27RC1']]));
  assert.equal(rc.status, 'unknown');
});

test('inspectPhpHeaders returns not-detected when only non-PHP headers exist', () => {
  const result = inspectPhpHeaders(raw([['Server', 'nginx/1.24.0'], ['X-Powered-By', 'ASP.NET']]));
  assert.equal(result.phpDetected, false);
  assert.equal(result.version, null);
  assert.equal(result.status, 'not-detected');
});

test('scanWebsite classifies a direct affected PHP signal at high confidence with patch caveats', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(200, [['X-Powered-By', 'PHP/8.4.26']]),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'high');
  assert.equal(result.php_version, '8.4.26');
  assert.equal(result.status, 'affected');
  assert.ok(result.warnings.some((warning) => /indicator|exploit/i.test(warning)));
  assert.ok(result.warnings.some((warning) => /backport/i.test(warning)));
});

test('scanWebsite detects actual .php href/src/action references at medium confidence', async () => {
  const html = [
    '<html><body>',
    '<a href="/login.php">login</a>',
    '<script src="/app.php"></script>',
    '<form action="https://example.test/check.php?token=secret"></form>',
    '<p>index.php</p>',
    '</body></html>',
  ].join('');
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(200, [['Content-Type', 'text/html; charset=utf-8']], html),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'medium');
  assert.equal(result.php_version, null);
  assert.equal(result.status, 'unknown');
  assert.ok(result.evidence.some((item) => /\.php URLs \(3 found\)/.test(item)));
  assert.equal(JSON.stringify(result).includes('token=secret'), false);
  assert.equal(JSON.stringify(result).includes('index.php'), false);
});

test('scanWebsite treats a final .php pathname as high confidence', async () => {
  const result = await scanWebsite(new URL('https://example.test/sso.php'), {
    resolve: publicResolve,
    request: async () => response(200, [['Content-Type', 'text/plain']]),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'high');
  assert.equal(result.php_version, null);
  assert.equal(result.status, 'unknown');
  assert.ok(result.evidence.some((item) => /final URL path ends in \.php/i.test(item)));
});

test('bare .php text in HTML is not a PHP signal', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(200, [['Content-Type', 'text/html']], '<p>index.php</p>'),
  });
  assert.equal(result.is_php, 'unknown');
  assert.equal(result.confidence, 'low');
  assert.equal(result.php_version, null);
  assert.equal(result.status, 'not-detected');
});

test('scanWebsite warns explicitly for HTTP >= 400', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(404, [['Content-Type', 'text/html']], '<p>no php</p>'),
  });
  assert.equal(result.httpStatus, 404);
  assert.equal(result.is_php, 'unknown');
  assert.equal(result.confidence, 'low');
  assert.equal(result.status, 'not-detected');
  assert.ok(result.warnings.some((warning) => /HTTP 404/.test(warning)));
});

test('scanWebsite warns when the HTML body is truncated at the 64 KiB cap', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(
      200,
      [['Content-Type', 'text/html']],
      '<a href="/first.php">first</a>',
      { bodyTruncated: true },
    ),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'medium');
  assert.ok(result.warnings.some((warning) => /truncated at 64 KiB/i.test(warning)));
});

test('scanWebsite skips an encoded HTML body and warns', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async () => response(
      200,
      [['Content-Type', 'text/html'], ['Content-Encoding', 'gzip']],
      null,
      { bodySkippedReason: 'encoding' },
    ),
  });
  assert.equal(result.is_php, 'unknown');
  assert.equal(result.confidence, 'low');
  assert.equal(result.status, 'not-detected');
  assert.ok(result.warnings.some((warning) => /content encoding/i.test(warning)));
});

test('a patched final hop does not hide an affected earlier hop', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async ({ target }) => target.hostname === 'example.test'
      ? response(301, [['Location', 'https://cdn.test/'], ['X-Powered-By', 'PHP/8.4.26']])
      : response(200, [['X-Powered-By', 'PHP/8.4.27']]),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'high');
  assert.equal(result.php_version, null);
  assert.equal(result.status, 'unknown');
  assert.ok(result.warnings.some((warning) => /affected.*patched|patched.*affected/i.test(warning)));
  assert.ok(result.evidence.some((item) => /example\.test.*8\.4\.26/.test(item)));
  assert.ok(result.evidence.some((item) => /cdn\.test.*8\.4\.27/.test(item)));
  assert.ok(result.warnings.some((warning) => /CDN|proxy|different host/i.test(warning)));
});

test('an affected earlier hop remains affected when the final hop has no PHP signal', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async ({ target }) => target.hostname === 'example.test'
      ? response(302, [['Location', 'https://cdn.test/'], ['X-Powered-By', 'PHP/8.3.29']])
      : response(200, [['Content-Type', 'text/html']], '<p>static</p>'),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'high');
  assert.equal(result.php_version, '8.3.29');
  assert.equal(result.status, 'affected');
  assert.ok(result.warnings.some((warning) => /another hop was undetermined|no PHP signal/i.test(warning)));
});

test('scanWebsite enforces redirect limit and loop detection', async () => {
  await assert.rejects(
    scanWebsite(new URL('https://example.test/'), {
      resolve: publicResolve,
      request: async ({ target }) => response(302, [['Location', `/r${Number(target.pathname.slice(2)) + 1}`]]),
    }),
    (error) => error instanceof ScanError && error.statusCode === 502 && /Too many redirects/.test(error.message),
  );
  await assert.rejects(
    scanWebsite(new URL('https://example.test/'), {
      resolve: publicResolve,
      request: async () => response(302, [['Location', '/a']]),
    }),
    (error) => error instanceof ScanError && /loop/i.test(error.message),
  );
});

test('scanWebsite rejects a redirect to a private address before transport', async () => {
  let calls = 0;
  await assert.rejects(
    scanWebsite(new URL('https://example.test/'), {
      resolve: publicResolve,
      request: async () => {
        calls += 1;
        return response(302, [['Location', 'http://127.0.0.1/']]);
      },
    }),
    (error) => error instanceof ScanError && error.statusCode === 502,
  );
  assert.equal(calls, 1);
});

test('scanWebsite rejects mixed public/private DNS answers', async () => {
  let requestCalled = false;
  await assert.rejects(
    scanWebsite(new URL('http://example.test/'), {
      resolve: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '10.0.0.1', family: 4 },
      ],
      request: async () => {
        requestCalled = true;
        return response(200);
      },
    }),
    (error) => error instanceof ScanError && error.statusCode === 400,
  );
  assert.equal(requestCalled, false);
});

test('scanWebsite rejects alternate private URL encodings before transport', async () => {
  const targets = [
    'http://2130706433/',
    'http://0x7f000001/',
    'http://0177.0.0.1/',
    'http://127.1/',
    'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:8.8.8.8]/',
  ];
  for (const rawUrl of targets) {
    let requestCalled = false;
    await assert.rejects(
      scanWebsite(new URL(rawUrl), {
        resolve: publicResolve,
        request: async () => {
          requestCalled = true;
          return response(200);
        },
      }),
      (error) => error instanceof ScanError && error.statusCode === 400,
      rawUrl,
    );
    assert.equal(requestCalled, false, rawUrl);
  }
});

test('scanWebsite rejects localhost without DNS resolution', async () => {
  let resolved = false;
  await assert.rejects(
    scanWebsite(new URL('http://localhost/'), {
      resolve: async () => {
        resolved = true;
        return [{ address: '93.184.216.34', family: 4 }];
      },
      request: async () => response(200),
    }),
    (error) => error instanceof ScanError && error.statusCode === 400,
  );
  assert.equal(resolved, false);
});

test('scanWebsite enforces the total deadline', async () => {
  await assert.rejects(
    scanWebsite(new URL('https://example.test/'), {
      resolve: () => new Promise(() => {}),
      deadlineMs: 25,
    }),
    (error) => error instanceof ScanError && error.statusCode === 502 && /timed out/i.test(error.message),
  );
});

test('scanWebsite maps DNS failures to ScanError', async () => {
  await assert.rejects(
    scanWebsite(new URL('https://example.test/'), {
      resolve: async () => {
        const error = new Error('not found');
        error.code = 'ENOTFOUND';
        throw error;
      },
    }),
    (error) => error instanceof ScanError && error.statusCode === 502 && /resolve/i.test(error.message),
  );
});

test('scanWebsite strips SSO query parameters and fragments from finalUrl', async () => {
  const result = await scanWebsite(new URL('https://example.test/'), {
    resolve: publicResolve,
    request: async ({ target }) => target.hostname === 'example.test'
      ? response(302, [['Location', 'https://idp.test/login.php?SAMLRequest=secret&SAMLResponse=secret&RelayState=secret#frag']])
      : response(200, [['Content-Type', 'text/html']], '<p>ok</p>'),
  });
  assert.equal(result.finalUrl, 'https://idp.test/login.php');
  const text = JSON.stringify(result);
  assert.equal(text.includes('SAMLRequest'), false);
  assert.equal(text.includes('SAMLResponse'), false);
  assert.equal(text.includes('RelayState'), false);
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'high');
  assert.ok(result.warnings.some((warning) => /final \.php path belongs to idp\.test/i.test(warning)));
});

test('requestHeaders performs one GET, sends no cookies, and skips the body by default', async (t) => {
  let observed = null;
  const server = http.createServer((req, res) => {
    res.on('error', () => {});
    observed = {
      method: req.method,
      ua: req.headers['user-agent'],
      accept: req.headers.accept,
      cookie: req.headers.cookie,
      url: req.url,
    };
    res.writeHead(200, { 'Content-Type': 'text/html', 'X-Powered-By': 'PHP/8.2.29' });
    res.end('<a href="/x.php">x</a>');
  });
  server.on('clientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();

  const result = await requestHeaders({
    target: new URL(`http://127.0.0.1:${port}/path?x=1`),
    address: '127.0.0.1',
    family: 4,
  });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body, null);
  assert.equal(result.bodySkippedReason, 'not-requested');
  assert.equal(observed.method, 'GET');
  assert.equal(observed.ua, 'PHP2Shell-Exposure-Checker');
  assert.equal(observed.accept, '*/*');
  assert.equal(observed.cookie, undefined);
  assert.equal(observed.url, '/path?x=1');
  const inspection = inspectPhpHeaders(result.rawHeaders);
  assert.equal(inspection.version, '8.2.29');
  assert.equal(inspection.status, 'affected');
});

test('requestHeaders caps captured HTML at 64 KiB', async (t) => {
  const server = http.createServer((req, res) => {
    res.on('error', () => {});
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('x'.repeat(70 * 1024));
  });
  server.on('clientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();

  const result = await requestHeaders({
    target: new URL(`http://127.0.0.1:${port}/`),
    address: '127.0.0.1',
    family: 4,
    captureBody: true,
  });
  assert.equal(result.bodyInspected, true);
  assert.equal(result.bodyTruncated, true);
  assert.equal(result.body.length, 64 * 1024);
});

test('scanWebsite real transport smoke via loopback fixture and vetted public DNS pin', async (t) => {
  const server = http.createServer((req, res) => {
    res.on('error', () => {});
    assert.equal(req.method, 'GET');
    assert.equal(req.headers['user-agent'], 'PHP2Shell-Exposure-Checker');
    assert.equal(req.headers.accept, '*/*');
    assert.equal(req.headers.cookie, undefined);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<a href="/status.php">status</a>');
  });
  server.on('clientError', () => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();

  const result = await scanWebsite(new URL('http://example.test/'), {
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    request: (options) => requestHeaders({
      ...options,
      target: new URL(`http://127.0.0.1:${port}/`),
      address: '127.0.0.1',
      family: 4,
    }),
  });
  assert.equal(result.is_php, 'yes');
  assert.equal(result.confidence, 'medium');
  assert.equal(result.php_version, null);
  assert.equal(result.status, 'unknown');
  assert.equal(result.httpStatus, 200);
  assert.ok(result.evidence.some((item) => /\.php URLs \(1 found\)/.test(item)));
});

test('self-signed HTTPS requires explicit override and warns without weakening address policy', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'php2shell-tls-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = path.join(directory, 'key.pem');
  const certPath = path.join(directory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  let hits = 0;
  const server = https.createServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, (req, res) => {
    hits += 1;
    res.writeHead(200, { 'X-Powered-By': 'PHP/8.2.29' });
    res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const options = {
    resolve: publicResolve,
    request: (request) => requestHeaders({ ...request,
      target: new URL(`https://localhost:${server.address().port}/`),
      address: '127.0.0.1', family: 4 }),
  };
  await assert.rejects(scanWebsite(new URL('https://example.test/'), options), /TLS certificate verification failed/);
  assert.equal(hits, 0);
  const result = await scanWebsite(new URL('https://example.test/'), { ...options, ignoreTlsErrors: true });
  assert.equal(hits, 1);
  assert.equal(result.php_version, '8.2.29');
  assert.equal(result.status, 'affected');
  assert.match(result.warnings[0], /TLS certificate verification was disabled/);
  await assert.rejects(scanWebsite(new URL('https://127.0.0.1/'), { ignoreTlsErrors: true }), /not a public address/);
});


