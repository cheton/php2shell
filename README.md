# PHP2Shell portal

Dependency-free Node.js portal with a real, non-invasive HTTP response checker for
CVE-2026-109618 and CVE-2026-109619. The server contacts the submitted public URL
with a standard GET and examines PHP version signals. No simulated result mode
or exploit payloads are included.

**This is exposure assessment, not proof of exploitability.** Missing or hidden
PHP signals leave exposure undetermined. Headers can be inaccurate, refer to a
proxy or different worker, or omit distribution backports.

## Run

Node.js 22 or newer; no dependencies or build step.

```sh
npm start
# http://127.0.0.1:3000
```

The default bind address is `0.0.0.0`: use the host's LAN IP from another device,
subject to firewall rules. For local-only access:

```sh
HOST=127.0.0.1 npm start
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `PUBLIC_DIR` | `./public` | Static asset directory |
| `SCAN_IGNORE_TLS_ERRORS` | `true` | Set `false` to restore certificate verification for scan targets |

The API is not authenticated. Keep this portal on a trusted network. The consent
checkbox records a caller assertion, not proof of target ownership. Internet
publication requires access control and deployment-level request rate limits.

Scans skip TLS certificate verification by default. Each HTTPS scan result warns
that TLS identity was not verified and evidence may be spoofed. To restore
certificate verification, run `SCAN_IGNORE_TLS_ERRORS=false npm start`.
This setting does not disable DNS validation, DNSSEC at the resolver, or SSRF
address restrictions. HTTP clients cannot select this override.

## Detection

1. Validate the URL and all resolved addresses.
2. Send one standard GET to a validated, pinned public IP, keeping the original
   hostname for HTTP Host and TLS certificate verification.
3. Follow at most three redirects, validating each destination independently.
4. Read `X-Powered-By`, `Server`, and the presence of a `PHPSESSID` cookie name.
   Check final `.php` paths and `.php` URL references in up to 64 KiB of HTML.
   Cookie values, URL query parameters and raw HTML are not returned as evidence.
5. Compare unambiguous stable PHP versions with the official fixed versions.

| Result | Meaning |
| --- | --- |
| `affected` | Advertised upstream version may be affected; verify vendor backports and actual runtime |
| `patched` | Advertised version is at or above the fixed release on a known branch; not a website safety verdict |
| `unknown` | PHP signal exists but version cannot be reliably classified |
| `not-detected` | No supported PHP signal; exposure remains undetermined |

Fixed releases: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. Earlier releases within
those branches are potentially affected. Legacy PHP 5.4–8.1 versions require
vendor/backport verification; unsupported or ambiguous versions do not establish
safety. Pre-release and conflicting version signals are inconclusive.

There is no crawling, subdomain enumeration, phpinfo-path discovery, WAF bypass,
credential forwarding, upload probe, worker-crash test, or RCE attempt.

## API

`POST /api/scan`, `Content-Type: application/json`, body at most 16 KiB:

```json
{"url":"https://example.com/","authorized":true}
```

Only HTTP/HTTPS public targets on standard ports are accepted. URL credentials
are forbidden. A client-supplied `scenario` is rejected; results cannot be chosen
by the caller.

```sh
curl --fail-with-body http://127.0.0.1:3000/api/scan \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://YOUR-AUTHORIZED-WEBSITE/","authorized":true}'
```

Successful responses contain `mock: false`, the submitted `url` and `hostname`,
`finalUrl`, target `httpStatus`, `is_php`, `confidence`, `php_version`, `status`,
and string arrays `evidence` and `warnings`. `is_php` is `yes` for a PHP signal,
otherwise `unknown` (not a false assertion of no PHP). `confidence` is `high`
for direct PHP header/cookie or final-path signals, `medium` for HTML references
alone, and `low` when no signal exists. It rates PHP identification, not CVE
exploitability. `php_version` is a version string or `null`. Target error responses
may still provide evidence; they do not establish application reachability or safety.

Errors contain `mock: false` and `error`. Invalid requests return 400, missing
consent 403, unsupported method 405, oversized body 413, and full scan capacity
429. Target connection, DNS, TLS, and deadline failures return explicit errors,
not a clean or patched verdict.

## Network safeguards

- Reject loopback, private, link-local, multicast, reserved and metadata addresses,
  including non-public DNS answers and mapped/transition IPv6 addresses.
- Pin the validated DNS address for each connection to prevent DNS rebinding.
- Revalidate redirect destinations and reject credentials and non-standard ports.
- Enforce a 10-second overall deadline, bounded headers and three redirects.
- Limit each server instance to four concurrent scans; excess requests are rejected.
- Skip TLS certificate verification by default with a result warning; operators
  can restore verification. Cap HTML reads at 64 KiB.

These controls reduce SSRF exposure; they do not replace outbound firewall policy,
API authentication, or review before deployment. Private/internal websites are
intentionally unsupported. There is no client or environment switch to bypass
address protections.

## Web scan and Local scan

The checker has two visible entrances. Web scan keeps the existing public URL
assessment. Local scan integrates a separately supplied host agent; this project
does not implement the agent's internal inspection or manufacture findings.

Local scan is frontend-only in this repository. Its enrollment and report APIs
will be supplied by a separate backend. Until those endpoints are connected,
the UI reports that the service is not connected; it does not generate a fake
kid, token, download, or result. Serve the frontend and backend under the same
origin, or configure a deployment reverse proxy for the `/api/v3.0/` routes.

The frontend sends an email and authorization assertion, then expects the backend
to return a `kid` and separate expiring upload token. It saves only `kid` in
`localStorage`; the token is displayed once and is not persisted there. The
backend must define email handling, authentication, retention and report storage.
If kid alone grants report access, treat it as a secret. The UI provides copy,
manual recovery, and refresh controls. It does not send email or verify ownership.

The backend supplies `agent_download_url` as HTTPS or null. Without it, the UI
explicitly says no agent download is configured. The agent provider defines the
executable and how it accepts the token; no unverified command is presented.
Use HTTPS in deployment. Web scan's target TLS override does not apply to agent
uploads or the portal's backend connection.

### Proposed backend response contract (not implemented here)

- `POST /api/v3.0/scans`: `{ "email": "you@example.com", "authorized": true }`.
  Returns `kid`, `jwt_token`, `token_expires_at`, and `agent_download_url`.
- `POST /api/v3.0/scans/kid/results`: `{ "kid": "YOUR_SCAN_KEY" }`.
  Returns `status` (`waiting` or `completed`), `runs`, and the download URL.
  Each run contains `run_id`, `received_at`, optional `hostname`, and `findings`.
  Each finding has `component` (string), `version` (string or null), `status`
  (`affected`, `patched`, or `unknown`), and `evidence` (array of strings).
  The agent upload route in the supplied diagram belongs to the separate backend;
  this frontend neither implements nor calls it.

Agent findings are untrusted, agent-reported evidence, not independently verified
exploitation or patch confirmation. Do not submit credentials, cookie values,
environment dumps, source files, or other secrets in findings. An empty findings
list does not establish that PHP is absent or the host is safe. Enrollment needs
deployment-level rate limiting and privacy/retention policies before public use.

## Code and tests

- `scanner.mjs`: address policy, real network requests, PHP evidence classification.
- `server.mjs`: request validation, authorization assertion, scan concurrency and
  static serving. `createServer({ publicDir, scan })` permits deterministic test
  injection; normal execution always uses the real scanner.
- `public/app.js`: live API flow and safe text rendering of evidence/warnings.

```sh
npm test
```

Tests use Node's built-in runner and isolated fixtures. They cover classification
boundaries, ambiguous signals, unsafe destinations and API/static behavior without
depending on a public website's current banner. Controlled fixtures advertise PHP
headers; they prove checker behavior, not the presence of an actual PHP exploit.
The self-signed HTTPS regression generates temporary test certificates with the
`openssl` executable; it checks default rejection, explicit override and SSRF rejection.

The user-supplied CSV is a regression reference, not an imported asset inventory.
Representative fixtures cover matching `PHP/8.2.29` in two headers, the mixed
product banner `PHP/8.3.29, ASP.NET`, cookie-only detection, HTML references and
PHP redirect paths. CSV confidence describes PHP identification, not confirmed
vulnerability. No bulk requests to the CSV domains run during verification.

## Sources and limits

- [PHP security advisory, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 upstream advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [NCSC-NL operational guidance](https://github.com/NCSC-NL/php2shell)
- [Public scanner approach reviewed](https://github.com/JoasASantos/php2shell-scanner)

Thresholds were checked against PHP's official advisories. No third-party scanner
code is executed. The reviewed scanner also offers potentially disruptive probes;
those are deliberately not included here. Confirming patch status requires an
owner-side audit of the web-serving PHP runtime, vendor package updates and worker
restart state; CLI PHP may be a different installation.

The visual design follows [php2shell.sh](https://www.php2shell.sh/). Its Imperva
CAPTCHA prevented complete visual inspection. This portal is not an official PHP
or Imperva service and does not claim pixel-identical fidelity.
