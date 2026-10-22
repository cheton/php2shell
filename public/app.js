const $ = (selector) => document.querySelector(selector);
const form = $('#scan-form');
const website = $('#website');
const authorized = $('#authorized');
const intro = $('#scan-intro');
const layout = $('#checker-layout');
const progress = $('#scan-progress');
const result = $('#scan-result');
const error = $('#form-error');
const terms = $('#terms-dialog');
const ranges = '5.4–8.1; 8.2.0–8.2.34; 8.3.0–8.3.35; 8.4.0–8.4.26; 8.5.0–8.5.11';
const remediation = `Affected versions are ${ranges}; patched releases are 8.2.35, 8.3.36, 8.4.27, and 8.5.12. Follow the remediation guidance from your PHP vendor or operating-system distribution, and apply the recommended update or mitigation.`;
const outcomes = {
  'not-detected': {
    label: 'EXPOSURE UNDETERMINED', title: 'No PHP signals found. Exposure is undetermined.', icon: 'info',
    description: `We didn't find PHP signals in this website's response. This doesn't rule PHP out, since many sites hide it. If you run PHP, check your version. ${remediation}`,
  },
  affected: {
    label: 'POTENTIALLY AFFECTED', title: 'The reported PHP version may be affected', icon: 'alert',
    description: `The reported PHP version falls within an affected version range. A version signal alone does not confirm that this website is exploitable. Verify your installed version, configuration, and vendor patch status. ${remediation}`,
  },
  patched: {
    label: 'UPSTREAM FIX THRESHOLD MET', title: 'The reported version meets the upstream fix threshold', icon: 'check',
    description: 'The advertised PHP version meets the upstream fixed-version threshold for the referenced PHP2Shell issues. This is a header-based indicator, not verification of the installed patch or website security. Confirm the web-serving runtime and vendor package status independently.',
  },
  unknown: {
    label: 'EXPOSURE UNDETERMINED', title: 'PHP detected. Exposure is undetermined.', icon: 'info',
    description: `We found PHP signals, but could not classify a reliable version against the advisory. Verify your installed PHP version and vendor patch status. ${remediation}`,
  },
};

function showForm() {
  intro.hidden = false;
  layout.hidden = false;
  progress.hidden = true;
  result.hidden = true;
  form.removeAttribute('aria-busy');
  $('#scan-button').disabled = false;
}

function showResult(data) {
  const outcome = outcomes[data.status];
  if (!outcome || data.mock !== false || typeof data.hostname !== 'string' || !['yes', 'unknown'].includes(data.is_php) || !['high', 'medium', 'low'].includes(data.confidence) || !Number.isInteger(data.httpStatus) || !(data.php_version === null || typeof data.php_version === 'string') || !Array.isArray(data.evidence) || !data.evidence.every((item) => typeof item === 'string') || !Array.isArray(data.warnings) || !data.warnings.every((item) => typeof item === 'string')) {
    throw new Error('The scan service returned an unexpected response. Please try again.');
  }
  $('.result-card').dataset.status = data.status;
  $('#result-label').textContent = outcome.label;
  $('#result-heading').textContent = outcome.title;
  $('#result-symbol').setAttribute('href', `#${outcome.icon}`);
  $('#result-host').textContent = data.hostname;
  $('#result-host').title = data.hostname;
  $('#result-http').textContent = `HTTP ${data.httpStatus}`;
  $('#result-php').textContent = data.is_php;
  $('#result-confidence').textContent = `${data.confidence} (PHP identification only)`;
  $('#result-version').textContent = data.php_version ?? '—';
  $('#result-description').textContent = outcome.description;
  for (const [selector, items] of [['#result-evidence', data.evidence], ['#result-warnings', data.warnings]]) {
    $(selector).replaceChildren(...items.map((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      return li;
    }));
  }
  progress.hidden = true;
  result.hidden = false;
  result.focus({ preventScroll: true });
  $('#checker').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity() || form.hasAttribute('aria-busy')) return;
  const url = new URL(website.value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    error.textContent = 'Enter an HTTP or HTTPS website URL without embedded credentials.';
    error.hidden = false;
    website.focus();
    return;
  }
  error.hidden = true;
  form.setAttribute('aria-busy', 'true');
  $('#scan-button').disabled = true;
  $('#web-mode').disabled = true;
  $('#local-mode').disabled = true;
  intro.hidden = true;
  layout.hidden = true;
  progress.hidden = false;
  $('#checker').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url.href, authorized: authorized.checked }),
      signal: AbortSignal.timeout(15000),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === 'string' ? data.error : 'The scan could not be completed. Please try again.');
    showResult(data);
  } catch (failure) {
    showForm();
    error.textContent = failure.name === 'TimeoutError'
      ? 'The scan service took too long to respond. Please try again.'
      : failure instanceof TypeError
        ? 'Unable to reach the scan service. Check your connection and try again.'
        : failure.message;
    error.hidden = false;
    error.scrollIntoView({ behavior: 'smooth', block: 'center' });
    website.focus({ preventScroll: true });
  } finally {
    form.removeAttribute('aria-busy');
    $('#scan-button').disabled = false;
    $('#web-mode').disabled = false;
    $('#local-mode').disabled = false;
  }
});

$('#scan-again').addEventListener('click', () => {
  showForm();
  error.hidden = true;
  authorized.checked = false;
  website.focus({ preventScroll: true });
  $('#checker').scrollIntoView({ behavior: 'smooth', block: 'start' });
});

for (const selector of ['#open-terms', '#footer-terms']) {
  $(selector).addEventListener('click', () => terms.showModal());
}
$('#close-terms').addEventListener('click', () => terms.close());
$('#accept-terms').addEventListener('click', () => terms.close());
terms.addEventListener('click', (event) => {
  if (event.target !== terms) return;
  const bounds = terms.getBoundingClientRect();
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) terms.close();
});
