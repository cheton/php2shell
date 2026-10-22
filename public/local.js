const $ = (selector) => document.querySelector(selector);
const storageKey = 'php2shell.local.kid';
let kid = '';
let busy = false;
let generation = 0;
const webElements = ['#scan-intro', '#checker-layout', '#scan-progress', '#scan-result'];
let webVisibility = null;
function mode(local) {
  if (local && !webVisibility) webVisibility = webElements.map((selector) => $(selector).hidden);
  $('#local-panel').hidden = !local;
  $('#local-mode').setAttribute('aria-pressed', String(local));
  $('#web-mode').setAttribute('aria-pressed', String(!local));
  webElements.forEach((selector, index) => { $(selector).hidden = local || (webVisibility?.[index] ?? index > 1); });
  if (!local) webVisibility = null;
}
$('#local-mode').addEventListener('click', () => mode(true));
$('#web-mode').addEventListener('click', () => mode(false));
function fail(error) {
  $('#local-error').textContent = error.name === 'TimeoutError' ? 'The local scan service timed out. Try opening your saved scan key again.' : error.message || 'Unable to reach the local scan service.';
  $('#local-error').hidden = false;
}
async function api(path, body) {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  if ([404, 405, 501].includes(response.status)) throw new Error('Local scan backend is not connected yet. No scan record was created or updated.');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The local scan request failed.');
  return data;
}
function render(data) {
  if (typeof data.kid !== 'string' || !data.kid || !Array.isArray(data.runs) || !['waiting', 'completed'].includes(data.status) || !data.runs.every((run) => run && Array.isArray(run.findings) && run.findings.every((finding) => finding && typeof finding.component === 'string' && (finding.version === null || typeof finding.version === 'string') && ['affected', 'patched', 'unknown'].includes(finding.status) && Array.isArray(finding.evidence) && finding.evidence.every((item) => typeof item === 'string')))) throw new Error('The report service returned an invalid response.');
  kid = data.kid;
  $('#local-kid').textContent = kid;
  $('#local-enroll').hidden = true;
  $('#local-restore').hidden = true;
  $('#local-workspace').hidden = false;
  try {
    localStorage.setItem(storageKey, kid);
    $('#local-storage-note').textContent = 'Saved in this browser. Keep a copy to open your report on another device. Anyone with this key can read your results.';
  } catch {
    $('#local-storage-note').textContent = 'Browser storage is unavailable. Copy your key now; you will need it to open this report again. Anyone with this key can read your results.';
  }
  const download = $('#local-download');
  download.hidden = !data.agent_download_url;
  if (data.agent_download_url) {
    const url = new URL(data.agent_download_url);
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('The agent download URL is invalid.');
    download.href = url.href;
    download.rel = 'noopener noreferrer';
  } else download.removeAttribute('href');
  $('#local-agent-unavailable').hidden = Boolean(data.agent_download_url);
  $('#local-state').textContent = data.status === 'waiting' ? 'Waiting for the agent to return results. Refresh after running your agent.' : `${data.runs.length} agent report(s) received.`;
  const runs = data.runs.map((run) => {
    const article = document.createElement('article'); article.className = 'local-run';
    const heading = document.createElement('h3'); heading.textContent = `${run.hostname || 'Host not reported'} — ${run.created_at || run.received_at || run.run_id}`; article.append(heading);
    for (const finding of run.findings) {
      const section = document.createElement('section'); section.className = 'local-finding';
      const title = document.createElement('h4'); title.textContent = `${finding.component}: ${finding.version ?? 'Version unavailable'} — ${finding.status}`;
      const list = document.createElement('ul');
      for (const evidence of finding.evidence) { const item = document.createElement('li'); item.textContent = evidence; list.append(item); }
      section.append(title, list); article.append(section);
    }
    if (!run.findings.length) { const note = document.createElement('p'); note.textContent = 'The agent returned no findings. This does not establish that PHP is absent or that the host is secure.'; article.append(note); }
    return article;
  });
  $('#local-runs').replaceChildren(...runs);
}
async function refresh(key = kid) {
  const current = generation;
  const data = await api('/api/v3.0/scans/kid/results', { kid: key });
  if (current === generation) render(data);
}
async function action(button, work) {
  if (busy) return;
  busy = true; button.disabled = true; $('#local-error').hidden = true;
  try { await work(); } catch (error) { fail(error); }
  finally { busy = false; button.disabled = false; }
}
$('#local-enroll').addEventListener('submit', (event) => {
  event.preventDefault();
  if (!event.target.reportValidity()) return;
  action($('#local-create'), async () => {
    generation += 1;
    const data = await api('/api/v3.0/scans', { email: $('#local-email').value.trim(), authorized: $('#local-consent').checked });
    kid = data.kid;
    $('#local-token').value = data.jwt_token;
    $('#local-command-block').hidden = false;
    $('#local-token-missing').hidden = true;
    $('#local-token-expiry').textContent = `Upload token expires: ${data.token_expires_at}`;
    render({ ...data, status: 'waiting', runs: [] });
    $('#local-email').value = '';
  });
});
$('#local-restore').addEventListener('submit', (event) => {
  event.preventDefault();
  action(event.target.querySelector('button'), async () => { generation += 1; await refresh($('#local-key-input').value.trim()); $('#local-token-missing').hidden = false; });
});
$('#local-refresh').addEventListener('click', () => action($('#local-refresh'), () => refresh()));
$('#local-copy').addEventListener('click', () => action($('#local-copy'), async () => { await navigator.clipboard.writeText(kid); $('#local-copy').textContent = 'Key copied'; }));
$('#local-new').addEventListener('click', () => {
  if (busy) return;
  generation += 1; kid = '';
  try { localStorage.removeItem(storageKey); } catch {}
  $('#local-enroll').hidden = false; $('#local-restore').hidden = false; $('#local-workspace').hidden = true;
  $('#local-token').value = ''; $('#local-command-block').hidden = true; $('#local-token-missing').hidden = true;
  $('#local-key-input').value = ''; $('#local-error').hidden = true; $('#local-copy').textContent = 'Copy key'; $('#local-email').focus();
});
let saved;
try { saved = localStorage.getItem(storageKey); } catch {}
if (saved) {
  $('#local-key-input').value = saved;
  mode(true);
  $('#local-token-missing').hidden = false;
  action($('#local-refresh'), () => refresh(saved));
}
