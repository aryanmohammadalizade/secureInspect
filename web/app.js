const el = id => document.getElementById(id);
let token = '', prepared = null, recordId = null;

async function api(path, body, access = token) {
  const headers = {'Content-Type': 'application/json'};
  if (access) headers.Authorization = 'Bearer ' + access;
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', headers,
    body: body === undefined ? undefined : JSON.stringify(body)});
  return {status: response.status, data: await response.json(), latency: response.headers.get("X-Verification-Ms")};
}

function check(id, state) {
  el(id).textContent = state;
  el(id).className = state === 'Passed' ? 'pass' : state === 'Failed' ? 'fail' : '';
}

function resetResult() {
  recordId = null;
  el('decrypt').disabled = true;
  ['jwt-check','cert-check','sig-check','fresh-check','plaus-check','store-check'].forEach(id => check(id, '—'));
  el('latency').textContent = '—';
  el('decision').textContent = 'Awaiting data'; el('decision').className = 'pill';
  el('result-text').textContent = 'No data has been submitted.';
  el('ciphertext').textContent = 'No accepted record yet.'; el('plaintext').hidden = true;
  el('verified-value').textContent = '—'; el('preview-value').textContent = '—';
  el('forecast-note').textContent = 'The counterfactual is an isolated calculation, never a way to bypass security or save unverified data.';
  el('chart').innerHTML = '<text x="220" y="120" text-anchor="middle" fill="#64748b">Submit a reading to compare forecasts.</text>';
}

function enableTransmission(enabled) {
  ['received','tamper','restore','scenario','verify'].forEach(id => el(id).disabled = !enabled);
}

el('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  token = ''; prepared = null; resetResult(); enableTransmission(false); el('prepare').disabled = true; el('source').disabled = true;
  el('audit').textContent = 'Log in to view the persistent audit history.';
  el('envelope-view').textContent = 'Prepare a reading to see the actual signed payload.';
  el('prepare-status').textContent = 'The local sender signs a new synthetic message.';
  try {
    const result = await api('/api/login', {username: el('username').value, password: el('password').value}, '');
    if (result.status !== 200) throw Error('Login rejected. Check the generated demo password.');
    token = result.data.access_token;
    el('password').value = ''; el('prepare').disabled = false; el('source').disabled = false;
    await refreshAudit();
    el('login-status').textContent = 'Authenticated. A real JWT was issued (30-minute validity).';
  } catch (error) { el('login-status').textContent = error.message; }
});

el('prepare').addEventListener('click', async () => {
  el('prepare').disabled = true; enableTransmission(false); resetResult(); prepared = null;
  try {
    const result = await api('/api/prepare?scenario=' + el('source').value, {});
    if (result.status !== 200) throw Error(result.data.detail);
    prepared = result.data;
    el('received').value = prepared.envelope.reading.current_mm; el('scenario').value = 'normal';
    el('envelope-view').textContent = JSON.stringify(prepared.envelope, null, 2);
    el('prepare-status').textContent = 'Signed at ' + new Date(prepared.envelope.reading.signed_at * 1000).toISOString() + '. Ready for transmission.';
    enableTransmission(true);
  } catch (error) { el('prepare-status').textContent = error.message; }
  finally { el('prepare').disabled = false; }
});

el('tamper').onclick = () => { el('received').value = 10; };
el('restore').onclick = () => { el('received').value = prepared.envelope.reading.current_mm; el('scenario').value = 'normal'; };

el('verify').addEventListener('click', async () => {
  if (!prepared || !el('received').reportValidity() || el('received').value === '') return;
  el('verify').disabled = true; el('prepare').disabled = true; resetResult();
  const envelope = JSON.parse(JSON.stringify(prepared.envelope));
  envelope.reading.current_mm = Number(el('received').value);
  const scenario = el('scenario').value;
  let access = token;
  if (scenario === 'certificate') envelope.certificate = prepared.untrusted_certificate;
  if (scenario === 'signature') envelope.signature = (envelope.signature[0] === 'A' ? 'B' : 'A') + envelope.signature.slice(1);
  if (scenario === 'token') access = 'invalid.token.value';
  if (scenario === 'missing') access = '';
  try {
    const preview = await api('/api/preview', envelope.reading, '');
    const result = await api('/api/verify', envelope, access);
    const accepted = result.status === 201, stage = result.data.stage;
    const stages = ['jwt','certificate','signature','freshness','plausibility','replay'];
    const failedAt = accepted ? stages.length : result.status === 401 ? 0 : stages.indexOf(stage);
    stages.forEach((name, i) => check(['jwt-check','cert-check','sig-check','fresh-check','plaus-check','store-check'][i], i < failedAt ? 'Passed' : i === failedAt ? 'Failed' : 'Not checked'));
    el('latency').textContent = result.latency === null ? '—' : result.latency + ' ms';
    el('decision').textContent = accepted ? 'Accepted · HTTP 201' : 'Rejected · HTTP ' + result.status;
    el('decision').className = 'pill ' + (accepted ? 'pass' : 'fail');
    el('result-text').textContent = accepted ? 'Authentic and plausible data accepted, encrypted and stored.' : (typeof result.data.detail === 'string' ? result.data.detail : 'Invalid input.');
    if (accepted) {
      recordId = result.data.record_id;
      el('ciphertext').textContent = JSON.stringify(result.data.encrypted, null, 2);
      el('decrypt').disabled = false;
    }
    if (preview.status === 200) drawForecast(envelope.reading, preview.data, accepted ? result.data.forecast : null);
    await refreshAudit();
  } catch (error) { el('result-text').textContent = 'Request failed: ' + error.message; }
  finally { el('verify').disabled = false; el('prepare').disabled = false; }
});

el('decrypt').addEventListener('click', async () => {
  if (!recordId) return;
  try {
    const result = await api('/api/records/' + recordId);
    el('plaintext').textContent = JSON.stringify(result.data, null, 2);
    el('plaintext').hidden = false;
  } catch (error) { el('result-text').textContent = error.message; }
});

async function refreshAudit() {
  try {
    const result = await api('/api/audit');
    el('audit').textContent = result.status === 200 ? result.data.slice().reverse().map(event =>
      `${event.time} | ${event.stage} | HTTP ${event.status} | ${event.latency_ms} ms`).join('\n') || 'No verification requests yet.' : 'Audit unavailable: log in again.';
  } catch (error) { el('audit').textContent = 'Audit unavailable: ' + error.message; }
}

function drawForecast(reading, preview, verified) {
  el('verified-value').textContent = verified ? verified.forecast_mm.toFixed(2) + ' mm' : 'Blocked';
  el('preview-value').textContent = preview.forecast_mm.toFixed(2) + ' mm';
  el('forecast-note').textContent = verified ? 'Verified forecast: ' + (verified.below_threshold ? 'below' : 'at or above') + ' the fictional 6 mm threshold.' : 'No verified forecast. Amber is hypothetical only; dashed grey is the fixed synthetic reference (4 mm in 2029), not an accepted record. Forecast difference: ' + (preview.forecast_mm - 4).toFixed(2) + ' mm.';
  const max = Math.max(12, reading.previous_mm, reading.current_mm, preview.forecast_mm) * 1.08;
  const min = Math.min(0, preview.forecast_mm) - 0.4;
  const y = v => (190 - (v - min) / (max - min) * 160).toFixed(2);
  const p = y(reading.previous_mm), c = y(reading.current_mm), f = y(preview.forecast_mm), t = y(6);
  const color = verified ? '#176b8c' : '#ad690c';
  el('chart').innerHTML = `<path d="M45 24 V190 H418" fill="none" stroke="#a1b1bb"/>
    <text x="45" y="15" font-size="10" fill="#64748b">Wall thickness (mm)</text>
    <line x1="45" y1="${t}" x2="418" y2="${t}" stroke="#ad392f" stroke-dasharray="4 4"/>
    <text x="418" y="${Number(t)-5}" font-size="10" text-anchor="end" fill="#ad392f">6 mm threshold</text>
    ${verified ? '' : `<path d="M60 ${y(10)} L230 ${y(7)} L400 ${y(4)}" fill="none" stroke="#64748b" stroke-width="1.5" stroke-dasharray="3 4"/>`}
    <path d="M60 ${p} L230 ${c}" fill="none" stroke="${color}" stroke-width="2.5"/>
    <path d="M230 ${c} L400 ${f}" fill="none" stroke="${color}" stroke-width="2.5" stroke-dasharray="6 4"/>
    ${[[60,p,reading.previous_mm],[230,c,reading.current_mm],[400,f,preview.forecast_mm]].map(([x,v,n]) => `<circle cx="${x}" cy="${v}" r="4" fill="${color}"/><text x="${x}" y="${Number(v)-9}" font-size="11" text-anchor="middle" fill="${color}">${Number(n).toFixed(1)}</text>`).join('')}
    <g font-size="11" fill="#64748b" text-anchor="middle"><text x="60" y="209">2023</text><text x="230" y="209">2026</text><text x="400" y="209">2029</text></g>`;
}
