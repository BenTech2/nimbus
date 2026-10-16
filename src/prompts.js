// Dialogs the backend asks for while connecting (SSH, SFTP, FTP), plus a simple text prompt.
import { esc, modal } from './ui.js';

export async function hostKeyPrompt(d, ctl) {
  const changed = !!d.previous;
  const html = changed
    ? `<div class="dangerbox"><strong>The key this server presents has changed.</strong> That happens when a server is
         reinstalled or its keys are rotated — but it is also exactly what an interception attack looks like.
         Only continue if you know why it changed.</div>
       <div class="fp-box"><div class="k">Host</div><div>${esc(d.host)}</div>
         <div class="k">Previously trusted</div><div>${esc(d.previous)}</div>
         <div class="k">Now presenting (${esc(d.keyType)})</div><div>${esc(d.fingerprint)}</div></div>`
    : `<p>This is the first time Nimbus has connected to <strong>${esc(d.host)}</strong>. Check the fingerprint
         matches the server before trusting it.</p>${d.note ? `<p class="hint">${esc(d.note)}</p>` : ''}
       <div class="fp-box"><div class="k">${esc(d.keyType)}</div><div class="selectable">${esc(d.fingerprint)}</div></div>`;
  const r = await modal({
    title: changed ? 'Host key changed' : 'Trust this host?',
    html,
    ctl,
    buttons: changed
      ? [{ label: 'Trust new key', value: 'ok', kind: 'danger' }, { label: 'Cancel', value: 'cancel', kind: 'primary', submit: true }]
      : [{ label: 'Cancel', value: 'cancel' }, { label: 'Trust and connect', value: 'ok', kind: 'primary', submit: true }],
  });
  return r.action === 'ok';
}

export async function secretPrompt(kind, d, ctl) {
  const what = kind === 'passphrase' ? 'passphrase' : 'password';
  const r = await modal({
    title: d.title || 'Password',
    html: `<p>${esc(d.message)}</p>
      <label class="field"><input type="password" name="value" autofocus></label>
      ${d.allowSave ? `<label class="check"><input type="checkbox" name="save"><span>Save ${what} on this computer</span></label>` : ''}`,
    ctl,
    buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Continue', value: 'ok', kind: 'primary', submit: true }],
  });
  return r.action === 'ok' ? { value: r.values.value, save: !!r.values.save } : null;
}

export async function textPrompt(d, ctl) {
  const r = await modal({
    title: d.title || 'Input',
    html: `<p>${esc(d.message)}</p><label class="field"><input type="text" name="value" value="${esc(d.value ?? '')}" autofocus spellcheck="false"></label>`,
    ctl,
    init: (form) => {
      // Pre-select the part of a file name before its extension, like Finder and Explorer.
      const input = form.elements.value;
      const dot = d.selectStem ? input.value.lastIndexOf('.') : -1;
      requestAnimationFrame(() => input.setSelectionRange(0, dot > 0 ? dot : input.value.length));
    },
    buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Continue', value: 'ok', kind: 'primary', submit: true }],
  });
  return r.action === 'ok' ? { value: r.values.value } : null;
}

export async function kbdPrompt(d, ctl) {
  const fields = d.prompts
    .map((p, i) => `<label class="field"><span>${esc(p.prompt)}</span><input type="${p.echo ? 'text' : 'password'}" name="r${i}" ${i === 0 ? 'autofocus' : ''} spellcheck="false"></label>`)
    .join('');
  const r = await modal({
    title: d.title || 'Server asks',
    html: `${d.message ? `<p>${esc(d.message)}</p>` : ''}${fields}`,
    ctl,
    buttons: [{ label: 'Cancel', value: 'cancel' }, { label: 'Continue', value: 'ok', kind: 'primary', submit: true }],
  });
  return r.action === 'ok' ? { responses: d.prompts.map((_, i) => r.values[`r${i}`] ?? '') } : null;
}
